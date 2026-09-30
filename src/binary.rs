use anyhow::{Context, Result};
use log::info;
use object::{
    build::{elf::Dynamic, ByteString},
    elf::{PF_R, PF_W, PT_LOAD, PT_PHDR},
    pe,
    read::{
        coff::CoffHeader,
        pe::{ImageNtHeaders, ImageOptionalHeader},
    },
    LittleEndian as LE, Object, ObjectSection, ObjectSegment, ObjectSymbol,
};
use rand::Rng;
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedConfig {
    pub magic1: i32,
    pub magic2: i32,
    pub version: i32,
    pub data_size: i32,
    pub data_offset: i32,
    pub data_xz: bool,
}

impl Default for EmbeddedConfig {
    fn default() -> Self {
        Self {
            magic1: 0x0d000721,
            magic2: 0x1f8a4e2b,
            version: 1,
            data_size: 0,
            data_offset: 0,
            data_xz: false,
        }
    }
}

impl EmbeddedConfig {
    pub fn new(data_size: i32, data_offset: i32, data_xz: bool) -> Self {
        Self {
            magic1: 0x0d000721,
            magic2: 0x1f8a4e2b,
            version: 1,
            data_size,
            data_offset,
            data_xz,
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; std::mem::size_of::<EmbeddedConfig>()];
        unsafe {
            let ptr = self as *const EmbeddedConfig as *const u8;
            std::ptr::copy_nonoverlapping(
                ptr,
                bytes.as_mut_ptr(),
                std::mem::size_of::<EmbeddedConfig>(),
            );
        }
        bytes
    }
}

pub enum ObjectFormat {
    Elf,
    Pe,
    MachO,
}

/// Name of the reserved section a Mach-O payload must expose so that fripack can
/// inject the script without rewriting the Mach-O structure.
pub const PAYLOAD_SECTION: &str = "__fripack";

pub struct BinaryProcessor {
    data: Vec<u8>,
    format: ObjectFormat,
}

const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug, Clone, Copy)]
struct ElfSegment {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    /// Offset of the p_filesz field itself, so it can be updated in place.
    filesz_field: usize,
    is_64: bool,
}

impl ElfSegment {
    /// Virtual address for a file offset inside this segment, if it covers it.
    fn vaddr_of_offset(&self, offset: u64) -> Option<u64> {
        (self.offset <= offset && offset < self.offset + self.filesz)
            .then(|| self.vaddr + (offset - self.offset))
    }
}

fn round_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn read_u16(data: &[u8], at: usize) -> Result<u16> {
    let bytes = data.get(at..at + 2).context("Truncated ELF header")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], at: usize) -> Result<u32> {
    let bytes = data.get(at..at + 4).context("Truncated ELF header")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], at: usize) -> Result<u64> {
    let bytes = data.get(at..at + 8).context("Truncated ELF header")?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn write_elf_word(data: &mut [u8], at: usize, value: u64, is_64: bool) -> Result<()> {
    if is_64 {
        data.get_mut(at..at + 8)
            .context("Truncated ELF program header")?
            .copy_from_slice(&value.to_le_bytes());
    } else {
        let narrowed = u32::try_from(value).context("Value does not fit in a 32-bit ELF")?;
        data.get_mut(at..at + 4)
            .context("Truncated ELF program header")?
            .copy_from_slice(&narrowed.to_le_bytes());
    }
    Ok(())
}

/// True for a 64-bit little-endian ELF, false for 32-bit.
fn elf_is_64(data: &[u8]) -> Result<bool> {
    if data.get(..4) != Some(b"\x7fELF") {
        return Err(anyhow::anyhow!("Payload is not an ELF file"));
    }
    if data.get(5) != Some(&1) {
        return Err(anyhow::anyhow!(
            "Only little-endian ELF payloads are supported"
        ));
    }
    match data.get(4) {
        Some(1) => Ok(false),
        Some(2) => Ok(true),
        other => Err(anyhow::anyhow!("Unsupported ELF class {other:?}")),
    }
}

#[derive(Debug, Clone)]
struct ElfSection {
    name: String,
    offset: u64,
    size: u64,
    /// Index of the linked section, which is how .dynsym points at .dynstr.
    link: u32,
    entsize: u64,
}

/// Reads the section header table of a 32- or 64-bit little-endian ELF.
fn elf_sections(data: &[u8]) -> Result<Vec<ElfSection>> {
    let is_64 = elf_is_64(data)?;
    let (shoff, shentsize, shnum, shstrndx) = if is_64 {
        (
            read_u64(data, 0x28)? as usize,
            read_u16(data, 0x3a)? as usize,
            read_u16(data, 0x3c)? as usize,
            read_u16(data, 0x3e)? as usize,
        )
    } else {
        (
            read_u32(data, 0x20)? as usize,
            read_u16(data, 0x2e)? as usize,
            read_u16(data, 0x30)? as usize,
            read_u16(data, 0x32)? as usize,
        )
    };

    let fields = |index: usize| -> Result<(u32, u64, u64, u32, u64)> {
        let base = shoff + index * shentsize;
        Ok(if is_64 {
            (
                read_u32(data, base)?,
                read_u64(data, base + 24)?,
                read_u64(data, base + 32)?,
                read_u32(data, base + 40)?,
                read_u64(data, base + 56)?,
            )
        } else {
            (
                read_u32(data, base)?,
                read_u32(data, base + 16)? as u64,
                read_u32(data, base + 20)? as u64,
                read_u32(data, base + 24)?,
                read_u32(data, base + 36)? as u64,
            )
        })
    };

    // Section names live in the section named by e_shstrndx.
    let (_, strtab_offset, strtab_size, _, _) = fields(shstrndx)?;
    let names = (strtab_offset as usize)..(strtab_offset + strtab_size) as usize;

    let mut sections = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let (name_offset, offset, size, link, entsize) = fields(index)?;
        let start = names.start + name_offset as usize;
        let name = if names.contains(&start) && data.len() > start {
            let end = data[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|n| start + n)
                .unwrap_or(data.len());
            String::from_utf8_lossy(&data[start..end]).into_owned()
        } else {
            String::new()
        };
        sections.push(ElfSection {
            name,
            offset,
            size,
            link,
            entsize,
        });
    }
    Ok(sections)
}

/// Reads the PT_LOAD entries of a 32- or 64-bit little-endian ELF.
fn elf_load_segments(data: &[u8]) -> Result<Vec<ElfSegment>> {
    if data.get(..4) != Some(b"\x7fELF") {
        return Err(anyhow::anyhow!("Payload is not an ELF file"));
    }
    let is_64 = elf_is_64(data)?;

    let (phoff, phnum, stride) = if is_64 {
        (
            read_u64(data, 0x20)?,
            read_u16(data, 0x38)? as usize,
            read_u16(data, 0x36)? as usize,
        )
    } else {
        (
            read_u32(data, 0x1c)? as u64,
            read_u16(data, 0x2c)? as usize,
            read_u16(data, 0x2a)? as usize,
        )
    };

    let mut segments = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let base = phoff as usize + index * stride;
        let (p_type, flags, offset, vaddr, filesz, memsz, filesz_field) = if is_64 {
            (
                read_u32(data, base)?,
                read_u32(data, base + 4)?,
                read_u64(data, base + 8)?,
                read_u64(data, base + 16)?,
                read_u64(data, base + 32)?,
                read_u64(data, base + 40)?,
                base + 32,
            )
        } else {
            (
                read_u32(data, base)?,
                read_u32(data, base + 24)?,
                read_u32(data, base + 4)? as u64,
                read_u32(data, base + 8)? as u64,
                read_u32(data, base + 16)? as u64,
                read_u32(data, base + 20)? as u64,
                base + 16,
            )
        };
        segments.push(ElfSegment {
            p_type,
            flags,
            offset,
            vaddr,
            filesz,
            memsz,
            filesz_field,
            is_64,
        });
    }
    Ok(segments)
}

impl BinaryProcessor {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        // `File::parse` rejects universal binaries with a generic
        // "Unsupported file format", so give a useful message instead.
        if let Ok(object::FileKind::MachOFat32 | object::FileKind::MachOFat64) =
            object::FileKind::parse(data.as_slice())
        {
            anyhow::bail!(
                "Universal (fat) Mach-O binaries are not supported; build the payload for a single \
                 architecture"
            );
        }

        let format = match object::read::File::parse(data.as_slice())? {
            object::read::File::Elf32(_) | object::read::File::Elf64(_) => ObjectFormat::Elf,
            object::read::File::Pe32(_) | object::read::File::Pe64(_) => ObjectFormat::Pe,
            object::read::File::MachO32(_) | object::read::File::MachO64(_) => ObjectFormat::MachO,
            _ => anyhow::bail!("Unsupported binary format (expected ELF, PE or Mach-O)"),
        };

        Ok(Self { data, format })
    }

    pub fn find_embedded_config(&self) -> Option<usize> {
        let magic1_bytes = (0x0d000721i32).to_le_bytes();
        let magic2_bytes = (0x1f8a4e2bi32).to_le_bytes();

        (0..self
            .data
            .len()
            .saturating_sub(std::mem::size_of::<EmbeddedConfig>()))
            .find(|&i| {
                self.data[i..i + 4] == magic1_bytes
                    && self.data[i + 4..i + 8] == magic2_bytes
                    && self.data[i + 8..i + 12] == (1i32).to_le_bytes()
                    && self.data[i + 12..i + 16] == [0, 0, 0, 0]
                    && self.data[i + 16..i + 20] == [0, 0, 0, 0]
            })
    }
}

pub fn add_needed_library_to_file(path: &std::path::Path, lib_name: &str) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    if let Some(lief::Binary::ELF(mut elf)) = lief::Binary::from(&mut file) {
        elf.add_library(lib_name);
        elf.write(path.to_str().context("Invalid path")?);
        info!("Added needed library '{}' via LIEF", lib_name);
        Ok(())
    } else {
        anyhow::bail!("Failed to parse ELF binary with LIEF")
    }
}

impl BinaryProcessor {
    pub fn add_embedded_config_data(&mut self, config_data: &[u8], use_xz: bool) -> Result<()> {
        let data = if use_xz {
            self.compress_xz(config_data)?
        } else {
            config_data.to_vec()
        };
        let mut embedded_config = EmbeddedConfig::new(data.len() as i32, 0, use_xz);

        match self.format {
            ObjectFormat::Elf => {
                self.patch_elf(&data, &mut embedded_config, use_xz)?;
            }
            ObjectFormat::Pe => {
                // Parse the PE file
                let kind = object::FileKind::parse(self.data.as_slice())?;
                let out_data = match kind {
                    object::FileKind::Pe32 => {
                        self.copy_pe_file::<pe::ImageNtHeaders32>(&data, &embedded_config)?
                    }
                    object::FileKind::Pe64 => {
                        self.copy_pe_file::<pe::ImageNtHeaders64>(&data, &embedded_config)?
                    }
                    _ => anyhow::bail!("Not a PE file"),
                };
                self.data = out_data;
            }
            ObjectFormat::MachO => {
                self.patch_macho(&data, &mut embedded_config)?;
            }
        }

        Ok(())
    }

    /// Patch a Mach-O payload using **pure byte writes** — the Mach-O structure
    /// is never rewritten.
    ///
    /// The payload is expected to ship a reserved, file-backed section
    /// ([`PAYLOAD_SECTION`]) that lives in the same segment as
    /// `g_embedded_config`. Because both then share one segment, the difference
    /// between their file offsets equals the difference between their virtual
    /// addresses, which is exactly what `data_offset` has to encode.
    ///
    /// Note for callers: patching invalidates the code signature. The artifact
    /// must be re-signed (`codesign --force --sign -`) before it can be loaded,
    /// otherwise dyld refuses to map it.
    fn patch_macho(&mut self, payload: &[u8], config: &mut EmbeddedConfig) -> Result<()> {
        // ---- read-only pass: locate the config and the reserved section ----
        let (config_offset, section_offset, section_size, data_offset) = {
            let config_offset = self.find_embedded_config().context(
                "Failed to find the embedded config struct: magic mismatch, or this payload has \
                 already been patched",
            )?;

            let file = object::read::File::parse(self.data.as_slice())?;

            let section = file
                .sections()
                .find(|section| section.name() == Ok(PAYLOAD_SECTION))
                .with_context(|| {
                    format!(
                        "Reserved payload section '{PAYLOAD_SECTION}' not found. Mach-O payloads \
                         must be built with one, e.g.\n  \
                         extern \"C\" __attribute__((used, section(\"__DATA,{PAYLOAD_SECTION}\"))) \
                         char g_fripack_payload[N] = {{0}};"
                    )
                })?;

            let (section_offset, section_size) = section.file_range().with_context(|| {
                format!(
                    "Reserved payload section '{PAYLOAD_SECTION}' occupies no file space (the \
                     linker folded it into zerofill). Give it an explicit initialiser, e.g. \
                     `= {{0}}`."
                )
            })?;

            // Segment that maps the config, resolved by file offset.
            let (segment_addr, segment_offset, segment_size) = file
                .segments()
                .find_map(|segment| {
                    let (offset, size) = segment.file_range();
                    let maps_config = size > 0
                        && offset <= config_offset as u64
                        && (config_offset as u64) < offset + size;
                    maps_config.then(|| (segment.address(), offset, size))
                })
                .context("Failed to find the Mach-O segment that maps the embedded config")?;

            if section_offset < segment_offset || section_offset >= segment_offset + segment_size {
                anyhow::bail!(
                    "Reserved payload section '{PAYLOAD_SECTION}' is not inside the same segment \
                     as the embedded config, so `data_offset` would not be a valid virtual-address \
                     delta. Place it in __DATA."
                );
            }

            let config_vaddr = config_offset as u64 - segment_offset + segment_addr;
            let data_offset = section.address() as i64 - config_vaddr as i64;
            if data_offset < i32::MIN as i64 || data_offset > i32::MAX as i64 {
                anyhow::bail!("Computed data_offset {data_offset} does not fit into an i32");
            }

            (config_offset, section_offset, section_size, data_offset)
        };

        if payload.len() as u64 > section_size {
            anyhow::bail!(
                "Payload is {} bytes but the reserved section only holds {} bytes; increase the \
                 reserved size in the payload",
                payload.len(),
                section_size
            );
        }

        // ---- write pass ----
        config.data_size = payload.len() as i32;
        config.data_offset = data_offset as i32;
        let config_bytes = config.as_bytes();

        self.data
            .get_mut(config_offset..config_offset + config_bytes.len())
            .context("Embedded config lies outside the file")?
            .copy_from_slice(&config_bytes);

        let section_start = section_offset as usize;
        self.data
            .get_mut(section_start..section_start + payload.len())
            .context("Reserved payload section lies outside the file")?
            .copy_from_slice(payload);

        info!(
            "Patched Mach-O: data_offset={data_offset:#x} (config@{config_offset:#x}, \
             section@{section_offset:#x}, reserved {section_size:#x} bytes)"
        );

        Ok(())
    }
    fn generate_random_string(len: usize) -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    /// Writes the embedded config into an ELF payload using byte writes only.
    ///
    /// The program header table and the section header table are left exactly as
    /// they were; an existing PT_LOAD simply has its p_filesz grown to cover the
    /// appended data.
    ///
    /// The previous implementation asked the ELF builder to append a section and a
    /// PT_LOAD for the payload. Adding a program header makes the program header
    /// table one entry longer, and in fripack-inject's Linux payload that table
    /// ends exactly where .dynsym begins - both at 0x238, with no gap - so the new
    /// entry landed on top of the first two dynamic symbols. The code noticed the
    /// overlap and "moved" the section, but it only rewrote the section header's
    /// sh_offset: the bytes were never copied and DT_SYMTAB still pointed at the
    /// old address, which is where the program header table now lived. The loader
    /// duly relocated against a corrupted symbol - measured dynsym[1].st_value ==
    /// 0x78 - and jumped to base + 0x78, segfaulting before the payload's
    /// constructor ever ran.
    fn patch_elf(
        &mut self,
        data: &[u8],
        embedded_config: &mut EmbeddedConfig,
        use_xz: bool,
    ) -> Result<()> {
        let segments = elf_load_segments(self.data.as_slice())?;

        let config_offset = self
            .find_embedded_config()
            .context("Embedded config not found in the ELF payload")?;
        let config_vaddr = segments
            .iter()
            .find_map(|seg| seg.vaddr_of_offset(config_offset as u64))
            .context("Embedded config is not covered by any PT_LOAD segment")?;

        // Park the data in the tail of a writable segment that has memory beyond
        // its file contents (a .bss), past the end of the file so that appending
        // cannot overwrite anything.
        let file_len = self.data.len() as u64;
        let mut chosen: Option<(ElfSegment, u64, u64)> = None;
        for seg in segments.iter() {
            if seg.p_type != PT_LOAD || seg.flags & PF_W == 0 {
                continue;
            }
            let after_eof = file_len.saturating_sub(seg.offset);
            let delta = round_up(seg.filesz.max(after_eof), PAGE_SIZE);
            let new_filesz = delta + data.len() as u64;
            if new_filesz > seg.memsz {
                continue; // would not fit in the segment's memory
            }
            // Prefer the tightest fit so the appended data stays close to its segment.
            if chosen
                .as_ref()
                .is_none_or(|(_, _, best_filesz)| new_filesz < *best_filesz)
            {
                chosen = Some((seg.clone(), delta, new_filesz));
            }
        }
        let (segment, delta, new_filesz) = chosen.context(
            "No writable PT_LOAD segment has room for the embedded script; the payload \
             needs a segment whose memory size exceeds its file size (a .bss)",
        )?;

        let data_vaddr = segment.vaddr + delta;
        let write_at = (segment.offset + delta) as usize;
        if self.data.len() < write_at {
            self.data.resize(write_at, 0);
        }
        self.data.extend_from_slice(data);

        write_elf_word(
            &mut self.data,
            segment.filesz_field,
            new_filesz,
            segment.is_64,
        )?;

        embedded_config.data_size = data.len() as i32;
        embedded_config.data_offset = (data_vaddr - config_vaddr) as i32;
        embedded_config.data_xz = use_xz;

        let config_bytes = embedded_config.as_bytes();
        self.data[config_offset..config_offset + config_bytes.len()]
            .copy_from_slice(&config_bytes);

        let data_offset = embedded_config.data_offset;
        info!(
            "Patched ELF: data_offset={data_offset:#x} (config@{config_offset:#x} \
             vaddr={config_vaddr:#x}, data@{data_vaddr:#x}, p_filesz {:#x} -> {new_filesz:#x})",
            segment.filesz
        );
        Ok(())
    }

    pub fn anti_anti_frida(&mut self) -> Result<()> {
        if let ObjectFormat::Elf = self.format {
            let sections = elf_sections(self.data.as_slice())?;
            let rodata_section_range = {
                let rodata = sections
                    .iter()
                    .find(|section| section.name == ".rodata")
                    .context("Failed to find .rodata section")?;
                (rodata.offset as usize)..((rodata.offset + rodata.size) as usize)
            };

            // .dynstr is not rewritten at all.
            //
            // Renaming a symbol name there breaks loading, and it took three layers
            // of this to find out. The loader resolves the library's own dynamic
            // relocations by looking symbols up *by name* through .gnu.hash, and
            // that table was built from the original names, so a renamed symbol
            // cannot be found and the load fails:
            //
            //     dlopen FAILED: undefined symbol: _uYhIZ_ffi_type_pointer
            //
            // Restricting the rewrite to defined symbols does not help - the symbol
            // in that error is defined (st_shndx = 10) and is still reported as
            // undefined - and restricting it to imports would break resolution
            // against libffi instead. Rebuilding .gnu.hash properly would mean
            // reordering .dynsym, since the format requires symbols to be sorted by
            // bucket, which is far more invasive than this pass is worth.
            //
            // The earlier code did rewrite .dynstr and claimed the rebuild that
            // followed fixed GNU_HASH. It did not: delete_orphan_dynamics,
            // delete_orphan_symbols and set_section_sizes never touch the hash
            // table.
            //
            // What .rodata still covers is what detection actually scans for, the
            // frida/gum strings the engine carries around.

            let mut replacements = 0;

            let kwd = |s: &'static str| (s.as_bytes(), Self::generate_random_string(s.len()));

            // Define keywords to replace
            let keywords = [
                kwd("frida"),
                (b"GMainLoop", "pool-6-th".to_string()),
                (b"gum-js-loop", "pool-6-thre".to_string()),
                (b"gmain", "Timer".to_string()),
                kwd("gum-js"),
                kwd("gum"),
                kwd("gdbus"),
                kwd("Gum"),
                kwd("Frida"),
                kwd("GUM"),
                kwd("GDBus"),
                kwd("g_dbus"),
                kwd("g_main"),
                kwd("GMain"),
                kwd("solist"),
                kwd("GLib-GIO"),
                kwd("GLib"),
                kwd("agent"),
                kwd("_Worker"),
            ];

            let keywords_rodata = [
                "frida",
                "GMainLoop",
                "gum-js-loop",
                "gmain",
                "gum-js",
                "gdbus",
                "GDBus",
                "g_dbus",
                "g_main",
                "GMain",
                "solist",
                "GLib-GIO",
                "GLib",
                "agent",
                "_Worker",
            ];

            for (keyword_bytes, replacement_str) in &keywords {
                let replace_bytes = replacement_str.as_bytes();

                // Use a sliding window approach with memchr for faster searching
                let mut pos = 0;
                while let Some(offset) = memchr::memmem::find(&self.data[pos..], keyword_bytes) {
                    let i = pos + offset;
                    let last = i + keyword_bytes.len() - 1;

                    // Rewrites happen in .rodata only. Symbol names in .dynstr are
                    // deliberately left alone - see the note above the keyword list.
                    let in_rodata = rodata_section_range.contains(&i)
                        && rodata_section_range.contains(&last)
                        && keywords_rodata
                            .contains(&std::str::from_utf8(keyword_bytes).unwrap());

                    if !in_rodata {
                        pos += offset + keyword_bytes.len();
                        continue;
                    }

                    self.data[i..i + keyword_bytes.len()].copy_from_slice(replace_bytes);
                    replacements += 1;
                    pos = i + keyword_bytes.len();
                }
            }

            info!("Replaced {} occurrences of keywords", replacements);

            // Deliberately no rewrite here. The replacements above are same-length
            // writes in place, so no section changes size and nothing becomes an
            // orphan, which makes the rebuild that used to follow a no-op at best.
            // In practice it was not: reading the file back through the ELF builder
            // and writing it out again re-laid the file out, and the result
            // segfaulted the dynamic loader on Linux while the version without it
            // loaded and ran - the same class of damage as the program header table
            // growing into .dynsym. The comment claimed it fixed GNU_HASH after the
            // string table changed, but none of delete_orphan_dynamics,
            // delete_orphan_symbols or set_section_sizes touches the hash table, so
            // it never did that either. Symbol names in .dynstr no longer match the
            // hashes in .gnu.hash, which only means lookups of the renamed names
            // fail - the table's buckets and chains are offsets into .dynsym and
            // stay structurally valid, so walking them is safe.
        }

        Ok(())
    }

    fn copy_pe_file<Pe: ImageNtHeaders>(
        &self,
        data: &[u8],
        embedded_config: &EmbeddedConfig,
    ) -> Result<Vec<u8>> {
        let in_data = self.data.as_slice();
        let in_dos_header = pe::ImageDosHeader::parse(in_data)?;
        let mut offset = in_dos_header.nt_headers_offset().into();
        let in_rich_header = object::read::pe::RichHeaderInfo::parse(in_data, offset);
        let (in_nt_headers, in_data_directories) = Pe::parse(in_data, &mut offset)?;
        let in_file_header = in_nt_headers.file_header();
        let in_optional_header = in_nt_headers.optional_header();
        let in_sections = in_file_header.sections(in_data, offset)?;

        let mut out_data = Vec::new();
        let mut writer = object::write::pe::Writer::new(
            in_nt_headers.is_type_64(),
            in_optional_header.section_alignment(),
            in_optional_header.file_alignment(),
            &mut out_data,
        );

        // Reserve file ranges and virtual addresses.
        writer.reserve_dos_header_and_stub();
        if let Some(in_rich_header) = in_rich_header.as_ref() {
            writer.reserve(in_rich_header.length as u32 + 8, 4);
        }
        writer.reserve_nt_headers(in_data_directories.len());

        // Copy data directories that don't have special handling.
        let cert_dir = in_data_directories
            .get(pe::IMAGE_DIRECTORY_ENTRY_SECURITY)
            .map(pe::ImageDataDirectory::address_range);
        let reloc_dir = in_data_directories
            .get(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .map(pe::ImageDataDirectory::address_range);
        for (i, dir) in in_data_directories.iter().enumerate() {
            if dir.virtual_address.get(LE) == 0
                || i == pe::IMAGE_DIRECTORY_ENTRY_SECURITY
                || i == pe::IMAGE_DIRECTORY_ENTRY_BASERELOC
            {
                continue;
            }
            writer.set_data_directory(i, dir.virtual_address.get(LE), dir.size.get(LE));
        }

        // Determine which sections to copy.
        // We ignore any existing ".reloc" section since we recreate it ourselves.
        let mut in_sections_index = Vec::new();
        for (index, in_section) in in_sections.enumerate() {
            if reloc_dir == Some(in_section.pe_address_range()) {
                continue;
            }
            in_sections_index.push(index);
        }

        let mut out_sections_len = in_sections_index.len();
        if reloc_dir.is_some() {
            out_sections_len += 1;
        }

        // Add one more section for our embedded data
        out_sections_len += 1;

        writer.reserve_section_headers(out_sections_len as u16);

        let mut in_sections_data = Vec::new();
        for index in &in_sections_index {
            let in_section = in_sections.section(*index)?;
            let range = writer.reserve_section(
                in_section.name,
                in_section.characteristics.get(LE),
                in_section.virtual_size.get(LE),
                in_section.size_of_raw_data.get(LE),
            );
            debug_assert_eq!(range.virtual_address, in_section.virtual_address.get(LE));
            debug_assert_eq!(range.file_offset, in_section.pointer_to_raw_data.get(LE));
            debug_assert_eq!(range.file_size, in_section.size_of_raw_data.get(LE));
            in_sections_data.push((range.file_offset, in_section.pe_data(in_data)?));
        }

        // Add our new section for embedded data
        let mut new_section_name = [0u8; 8];
        new_section_name[..8].copy_from_slice(&b".fripac\0"[..8]);
        let new_section_characteristics =
            pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ | pe::IMAGE_SCN_MEM_WRITE;
        let new_section_range = writer.reserve_section(
            new_section_name,
            new_section_characteristics,
            data.len() as u32,
            data.len() as u32,
        );

        if reloc_dir.is_some() {
            let mut blocks = in_data_directories
                .relocation_blocks(in_data, &in_sections)?
                .unwrap();
            while let Some(block) = blocks.next()? {
                for reloc in block {
                    writer.add_reloc(reloc.virtual_address, reloc.typ);
                }
            }
            writer.reserve_reloc_section();
        }

        if let Some((_, size)) = cert_dir {
            // TODO: reserve individual certificates
            writer.reserve_certificate_table(size);
        }

        // Start writing.
        writer.write_dos_header_and_stub()?;
        if let Some(in_rich_header) = in_rich_header.as_ref() {
            // TODO: recalculate xor key
            writer.write_align(4);
            writer.write(&in_data[in_rich_header.offset..][..in_rich_header.length + 8]);
        }
        writer.write_nt_headers(object::write::pe::NtHeaders {
            machine: in_file_header.machine.get(LE),
            time_date_stamp: in_file_header.time_date_stamp.get(LE),
            characteristics: in_file_header.characteristics.get(LE),
            major_linker_version: in_optional_header.major_linker_version(),
            minor_linker_version: in_optional_header.minor_linker_version(),
            address_of_entry_point: in_optional_header.address_of_entry_point(),
            image_base: in_optional_header.image_base(),
            major_operating_system_version: in_optional_header.major_operating_system_version(),
            minor_operating_system_version: in_optional_header.minor_operating_system_version(),
            major_image_version: in_optional_header.major_image_version(),
            minor_image_version: in_optional_header.minor_image_version(),
            major_subsystem_version: in_optional_header.major_subsystem_version(),
            minor_subsystem_version: in_optional_header.minor_subsystem_version(),
            subsystem: in_optional_header.subsystem(),
            dll_characteristics: in_optional_header.dll_characteristics(),
            size_of_stack_reserve: in_optional_header.size_of_stack_reserve(),
            size_of_stack_commit: in_optional_header.size_of_stack_commit(),
            size_of_heap_reserve: in_optional_header.size_of_heap_reserve(),
            size_of_heap_commit: in_optional_header.size_of_heap_commit(),
        });
        writer.write_section_headers();
        for (offset, data) in in_sections_data {
            writer.write_section(offset, data);
        }

        // Write our new section with embedded data
        writer.write_section(new_section_range.file_offset, data);

        writer.write_reloc_section();
        if let Some((address, size)) = cert_dir {
            // TODO: write individual certificates
            writer.write_certificate_table(&in_data[address as usize..][..size as usize]);
        }

        debug_assert_eq!(writer.reserved_len() as usize, writer.len());

        // Now update the embedded config offset
        let embedded_config_offset = self
            .find_embedded_config()
            .context("Failed to find embedded config after adding data")?;

        let config_data_offset = new_section_range.file_offset as i32;
        let config_data_rva = new_section_range.virtual_address as i32;

        // Find the section containing the embedded config
        let mut config_section_rva = 0;
        let mut config_section_offset = 0;
        for index in &in_sections_index {
            let in_section = in_sections.section(*index)?;
            let section_start = in_section.pointer_to_raw_data.get(LE) as usize;
            let section_end = section_start + in_section.size_of_raw_data.get(LE) as usize;
            if embedded_config_offset >= section_start && embedded_config_offset < section_end {
                config_section_rva = in_section.virtual_address.get(LE) as i32;
                config_section_offset = in_section.pointer_to_raw_data.get(LE) as i32;
                break;
            }
        }

        let mut updated_config = *embedded_config;
        updated_config.data_offset = (config_data_offset as i32 - embedded_config_offset as i32)
            - (config_data_offset as i32 - config_section_offset as i32)
            + (config_data_rva - config_section_rva);

        let config_bytes = updated_config.as_bytes();
        let mut final_out_data = out_data;
        final_out_data[embedded_config_offset..embedded_config_offset + config_bytes.len()]
            .copy_from_slice(&config_bytes);

        Ok(final_out_data)
    }

    fn compress_xz(&self, data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Write;
        use xz2::write::XzEncoder;

        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small Mach-O dylib exposing the same ABI as a real payload.
    /// Regenerate with `tests/fixtures/build_fixture.sh`.
    const MACHO_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/payload-macos-arm64.dylib");

    fn payload_bytes() -> &'static [u8] {
        br#"{"mode":1,"js_filepath":"main.js","js_content":"console.log(1)","watch_path":null}"#
    }

    fn read_i32(data: &[u8], offset: usize) -> i32 {
        i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn macho_fixture_is_recognised() {
        let processor = BinaryProcessor::new(MACHO_FIXTURE.to_vec()).unwrap();
        assert!(matches!(processor.format, ObjectFormat::MachO));
        assert!(processor.find_embedded_config().is_some());
    }

    /// The reserved section must be file-backed, otherwise the whole approach
    /// cannot work (this is the failure mode a payload without an explicit
    /// initialiser runs into).
    #[test]
    fn macho_fixture_reserved_section_is_file_backed() {
        let file = object::read::File::parse(MACHO_FIXTURE).unwrap();
        let section = file
            .sections()
            .find(|section| section.name() == Ok(PAYLOAD_SECTION))
            .expect("fixture must expose the reserved section");
        let (_, size) = section
            .file_range()
            .expect("reserved section must occupy file space");
        assert_eq!(size, 4096);
    }

    #[test]
    fn macho_patch_writes_config_and_payload() {
        let mut processor = BinaryProcessor::new(MACHO_FIXTURE.to_vec()).unwrap();
        let config_offset = processor.find_embedded_config().unwrap();

        let payload = payload_bytes();
        processor.add_embedded_config_data(payload, false).unwrap();
        let patched = processor.into_data();

        assert_eq!(
            read_i32(&patched, config_offset + 12) as usize,
            payload.len()
        );
        assert_eq!(patched[config_offset + 20], 0, "data_xz must stay false");

        // `data_offset` is a virtual-address delta, so it must land exactly on
        // the reserved section's contents.
        let data_offset = read_i32(&patched, config_offset + 16);
        let start = (config_offset as i64 + data_offset as i64) as usize;
        assert_eq!(&patched[start..start + payload.len()], payload);

        // ... and that address must be the section's virtual address.
        let file = object::read::File::parse(patched.as_slice()).unwrap();
        let section = file
            .sections()
            .find(|section| section.name() == Ok(PAYLOAD_SECTION))
            .unwrap();
        let segment = file
            .segments()
            .find(|segment| {
                let (offset, size) = segment.file_range();
                size > 0 && offset <= config_offset as u64 && (config_offset as u64) < offset + size
            })
            .unwrap();
        let (segment_offset, _) = segment.file_range();
        let config_vaddr = config_offset as u64 - segment_offset + segment.address();
        assert_eq!(
            start as u64,
            section.address() - config_vaddr + config_offset as u64
        );
        assert_eq!(
            section.address() as i64 - config_vaddr as i64,
            data_offset as i64
        );
    }

    #[test]
    fn macho_missing_reserved_section_is_reported() {
        // Scramble the section name in the section header.
        let mut data = MACHO_FIXTURE.to_vec();
        let position = data
            .windows(PAYLOAD_SECTION.len())
            .position(|window| window == PAYLOAD_SECTION.as_bytes())
            .expect("fixture must contain the section name");
        data[position..position + PAYLOAD_SECTION.len()].copy_from_slice(b"__fripacX");

        let mut processor = BinaryProcessor::new(data).unwrap();
        let error = processor
            .add_embedded_config_data(payload_bytes(), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not found"), "unexpected error: {error}");
    }

    #[test]
    fn macho_missing_config_magic_is_reported() {
        let mut data = MACHO_FIXTURE.to_vec();
        let position = data
            .windows(4)
            .position(|window| window == 0x0d000721i32.to_le_bytes())
            .expect("fixture must contain the config magic");
        data[position] ^= 0xff;

        let mut processor = BinaryProcessor::new(data).unwrap();
        let error = processor
            .add_embedded_config_data(payload_bytes(), false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("embedded config"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn macho_oversized_payload_is_rejected() {
        let mut processor = BinaryProcessor::new(MACHO_FIXTURE.to_vec()).unwrap();
        let error = processor
            .add_embedded_config_data(&vec![0u8; 4097], false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("only holds"), "unexpected error: {error}");
    }

    #[test]
    fn non_object_data_is_rejected() {
        assert!(BinaryProcessor::new(b"not a binary at all".to_vec()).is_err());
    }

    #[test]
    fn universal_macho_is_reported_clearly() {
        // Minimal fat header: magic + one architecture entry.
        let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x01];
        fat.extend_from_slice(&[0u8; 20]);

        let error = match BinaryProcessor::new(fat) {
            Ok(_) => panic!("universal Mach-O should be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Universal"), "unexpected error: {error}");
    }
}
