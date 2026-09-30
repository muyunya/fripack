// Minimal stand-in for a fripack payload on ELF, used by the patching tests.
//
// It mirrors what a real payload has to provide: a g_embedded_config the patcher
// finds by magic, and a reserved section for the embedded script.
#include <cstdint>
#include <cstdio>
#include <cstring>

#pragma pack(push, 1)
struct EmbeddedConfig {
  int32_t magic1 = 0x0d000721;
  int32_t magic2 = 0x1f8a4e2b;
  int32_t version = 1;
  int32_t data_size = 0;
  int32_t data_offset = 0; // Offset from the start of the struct.
  bool data_xz = false;
};
#pragma pack(pop)

extern "C" __attribute__((visibility("default"))) EmbeddedConfig g_embedded_config{};

// Reserved, file-backed buffer for the embedded script.
//
// No section attribute: a section named `.data.*` would be merged into `.data` by
// the default linker script and lose its name. fripack finds this buffer by symbol
// name through .dynsym instead, which survives stripping.
//
// The initialiser is load-bearing. An all-zero array is folded into .bss, which
// occupies no space in the file and therefore cannot carry the script.
extern "C" __attribute__((used, visibility("default")))
unsigned char g_fripack_payload[65536] = {1};

__attribute__((constructor)) static void report_embedded_config() {
  const char *data =
      reinterpret_cast<const char *>(&g_embedded_config) + g_embedded_config.data_offset;
  char buffer[512] = {0};
  int count = g_embedded_config.data_size;
  if (count < 0) count = 0;
  if (count > 511) count = 511;
  if (count > 0) std::memcpy(buffer, data, static_cast<size_t>(count));
  std::printf("ELF-PAYLOAD size=%d xz=%d data=%s\n", g_embedded_config.data_size,
              g_embedded_config.data_xz ? 1 : 0, buffer);
  std::fflush(stdout);
}
