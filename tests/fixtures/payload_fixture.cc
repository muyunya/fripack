// Minimal stand-in for a fripack Mach-O payload, used by the patching tests in
// src/binary.rs.
//
// It mirrors the ABI the real payloads expose:
//   * `g_embedded_config`       - the struct fripack locates by magic and fills in
//   * `g_fripack_payload`       - the reserved, file-backed section the script is
//                                 written into (see PAYLOAD_SECTION in src/binary.rs)
//
// Note the explicit initialiser on the reserved buffer: a buffer without one is
// folded into zerofill by the linker, which means it occupies no file space and
// cannot be patched in place.
//
// Regenerate with ./build_fixture.sh after changing this file.

#include <cstdint>

struct __attribute__((packed)) EmbeddedConfig {
  int32_t magic1 = 0x0d000721;
  int32_t magic2 = 0x1f8a4e2b;
  int32_t version = 1;
  int32_t data_size = 0;
  int32_t data_offset = 0;
  bool data_xz = false;
};

extern "C" __attribute__((visibility("default"))) EmbeddedConfig g_embedded_config{};

extern "C" __attribute__((used, section("__DATA,__fripack")))
char g_fripack_payload[4096] = {0};
