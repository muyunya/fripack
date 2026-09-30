// Throwaway Mach-O payload used by tests/e2e/macos_e2e.sh.
//
// It exposes the same ABI as a real payload (see tests/fixtures/payload_fixture.cc)
// but additionally prints whatever fripack embedded, which is what the end-to-end
// test asserts on.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#define FRIPACK_E2E_RESERVE 4096

struct __attribute__((packed)) EmbeddedConfig {
  int32_t magic1 = 0x0d000721;
  int32_t magic2 = 0x1f8a4e2b;
  int32_t version = 1;
  int32_t data_size = 0;
  int32_t data_offset = 0;
  bool data_xz = false;
};

extern "C" __attribute__((visibility("default"))) EmbeddedConfig g_embedded_config{};

// The explicit initialiser is required: without it the linker folds the buffer
// into zerofill and it occupies no file space, so fripack cannot patch it.
extern "C" __attribute__((used, section("__DATA,__fripack")))
char g_fripack_payload[FRIPACK_E2E_RESERVE] = {0};

__attribute__((constructor)) static void payload_main() {
  const auto &config = g_embedded_config;
  if (config.magic1 != 0x0d000721 || config.magic2 != 0x1f8a4e2b ||
      config.version != 1 || config.data_size <= 0 || config.data_offset == 0) {
    std::fprintf(stderr, "[e2e] RESULT=FAIL no embedded config\n");
    return;
  }

  const char *data =
      reinterpret_cast<const char *>(&g_embedded_config) + config.data_offset;
  std::string contents(data, static_cast<size_t>(config.data_size));
  std::fprintf(stderr, "[e2e] RESULT=OK %s\n", contents.c_str());
}
