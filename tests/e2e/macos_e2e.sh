#!/usr/bin/env bash
#
# End-to-end check for macOS targets.
#
# Builds a throwaway Mach-O payload, patches it with the fripack CLI, injects the
# result into a separate host process and verifies two things:
#   1. the script fripack embedded is what the payload reads back at runtime;
#   2. a payload whose signature was invalidated must NOT load.
#
# Requires macOS (clang, codesign, dyld). Run `cargo build` first.
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"
CLI="${FRIPACK_BIN:-$ROOT/target/debug/fripack}"

if [ ! -x "$CLI" ]; then
  echo "error: fripack binary not found at $CLI (run 'cargo build' first)" >&2
  exit 1
fi

case "$(uname -m)" in
  arm64)  PLATFORM=macos-arm64 ;;
  x86_64) PLATFORM=macos-x86_64 ;;
  *) echo "error: unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building payload and host for $PLATFORM =="
clang++ -dynamiclib -O1 -o "$WORK/libpayload.dylib" tests/e2e/payload_e2e.cc
clang -o "$WORK/host" tests/e2e/host.c

echo "== patching with fripack =="
cat > "$WORK/fripack.json" <<JSON
{
  "macos": {
    "type": "shared",
    "platform": "$PLATFORM",
    "entry": "./main.js",
    "xz": false,
    "outputDir": "./out",
    "targetBaseName": "e2e",
    "overridePrebuildFile": "./libpayload.dylib"
  }
}
JSON
echo 'globalThis.__fripack_e2e_marker = "hello-from-fripack";' > "$WORK/main.js"
(cd "$WORK" && "$CLI" build macos)

OUT="$WORK/out/e2e-$PLATFORM.dylib"
[ -f "$OUT" ] || { echo "FAIL: expected artifact $OUT was not produced" >&2; exit 1; }

echo "== checking the artifact was re-signed =="
# Note: capture first, then match. `codesign | grep -q` would trip pipefail,
# because grep -q closes the pipe and codesign then dies of SIGPIPE.
SIGNATURE_INFO="$(codesign -dvvv "$OUT" 2>&1 || true)"
case "$SIGNATURE_INFO" in
  *adhoc*) echo "   ok: ad-hoc signed" ;;
  *) echo "FAIL: artifact is not ad-hoc signed" >&2; echo "$SIGNATURE_INFO" >&2; exit 1 ;;
esac

echo "== injecting into a host process =="
LOG="$WORK/run.log"
DYLD_INSERT_LIBRARIES="$OUT" "$WORK/host" > "$LOG" 2>&1 \
  || { echo "FAIL: host exited non-zero" >&2; cat "$LOG"; exit 1; }
grep -q "hello-from-fripack" "$LOG" \
  || { echo "FAIL: embedded script was not recovered by the payload" >&2; cat "$LOG"; exit 1; }
echo "   ok: payload recovered the embedded script"

echo "== negative case: invalidated signature must not load =="
SECTION_OFFSET="$(otool -l "$OUT" | awk '/sectname __fripack/{seen=1} seen && $1=="offset"{print $2; exit}')"
[ -n "$SECTION_OFFSET" ] || { echo "FAIL: could not locate the reserved section" >&2; exit 1; }

BROKEN="$WORK/broken.dylib"
cp "$OUT" "$BROKEN"
printf '\xff' | dd of="$BROKEN" bs=1 seek="$((SECTION_OFFSET + 2048))" count=1 conv=notrunc 2>/dev/null

set +e
DYLD_INSERT_LIBRARIES="$BROKEN" "$WORK/host" > "$WORK/broken.log" 2>&1
STATUS=$?
set -e
[ "$STATUS" -ne 0 ] \
  || { echo "FAIL: a payload with a broken signature was loaded anyway" >&2; exit 1; }
grep -q "hello-from-fripack" "$WORK/broken.log" \
  && { echo "FAIL: broken payload executed" >&2; exit 1; }
echo "   ok: broken signature rejected (exit $STATUS)"

echo "PASS: macOS end-to-end"
