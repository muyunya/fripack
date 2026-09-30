#!/bin/sh
# Regenerates the committed Mach-O fixture used by the tests in src/binary.rs.
set -e
cd "$(dirname "$0")"
clang++ -dynamiclib -O1 -o payload-macos-arm64.dylib payload_fixture.cc
echo "wrote $(pwd)/payload-macos-arm64.dylib"
