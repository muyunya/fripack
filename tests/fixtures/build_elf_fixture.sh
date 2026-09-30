#!/bin/sh
# Rebuilds payload-linux-x86_64.so, the ELF payload fixture.
#
# Has to run on Linux: the fixture is an ELF shared object, so a cross toolchain
# is needed anywhere else. The committed binary is what the tests use.
set -eu
cd "$(dirname "$0")"
g++ -shared -fPIC -O1 -o payload-linux-x86_64.so payload_elf.cc
