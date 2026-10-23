#!/bin/bash
# Build the MHI host sources with the runtime and run them against the simulated boot ROM.
cd "$(dirname "$0")/.."
set -e
bash tools/check-mhi.sh >/dev/null 2>&1 || true
L=$PWD/deps/linux; O=out/mhi-src
CF="-std=gnu11 -g -w -I shim/include -I src -I $O -idirafter $L/include"
mkdir -p out/t
for f in init main pm boot; do clang $CF -c $O/$f.c -o out/t/$f.o; done
clang $CF -c shim/src/lx_rt.c -o out/t/rt.o; clang $CF -c shim/src/mhi_hook.c -o out/t/hook.o
clang $CF -c src/nw_mhi.c -o out/t/nw.o; clang $CF -c tests/mhi_host_test.c -o out/t/t.o
clang out/t/*.o -o out/t/mhi_test
./out/t/mhi_test
