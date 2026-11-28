#!/bin/bash
# Syntax check of the ath11k sources of tools/sources-ath11k.txt; the ones behind Kconfig switches (debugfs, testmode, thermal, spectral, wow, coredump, cfr, ahb) are not in it.
cd "$(dirname "$0")/.."
bash tools/prepare-ath11k.sh || exit 1
O=$PWD/out/ath11k-src; R=$(clang -print-resource-dir)/include; n=0
for f in $(sed -n "s/^ath11k:\(.*\)\.c$/\1/p" tools/sources-ath11k.txt); do
  out=$(clang -fsyntax-only -nostdinc -isystem shim/libc -isystem $R -ferror-limit=0 -std=gnu11 -w -DCONFIG_ATH11K_DEBUG -include lx_pci.h -include lx_ath11k.h -I shim/include -I include -I out/pinned -I $O $O/$f.c 2>&1 | grep error || true)
  if [ -n "$out" ]; then echo "== $f"; echo "$out" | head -${N:-6}; n=$((n+1)); fi
done
out=$(clang -fsyntax-only -nostdinc -isystem shim/libc -isystem $R -ferror-limit=0 -std=gnu11 -w -DCONFIG_ATH11K_DEBUG -include lx_pci.h -include lx_ath11k.h -I shim/include -I include -I out/pinned -I $O src/nw_debug_ath11k.c 2>&1 | grep error || true); [ -n "$out" ] && { echo "== nw_debug_ath11k"; echo "$out" | head -6; n=$((n+1)); }
for g in nw_wifi_ath11k; do out=$(clang -fsyntax-only -ferror-limit=0 -nostdinc -isystem shim/libc -isystem $R -std=gnu11 -w -DCONFIG_ATH11K_DEBUG -include lx_pci.h -include lx_ath11k.h -I shim/include -I include -I src -I out/pinned -I out -I out/mhi-src -I $O src/$g.c 2>&1 | grep error || true); [ -n "$out" ] && { echo "== $g"; echo "$out" | head -6; n=$((n+1)); }; done
echo "files with errors: $n"
[ $n -eq 0 ]
