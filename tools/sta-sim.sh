#!/bin/bash
# The station code against a fake driver and access point (tests/sta_sim.c).
cd "$(dirname "$0")/.."
bash tools/link-check.sh >/dev/null 2>&1
clang -std=gnu11 -w -g -DCONFIG_ATH12K_DEBUG -include lx_pci.h -I shim/include -I include -I out/pinned -I src -I out/ath12k-src tests/sta_sim.c out/all/lx_rt.o out/all/nw_sta.o out/all/nw_crypto.o out/all/nw_mac80211.o out/all/nw_net.o -o out/sta_sim 2>&1 | grep -E "error|undefined|Undefined|_" | head -20
./out/sta_sim
