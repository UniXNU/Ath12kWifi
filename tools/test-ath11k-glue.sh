#!/bin/bash
# Build tests/ath11k_glue_test.c with the ath11k glue, the driver's peer table (peer.c, on the shared hash table of src/nw_net.c) and cfg80211's
# rate calculation (util.c) under ASan/UBSan, against the shim's C library headers, and run it. Symbols those objects name but the test
# never reaches stay unresolved.
set -e
cd "$(dirname "$0")/.."
bash tools/prepare.sh >/dev/null
R=$(clang -print-resource-dir)/include; D=out/ath11k-glue-test; rm -rf $D; mkdir -p $D
F=(-c -nostdinc -isystem shim/libc -isystem $R -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -w
   -DCONFIG_CFG80211=1 -DCONFIG_MAC80211=1 -DCONFIG_MAC80211_STA_HASH_MAX_SIZE=0 '-DCONFIG_MAC80211_RC_DEFAULT=""' -fno-strict-aliasing -fwrapv
   -include lx_pci.h -I shim/include -I include -I src -I out/pinned -I out)
A11K=(-I out/ath11k-src -include lx_ath11k.h -DCONFIG_ATH11K_DEBUG)
clang "${F[@]}" "${A11K[@]}" tests/ath11k_glue_test.c -o $D/test.o
clang "${F[@]}" "${A11K[@]}" src/nw_wifi_ath11k.c -o $D/glue.o
clang "${F[@]}" "${A11K[@]}" out/ath11k-src/peer.c -o $D/peer.o
clang "${F[@]}" -I out/cfg80211 out/cfg80211/util.c -o $D/util.o
clang "${F[@]}" src/nw_net.c -o $D/net.o
clang -fsanitize=address,undefined -no-pie -Wl,--unresolved-symbols=ignore-all $D/*.o -o $D/test
stdbuf -o0 $D/test
