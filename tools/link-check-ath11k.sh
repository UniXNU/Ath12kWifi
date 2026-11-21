#!/bin/bash
# Compile every source of tools/sources-ath11k.txt with the flags of the kernel build (arm64e, -O2), then list the symbols that the ath11k
# objects use and nothing defines, the XNU imports of the whole set, and duplicate definitions. The shared entries of the manifest must be
# those of tools/sources.txt.
cd "$(dirname "$0")/.."
bash tools/prepare.sh >/dev/null 2>&1 || { echo "prepare.sh failed" >&2; exit 1; }
M=tools/sources-ath11k.txt
shared() { grep -v -e '^#' -e '^$' -e '^ath1[12]k:' "$1" | sed -e 's#^src/nw_wifi\(_ath11k\)\?\.c$#GLUE_WIFI#' -e 's#^src/nw_debug\(_ath11k\)\?\.c$#GLUE_DEBUG#'; }
diff <(shared tools/sources.txt) <(shared $M) >/dev/null || { echo "$M: shared entries differ from tools/sources.txt" >&2; diff <(shared tools/sources.txt) <(shared $M) >&2; exit 1; }
R=$(clang -print-resource-dir)/include; D=out/ath11k-link; rm -rf $D; mkdir -p $D
K=(-target arm64e-apple-ios27.0 -mkernel -ffreestanding -fno-builtin -fno-common -fno-stack-protector -mgeneral-regs-only)
F=("${K[@]}" -c -O2 -nostdinc -isystem shim/libc -isystem $R -std=gnu11 -w -g0 -Wno-incompatible-pointer-types -Wno-pointer-sign -Wno-macro-redefined -fno-strict-aliasing -fwrapv -DCONFIG_CFG80211=1 -DCONFIG_MAC80211=1 -DCONFIG_MAC80211_STA_HASH_MAX_SIZE=0 '-DCONFIG_MAC80211_RC_DEFAULT=""' -include lx_pci.h -I shim/include -I include -I src -I out/pinned -I out)
A11K=(-I out/ath11k-src -include lx_ath11k.h -DCONFIG_ATH11K_DEBUG)
n=0
while read -r line; do
  case "$line" in ''|'#'*) continue;; esac
  tree=; name=$line; case "$line" in *:*) tree=${line%%:*}; name=${line#*:};; esac
  x=()
  case $tree in mac80211|cfg80211) src=out/$tree/$name; x=(-I out/$tree);; crypto) src=out/crypto/$name; x=(-I shim/crypto -I out/crypto);; generated) src=out/$name;; mhi) src=out/mhi-src/$name; x=(-I out/mhi-src);; qmi) src=deps/linux/drivers/soc/qcom/$name;; ath11k) src=out/ath11k-src/$name; x=("${A11K[@]}");; *) src=$line;; esac
  case $line in src/*_ath11k.c) x+=("${A11K[@]}");; src/nw_crypto_mac80211.c) x+=(-I shim/crypto -I out/crypto -I out/mac80211);; src/nw_fils.c) x+=(-I out/mac80211);; src/nw_cfg80211_*) x+=(-I out/cfg80211);; crypto:aes-siv.c) x+=(-Daes_siv_encrypt=nw_aes_siv_encrypt -Daes_siv_decrypt=nw_aes_siv_decrypt);; esac
  clang "${x[@]}" "${F[@]}" $src -o $D/${tree:-src}_$(basename $src .c).o 2>&1 | grep error | head -2 | sed "s#^#[$line] #"
  n=$((n+1))
done < $M
echo "manifest entries: $n, objects: $(ls $D/*.o | wc -l)"
# Mach-O names carry a leading underscore; the lists below keep it.
llvm-nm -g --defined-only $D/*.o | awk 'NF==3{print $3}' | sort > $D/def-all.txt
sort -u $D/def-all.txt > $D/def.txt
llvm-nm -u $D/ath11k_*.o $D/src_nw_*ath11k.o | grep -v -e ':$' -e '^$' | sort -u | comm -13 $D/def.txt - > $D/a11k-imports.txt
llvm-nm -u $D/*.o | grep -v -e ':$' -e '^$' | sort -u | comm -13 $D/def.txt - > $D/imports.txt
uniq -d $D/def-all.txt > $D/duplicates.txt
echo "ath11k imports: $(tr '\n' ' ' < $D/a11k-imports.txt)"
echo "all imports ($(wc -l < $D/imports.txt)): $(tr '\n' ' ' < $D/imports.txt)"
echo "duplicate definitions: $(wc -l < $D/duplicates.txt) $(tr '\n' ' ' < $D/duplicates.txt)"
[ "$(ls $D/*.o | wc -l)" -eq $n ] && [ ! -s $D/duplicates.txt ]
