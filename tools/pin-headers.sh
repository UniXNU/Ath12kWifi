#!/bin/bash
# Link the public Linux headers that are used as they are into out/pinned (everything else comes from shim/include).
cd "$(dirname "$0")/.."
L=$PWD/deps/linux/include
rm -rf out/pinned; mkdir -p out/pinned/linux/soc/qcom out/pinned/net
for h in linux/mhi.h linux/ieee80211.h linux/soc/qcom/qmi.h net/cfg80211.h net/regulatory.h net/codel.h net/ieee80211_radiotap.h; do
  mkdir -p out/pinned/$(dirname $h); ln -s $L/$h out/pinned/$h
done
for f in $L/linux/ieee80211-*.h; do ln -s $f out/pinned/linux/$(basename $f); done
ln -s $L/uapi/linux/nl80211.h out/pinned/linux/nl80211.h
ln -s $L/uapi/linux/rfkill.h out/pinned/linux/rfkill.h
mkdir -p out/pinned/uapi/linux; ln -s $L/uapi/linux/rfkill.h out/pinned/uapi/linux/rfkill.h
ln -s $L/net/mac80211.h out/pinned/net/mac80211.real.h
