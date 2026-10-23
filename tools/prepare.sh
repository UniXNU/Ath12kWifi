#!/bin/bash
# Lays out the generated include trees the sources are built from: out/pinned (public headers used as they are), out/ath12k-src and out/mhi-src
# (links to the driver sources with the trace points replaced by empty ones).
cd "$(dirname "$0")/.."
bash tools/pin-headers.sh
L=$PWD/deps/linux
A=$L/drivers/net/wireless/ath/ath12k; O=out/ath12k-src
rm -rf $O; mkdir -p $O/wifi7
for f in $A/*.c $A/*.h; do ln -s $f $O/; done
for f in $A/wifi7/*.c $A/wifi7/*.h; do ln -s $f $O/wifi7/; done
rm -f $O/trace.h
{ echo '#ifndef LX_ATH12K_TRACE_H'; echo '#define LX_ATH12K_TRACE_H'; grep -ohE "trace_ath12k_[a-z_0-9]+" $A/*.c $A/*.h $A/wifi7/*.c | sort -u | sed 's/.*/#define & (...) ((void)0)/' | sed 's/ (\.\.\.)/(...)/'; echo '#endif'; } > $O/trace.h
H=$L/drivers/bus/mhi/host; M=out/mhi-src
rm -rf $M; mkdir -p $M
for f in $H/*.c $H/internal.h; do ln -s $f $M/; done
cp shim/mhi/trace.h $M/trace.h
ln -sf $L/drivers/bus/mhi/common.h out/common.h
