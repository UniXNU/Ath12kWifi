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
# One call is added to the generated copy of boot.c: the chip's boot loader is given its MHI contexts (and some time after the reset) before the image is offered.
rm -f out/mhi-src/boot.c; cp $H/boot.c out/mhi-src/boot.c
python3 - <<'PY'
p='out/mhi-src/boot.c'; s=open(p).read()
mark='\tret = request_firmware(&firmware, fw_name, dev);'
assert mark in s
if 'nw_mhi_pre_load' not in s:
    s=s.replace(mark,'\t{ extern void nw_mhi_pre_load(struct mhi_controller *); nw_mhi_pre_load(mhi_cntrl); }\n'+mark,1)
open(p,'w').write(s)
PY
# The refill ring of the receive buffers is the largest user of the endpoint's DMA window; the copy of dp.h makes it 512 buffers instead of 4096.
rm -f $O/dp.h; sed 's/^#define DP_RXDMA_BUF_RING_SIZE\t\t4096/#define DP_RXDMA_BUF_RING_SIZE\t\t512/' $A/dp.h > $O/dp.h
grep -q 'DP_RXDMA_BUF_RING_SIZE.*512' $O/dp.h || { echo "dp.h patch missed" >&2; exit 1; }
# Sending a command is the condition of the wait in ath12k_wmi_cmd_send: that wait must evaluate it once per round and never after it has succeeded.
rm -f $O/wmi.c; sed '/^int ath12k_wmi_cmd_send(/,/^}/ s/wait_event_timeout(/wait_event_timeout_once(/' $A/wmi.c > $O/wmi.c
grep -q 'wait_event_timeout_once' $O/wmi.c || { echo "wmi.c patch missed" >&2; exit 1; }
ln -sf $L/drivers/bus/mhi/common.h out/common.h
