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
# This board has no radio switch on the chip's pin 48: the WCN7850 entry of the copy of wifi7/hw.c names no rfkill pin, so no switch is configured.
rm -f $O/wifi7/hw.c; sed 's/^\t\t\.rfkill_pin = 48,/\t\t.rfkill_pin = 0,/' $A/wifi7/hw.c > $O/wifi7/hw.c
grep -q 'rfkill_pin = 48' $O/wifi7/hw.c && { echo "wifi7/hw.c patch missed" >&2; exit 1; }
# The WCN7850 firmware takes its MLO peer count from the MLO fields of the host capability message and fails an allocation in WMI_INIT
# when they are missing; the firmware does not always flag single chip MLO in its PHY capability reply. The copy of qmi.c treats a
# successful PHY capability reply as single chip MLO support, so the host capability message always carries those fields.
python3 - "$A/qmi.c" "$O/qmi.c" <<'PY'
import os, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
old = '\tif (resp.single_chip_mlo_support_valid && resp.single_chip_mlo_support)\n\t\tab->single_chip_mlo_support = true;\n'
assert s.count(old) == 1, "qmi.c mlo mark"
s = s.replace(old, '\tab->single_chip_mlo_support = true;\n', 1)
if os.path.lexists(dst): os.remove(dst)
open(dst, 'w').write(s)
PY
# The WCN7850 firmware of this board reports an all-zero address, and a scan interface made with it stops the firmware's replies: the copy
# of mac.c asks the board (nw_board_mac) for the address of a radio whose address is not valid.
python3 - "$A/mac.c" "$O/mac.c" <<'PY'
import os, sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
old = '\t\t\tar->mac_addr[4] += ar->pdev_idx;\n\t\t}\n'
assert s.count(old) == 1, "mac.c address mark"
s = s.replace(old, old + '\t\tif (!is_valid_ether_addr(ar->mac_addr)) {\n\t\t\tnw_board_mac(ar->mac_addr);\n\t\t\tar->mac_addr[4] += ar->pdev_idx;\n\t\t}\n', 1)
s = s.replace('#include "mac.h"\n', '#include "mac.h"\nvoid nw_board_mac(u8 *a);\n', 1)
assert 'void nw_board_mac' in s, "mac.c include mark"
if os.path.lexists(dst): os.remove(dst)
open(dst, 'w').write(s)
PY
# The copy also shows the bytes of an event it does not know.
python3 - "$O/wmi.c" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
mark = '\t\tath12k_dbg(ab, ATH12K_DBG_WMI, "Unknown eventid: 0x%x\\n", id);\n'
assert mark in s, "unknown event mark"
s = s.replace(mark, mark + '\t\tath12k_dbg_dump(ab, ATH12K_DBG_WMI, NULL, "", skb->data, skb->len);\n', 1)
open(p, 'w').write(s)
PY
ln -sf $L/drivers/bus/mhi/common.h out/common.h
