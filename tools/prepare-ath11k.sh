#!/bin/bash
set -euo pipefail
# Lays out out/ath11k-src: links to the ath11k driver sources with the trace points replaced by empty ones, and links to the headers of the parent directory that they include with ../.
cd "$(dirname "$0")/.."
[ -d out/pinned ] || bash tools/pin-headers.sh
L=$PWD/deps/linux/drivers/net/wireless/ath; A=$L/ath11k; O=out/ath11k-src
rm -rf $O; mkdir -p $O
for f in $A/*.c $A/*.h; do ln -s $f $O/; done
rm -f $O/trace.h
# The debug mask test in ath11k_dbg() ORs the trace point's enabled test into a condition, so that one must be a number and not void.
{ echo '#ifndef LX_ATH11K_TRACE_H'; echo '#define LX_ATH11K_TRACE_H'; grep -ohE "trace_ath11k_[a-z_0-9]+" $A/*.c $A/*.h | sort -u | grep -v '_enabled$' | sed -E 's/.*/#define &(...) ((void)0)/'; echo '#define trace_ath11k_log_dbg_enabled(...) 0'; echo '#endif'; } > $O/trace.h
for h in $(grep -ohE '#include "\.\./[^"]+"' $A/*.c $A/*.h | sed -E 's/#include "\.\.\/([^"]+)"/\1/' | sort -u); do ln -sf $L/$h out/$h; done
# The driver's entry point is static and is registered by module_init, which is empty here: the copy of pci.c makes it callable.
rm -f $O/pci.c; sed 's/^static int ath11k_pci_init(void)/int ath11k_pci_init(void)/' $A/pci.c > $O/pci.c
grep -q '^int ath11k_pci_init(void)' $O/pci.c || { echo "pci.c patch missed" >&2; exit 1; }
# Sending a command is the condition of the waits in ath11k_wmi_cmd_send: they must evaluate it once per round and never after it has succeeded.
rm -f $O/wmi.c; sed '/^int ath11k_wmi_cmd_send(/,/^}/ s/wait_event_timeout(/wait_event_timeout_once(/' $A/wmi.c > $O/wmi.c
[ "$(grep -c 'wait_event_timeout_once(' $O/wmi.c)" -eq 2 ] || { echo "wmi.c patch missed" >&2; exit 1; }
# ath11k_pci_select_window writes the window register only when the window number changes, and power-up records window 0 without writing it:
# the register keeps whatever the boot loader or a previous start left there, and the first access to window 0 would go elsewhere. The copy
# of pci.c records a number no window has, so the first windowed access writes the register. (Taken from the alioth QCA6390 build.)
python3 - "$O/pci.c" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = '\tab_pci->register_window = 0;\n'
assert s.count(old) == 1, "pci.c window mark"
open(p, 'w').write(s.replace(old, '\tab_pci->register_window = 0xffffffff;\n', 1))
PY
