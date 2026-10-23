#!/bin/bash
# Fetch the two public source trees NativeWifi builds against into deps/ (not kept in the repository):
#   Linux v7.0.14   the WLAN driver (drivers/net/wireless/ath/ath12k), the MHI host (drivers/bus/mhi/host), the QMI library and QRTR (net/qrtr)
#   FreeBSD releng/15.1   its Linux compatibility headers (sys/compat/linuxkpi), BSD-2-Clause; they follow Linux 7.0
set -e
cd "$(dirname "$0")/.."
mkdir -p deps
if [ ! -d deps/linux ]; then
  git clone -q --depth 1 --branch v7.0.14 --filter=blob:none --sparse https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git deps/linux
  git -C deps/linux sparse-checkout set --no-cone /drivers/net/wireless/ath/ /drivers/bus/mhi/ /include/ /net/qrtr/ /drivers/soc/qcom/qmi_interface.c /drivers/soc/qcom/qmi_encdec.c
fi
if [ ! -d deps/freebsd ]; then
  git clone -q --depth 1 --branch releng/15.1 --filter=blob:none --sparse https://github.com/freebsd/freebsd-src.git deps/freebsd
  git -C deps/freebsd sparse-checkout set --no-cone /sys/compat/linuxkpi/ /sys/net80211/ /sys/sys/
fi
echo done
