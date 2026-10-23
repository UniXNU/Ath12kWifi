/* Starts the driver stack on the board and drives a station interface: scan on a timer and report what is heard. */
#include "lx_pci.h"
#include "lx_plat.h"
#include <net/mac80211.h>
#include "core.h"
#include "debug.h"
#include "nw_mhi.h"
#include "nw_qrtr.h"
#include "nw_mac80211.h"
#include "nw_wifi.h"
#include "nw_sta.h"
#include "nw_board.h"

int ath12k_wifi7_pci_init(void);
void ath12k_wifi7_pci_exit(void);
int mhi_init_hook(void);
extern unsigned int ath12k_debug_mask;

struct nw_wifi_stats nw_wifi_stats;
static void on_rx(struct ieee80211_hw *hw, struct sk_buff *skb) { (void)hw; nw_sta_rx(skb); }
static void on_scan_done(struct ieee80211_hw *hw, bool aborted) { (void)hw; nw_sta_scan_done(aborted); }
static void on_lost(void) { nw_sta_link_lost(); }
static void on_registered(struct ieee80211_hw *hw) { nw_sta_ready(hw); }
static const struct nw_wifi_hooks hooks = { .registered = on_registered, .rx = on_rx, .scan_done = on_scan_done, .beacon_loss = on_lost };

/* The first time the MHI core reports the device's RAM dump state, the boot interface's registers say where the boot stopped. */
static int has_text(const char *s, const char *w) {
  for (; *s; s++) { const char *a = s, *b = w; while (*a && *b && *a == *b) { a++; b++; } if (!*b) return 1; }
  return 0; }
static void log_tap(int level, const char *line) {
  static int done; (void)level;
  if (done || !has_text(line, "RDDM") || !nw_board || !nw_board->bar) return;
  done = 1;
  const volatile u8 *m = nw_board->bar; u32 bhi = readl(m + 0x2c);
  if (bhi >= nw_board->bar_len) bhi = 0x100;
  lx_log(3, "rddm: mhistatus %08x mhictrl %08x ee %08x bhi-status %08x err %08x dbg %08x %08x %08x",
         readl(m + 0x48), readl(m + 0x38), readl(m + bhi + 0x28), readl(m + bhi + 0x2c), readl(m + bhi + 0x30), readl(m + bhi + 0x34),
         readl(m + bhi + 0x38), readl(m + bhi + 0x3c)); }

void lx_irq_raise_all(void);
static void irq_poll(void) { lx_irq_raise_all(); }
int nw_wifi_start(const struct lx_platform *p, const struct nw_board *b) {
  lx_plat = p; nw_board = b; ath12k_debug_mask = 0xffffffffu & ~0x2000u;
  lx_root_init(); lx_log_tap = log_tap; nw_qrtr_init(); nw_wifi_set_hooks(&hooks);
  int r = mhi_init_hook(); if (r) return r;
  r = nw_qrtr_mhi_register(); if (r) return r;
  nw_wifi_stats.stage = 1;
  r = ath12k_wifi7_pci_init();
  if (r) { nw_wifi_stats.last_err = r; lx_log(3, "wifi: driver start failed: %d", r); return r; }
  nw_wifi_stats.stage = 2; return 0; }
int nw_wifi_step(void) { irq_poll(); int r = lx_pump(); nw_sta_run(); return r; }
void nw_wifi_stop(void) { ath12k_wifi7_pci_exit(); }
