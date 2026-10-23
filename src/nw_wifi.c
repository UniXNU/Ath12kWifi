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
#include "pci.h"
#include <linux/mhi.h>

int ath12k_wifi7_pci_init(void);
void ath12k_wifi7_pci_exit(void);
int mhi_init_hook(void);
extern unsigned int ath12k_debug_mask;

struct nw_wifi_stats nw_wifi_stats;
static void on_rx(struct ieee80211_hw *hw, struct sk_buff *skb) { (void)hw; nw_sta_rx(skb); }
static void on_scan_done(struct ieee80211_hw *hw, bool aborted) { (void)hw; nw_sta_scan_done(aborted); }
static void on_lost(void) { nw_sta_link_lost(); }
static struct ieee80211_hw *g_hw;
static void on_registered(struct ieee80211_hw *hw) { g_hw = hw; nw_sta_ready(hw); }
static const struct nw_wifi_hooks hooks = { .registered = on_registered, .rx = on_rx, .scan_done = on_scan_done, .beacon_loss = on_lost };

/* The first time the MHI core reports the device's RAM dump state, the boot interface's registers say where the boot stopped. */
static int has_text(const char *s, const char *w) {
  for (; *s; s++) { const char *a = s, *b = w; while (*a && *b && *a == *b) { a++; b++; } if (!*b) return 1; }
  return 0; }
/* The first WMI command that times out: the copy engines' ring positions (host and device side) and the WMI credits are logged, then the device is
 * asked for its RAM dump, which shows where the firmware stands. */
static int g_wmi_stuck;
static void ring_state(struct ath12k_base *ab, int p) {
  struct ath12k_ce_pipe *pipe = &ab->ce.ce_pipe[p];
  if (pipe->src_ring) {
    struct hal_srng *s = &ab->hal.srng_list[pipe->src_ring->hal_ring_id];
    lx_log(3, "stuck: ce%d src sw %u write %u hp %u reap %u cached-tp %u tp %u", p, pipe->src_ring->sw_index, pipe->src_ring->write_index,
           s->u.src_ring.hp, s->u.src_ring.reap_hp, s->u.src_ring.cached_tp, s->u.src_ring.tp_addr ? *(volatile u32 *)s->u.src_ring.tp_addr : 0xffffffffu);
  }
  if (pipe->dest_ring) {
    struct hal_srng *s = &ab->hal.srng_list[pipe->dest_ring->hal_ring_id];
    lx_log(3, "stuck: ce%d dst sw %u write %u tp %u cached-hp %u hp %u needed %u", p, pipe->dest_ring->sw_index, pipe->dest_ring->write_index,
           s->u.dst_ring.tp, s->u.dst_ring.cached_hp, s->u.dst_ring.hp_addr ? *s->u.dst_ring.hp_addr : 0xffffffffu, pipe->rx_buf_needed);
  }
}
static void wmi_stuck(void) {
  if (g_wmi_stuck != 1 || !g_hw) return;
  g_wmi_stuck = 2;
  struct ath12k *ar = ath12k_ah_to_ar(g_hw->priv, 0); struct ath12k_base *ab = ar->ab;
  for (int p = 1; p <= 4; p++) ring_state(ab, p);
  lx_log(3, "stuck: wmi credits %d, mhi ee %d state %d", ab->htc.endpoint[ATH12K_HTC_EP_2].tx_credits, ath12k_pci_priv(ab)->mhi_ctrl->ee,
         ath12k_pci_priv(ab)->mhi_ctrl->dev_state);
  lx_log(3, "stuck: asking for the RAM dump: %d", mhi_force_rddm_mode(ath12k_pci_priv(ab)->mhi_ctrl));
}
static void log_tap(int level, const char *line) {
  static int done; (void)level;
  if (!g_wmi_stuck && has_text(line, "wmi command") && has_text(line, "timeout")) g_wmi_stuck = 1;
  if (done || !has_text(line, "MHI_CB_EE_RDDM") || !nw_board || !nw_board->bar) return;
  done = 1;
  const volatile u8 *m = nw_board->bar; u32 bhi = readl(m + 0x28);
  if (bhi >= nw_board->bar_len) bhi = 0x100;
  lx_log(3, "rddm: mhistatus %08x mhictrl %08x ee %08x bhi-status %08x err %08x dbg %08x %08x %08x",
         readl(m + 0x48), readl(m + 0x38), readl(m + bhi + 0x28), readl(m + bhi + 0x2c), readl(m + bhi + 0x30), readl(m + bhi + 0x34),
         readl(m + bhi + 0x38), readl(m + bhi + 0x3c)); }

/* The address of a radio whose firmware reports none: the board's file wlan_mac.bin (text, the address as twelve hex digits after the
 * last '='), else a locally administered address made up once. */
static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
void nw_board_mac(u8 *a) {
  static u8 made[6]; static int have;
  const u8 *d; size_t n;
  if (!have && lx_plat->fw_get && !lx_plat->fw_get("wlan_mac.bin", &d, &n)) {
    size_t s = 0; for (size_t i = 0; i < n; i++) if (d[i] == '=') s = i + 1;
    u8 m[6]; size_t k = 0;
    for (size_t i = s; i < n && k < 12; i++) { int v = hexval((char)d[i]); if (v < 0) { if (k) break; continue; } m[k / 2] = (u8)(k & 1 ? m[k / 2] << 4 | v : v); k++; }
    if (k == 12 && is_valid_ether_addr(m)) { memcpy(made, m, 6); have = 1; lx_log(6, "wifi: address from wlan_mac.bin"); }
  }
  if (!have) {
    for (int i = 0; i < 6; i++) made[i] = (u8)(lx_random_u32() ^ lx_now_ms() >> (i * 3));
    made[0] = (made[0] & 0xfe) | 0x02; have = 1; lx_log(4, "wifi: the firmware and the board give no address: a made-up one is used");
  }
  memcpy(a, made, 6); }

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
int nw_wifi_step(void) { irq_poll(); int r = lx_pump(); nw_sta_run(); wmi_stuck(); return r; }
void nw_wifi_stop(void) { ath12k_wifi7_pci_exit(); }
