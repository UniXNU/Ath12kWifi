/* Start the original cfg80211/mac80211 stack and the board's ath11k transport. Diagnostics that read the driver's internals (rings, firmware
 * statistics, RAM dump) are not carried over from the ath12k version. */
#include "lx_pci.h"
#include "lx_plat.h"
#include <net/mac80211.h>
#include "nw_mhi.h"
#include "nw_qrtr.h"
#include "nw_mainline.h"
#include "nw_wifi.h"
#include "nw_board.h"
#include "nw_events.h"
#include "nw_control_endpoint.h"
#include <linux/mhi.h>
#include "mac80211/ieee80211_i.h"
#include "core.h"
#include "peer.h"

int ath11k_pci_init(void);
void lx_exit_ath11k_pci_exit(void);
int mhi_init_hook(void);
extern unsigned int ath11k_debug_mask;

struct nw_wifi_stats nw_wifi_stats;
static struct ieee80211_hw *g_hw;
void nw_wifi_hw_ready(struct ieee80211_hw *hw) { g_hw = hw; }
int lx_init_cfg80211_init(void);
int lx_init_ieee80211_init(void);
void lx_exit_cfg80211_exit(void);
void lx_exit_ieee80211_exit(void);
static bool cfg_started, mac_started, pci_started, mhi_started, qrtr_started;
extern const struct bus_type mhi_bus_type;

/* ath11k keeps no counts of transmit completions by reason: these are the frames it could not hand to the hardware, for want of a descriptor
 * on each transmit ring and for any other reason. */
void nw_wifi_tx_reasons(char *b, int n) {
  b[0] = 0; if (!g_hw) return;
  struct ath11k_base *ab = ((struct ath11k *)g_hw->priv)->ab; struct ath11k_soc_dp_tx_err_stats *e = &ab->soc_stats.tx_err; int o = 0;
  o += snprintf(b + o, n - o, "no desc"); for (int i = 0; i < DP_TCL_NUM_RING_MAX && o < n; i++) o += snprintf(b + o, n - o, " %u", e->desc_na[i]);
  if (o < n) snprintf(b + o, n - o, " other %d", atomic_read(&e->misc_fail)); }
/* The rate is the one ath11k cached at the last transmit completion (QCA6390 and WCN6855 update it at every completion). ath11k gives
 * received data frames no signal; the signal is mac80211's average over the frames from the access point that carry one, the management
 * frames the firmware passes up (beacons among them), already in dBm. */
void nw_wifi_link_state(char *text, int size) {
  struct nw_wifi_status state; nw_wifi_status_get(&state);
  text[0] = 0;
  if (!g_hw || state.state != NW_STA_UP) return;
  struct ath11k *ar = g_hw->priv; struct ath11k_base *ab = ar->ab;
  struct rate_info txrate = {}; int signal = 0, last = 0;
  spin_lock_bh(&ab->base_lock);
  struct ath11k_peer *peer = ath11k_peer_find_by_addr(ab, state.bssid);
  if (peer && peer->sta) {
    txrate = ath11k_sta_to_arsta(peer->sta)->txrate;
    struct sta_info *sta = container_of(peer->sta, struct sta_info, sta);
    signal = -(int)ewma_signal_read(&sta->deflink.rx_stats_avg.signal); last = sta->deflink.rx_stats.last_signal;
  }
  spin_unlock_bh(&ab->base_lock);
  if (!signal) signal = last;
  u32 rate = txrate.legacy || txrate.nss ? cfg80211_calculate_bitrate(&txrate) : 0;
  if (rate) nw_mainline_rate_update(state.bssid, rate);
  if (signal) nw_mainline_signal_update(state.bssid, signal);
  struct nw_wifi_status updated; nw_wifi_status_get(&updated);
  snprintf(text, size, "freq %u rssi %d (last %d) tx %u.%u Mbps flags %x mcs %u nss %u bw-code %u gi %u",
           state.freq_mhz, updated.signal_dbm, last, rate / 10, rate % 10, txrate.flags, txrate.mcs, txrate.nss, txrate.bw, txrate.he_gi);
}
void nw_wifi_irq_mode(int delivered) { lx_irq_polling(!delivered); }
void nw_wifi_poll(void) { nw_mainline_poll(); nw_wifi_control_poll(); }
void nw_wifi_irq_pending(uint32_t vectors) {
  if (!nw_board) return;
  while (vectors) {
    unsigned bit = __builtin_ctz(vectors); vectors &= vectors - 1;
    lx_irq_raise(nw_board->irq_base + bit);
  }
}
unsigned nw_wifi_wait_ms(unsigned maximum) {
  return nw_mainline_pending() || nw_wifi_control_pending() ? 0 : lx_next_wait_ms(maximum);
}
void nw_wifi_set_platform(const struct lx_platform *p) { lx_plat = p; }
int nw_board_mac_address(uint8_t *a) {
  static const uint8_t zero[6];
  if (!nw_board || !memcmp(nw_board->mac, zero, sizeof(zero))) return -ENOENT;
  memcpy(a, nw_board->mac, sizeof(nw_board->mac));
  return 0;
}
int nw_wifi_start(const struct lx_platform *p, const struct nw_board *b) {
  lx_plat = p; nw_board = b; ath11k_debug_mask = 0;
  nw_wifi_buffer_pool_configure(1024 * 1024);
  lx_root_init(); nw_qrtr_init();
  int r = nw_mainline_init(); if (r) goto fail;
  r = lx_init_cfg80211_init(); if (r) goto fail;
  cfg_started = true;
  r = lx_init_ieee80211_init(); if (r) goto fail;
  mac_started = true;
  r = mhi_init_hook(); if (r) goto fail;
  mhi_started = true;
  r = nw_qrtr_mhi_register(); if (r) goto fail;
  qrtr_started = true;
  nw_wifi_stats.stage = 1;
  r = ath11k_pci_init();
  if (r) goto fail;
  pci_started = true; nw_wifi_stats.stage = 2; return 0;
fail:
  nw_wifi_stats.last_err = r; nw_wifi_stop(); lx_log(3, "wifi: driver start failed: %d", r); return r;
}
int nw_wifi_step(void) {
  static unsigned last_frames; nw_wifi_control_poll(); lx_pump(); nw_mainline_run();
  static u64 next_signal;
  if (g_hw && lx_now_ms() >= next_signal) { next_signal = lx_now_ms() + 1000; char link[128]; nw_wifi_link_state(link, sizeof(link)); }
  const unsigned f = nw_wifi_stats.frames; const int moved = f != last_frames; last_frames = f;
  return moved || nw_mainline_pending() || nw_wifi_control_pending() || lx_next_wait_ms(1000) == 0; }
void nw_wifi_stop(void) {
  nw_mainline_shutdown(); nw_wifi_control_shutdown();
  if (pci_started) { lx_exit_ath11k_pci_exit(); pci_started = false; }
  if (qrtr_started) { nw_qrtr_mhi_unregister(); qrtr_started = false; }
  if (mhi_started) { bus_unregister(&mhi_bus_type); mhi_started = false; }
  if (mac_started) { lx_exit_ieee80211_exit(); mac_started = false; }
  if (cfg_started) { lx_exit_cfg80211_exit(); cfg_started = false; }
  g_hw = NULL; nw_wifi_buffer_pool_configure(0);
}
