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
#include "nw_board.h"

int ath12k_wifi7_pci_init(void);
void ath12k_wifi7_pci_exit(void);
int mhi_init_hook(void);
extern unsigned int ath12k_debug_mask;

struct nw_wifi_stats nw_wifi_stats;
static struct ieee80211_vif *g_vif;
static struct delayed_work g_scan_work;
static int g_scanning;
#define SCAN_PERIOD_MS 8000

struct seen { u8 bssid[6]; };
static struct seen g_seen[64]; static int g_nseen;

static void log_beacon(struct sk_buff *skb) {
  struct ieee80211_rx_status *st = IEEE80211_SKB_RXCB(skb);
  struct ieee80211_mgmt *m = (void *)skb->data;
  u16 fc = le16_to_cpu(m->frame_control);
  int hdr = 24 + 12;                                     /* header + timestamp, interval, capabilities */
  if ((fc & 0xfc) != 0x80 && (fc & 0xfc) != 0x50) return;   /* beacon or probe response */
  if (skb->len < hdr) return;
  nw_wifi_stats.beacons++;
  for (int i = 0; i < g_nseen; i++) if (!memcmp(g_seen[i].bssid, m->bssid, 6)) return;
  if (g_nseen < 64) memcpy(g_seen[g_nseen++].bssid, m->bssid, 6);
  nw_wifi_stats.bss_seen = g_nseen;
  const u8 *ie = skb->data + hdr; unsigned len = skb->len - hdr;
  const struct element *ssid = cfg80211_find_elem_match(WLAN_EID_SSID, ie, len, 0, 0, 0);
  char name[33] = ""; if (ssid && ssid->datalen <= 32) { memcpy(name, ssid->data, ssid->datalen); name[ssid->datalen] = 0; }
  lx_log(6, "wifi: bss %02x:%02x:%02x:%02x:%02x:%02x freq %u signal %d ssid \"%s\"", m->bssid[0], m->bssid[1], m->bssid[2], m->bssid[3], m->bssid[4], m->bssid[5], st->freq, st->signal, name);
}
static void on_rx(struct ieee80211_hw *hw, struct sk_buff *skb) { (void)hw; nw_wifi_stats.frames++; if (skb->len >= 24) log_beacon(skb); }

static void start_scan(struct work_struct *w);
static void on_scan_done(struct ieee80211_hw *hw, bool aborted) {
  (void)hw; g_scanning = 0; nw_wifi_stats.scans++; nw_wifi_stats.stage = 6;
  lx_log(6, "wifi: scan %u finished%s, %u beacons, %u networks", nw_wifi_stats.scans, aborted ? " (aborted)" : "", nw_wifi_stats.beacons, nw_wifi_stats.bss_seen);
  lx_queue_delayed(&g_scan_work, SCAN_PERIOD_MS); }

static void start_scan(struct work_struct *w) {
  (void)w; struct ieee80211_hw *hw = nw_wifi_hw(); const struct ieee80211_ops *ops = nw_wifi_ops();
  if (!hw || !g_vif || g_scanning) return;
  int n = 0; for (int b = 0; b < NUM_NL80211_BANDS; b++) if (hw->wiphy->bands[b]) n += hw->wiphy->bands[b]->n_channels;
  struct ieee80211_scan_request *rq = lx_alloc(sizeof *rq + sizeof(struct ieee80211_channel *) * n, 1); if (!rq) return;
  int k = 0;
  for (int b = 0; b < NUM_NL80211_BANDS; b++) { struct ieee80211_supported_band *sb = hw->wiphy->bands[b]; if (!sb) continue;
    for (int i = 0; i < sb->n_channels; i++) if (!(sb->channels[i].flags & IEEE80211_CHAN_DISABLED)) rq->req.channels[k++] = &sb->channels[i]; }
  rq->req.n_channels = k;
  rq->req.wiphy = hw->wiphy; rq->req.n_ssids = 0; rq->req.flags = 0;
  g_scanning = 1; nw_wifi_stats.stage = 5;
  lx_log(6, "wifi: scan starts on %d channels", k);
  int r = ops->hw_scan(hw, g_vif, rq);
  if (r) { lx_log(3, "wifi: scan request failed: %d", r); nw_wifi_stats.last_err = r; g_scanning = 0; lx_queue_delayed(&g_scan_work, SCAN_PERIOD_MS); }
  lx_free(rq); }

static void on_registered(struct ieee80211_hw *hw) {
  const struct ieee80211_ops *ops = nw_wifi_ops(); int r;
  nw_wifi_stats.stage = 3;
  r = ops->start(hw); if (r) { lx_log(3, "wifi: start failed: %d", r); nw_wifi_stats.last_err = r; return; }
  g_vif = lx_alloc(sizeof *g_vif + hw->vif_data_size + 64, 1); if (!g_vif) return;
  g_vif->type = NL80211_IFTYPE_STATION; g_vif->bss_conf.vif = g_vif;
  memcpy(g_vif->addr, hw->wiphy->perm_addr, 6);
  r = ops->add_interface(hw, g_vif); if (r) { lx_log(3, "wifi: add interface failed: %d", r); nw_wifi_stats.last_err = r; return; }
  nw_wifi_vif_add(g_vif); nw_wifi_stats.stage = 4;
  INIT_DELAYED_WORK(&g_scan_work, start_scan); lx_queue_delayed(&g_scan_work, 100); }
static const struct nw_wifi_hooks hooks = { .registered = on_registered, .rx = on_rx, .scan_done = on_scan_done };

void lx_irq_raise_all(void);
static void irq_poll(void) { lx_irq_raise_all(); }
int nw_wifi_start(const struct lx_platform *p, const struct nw_board *b) {
  lx_plat = p; nw_board = b; ath12k_debug_mask = 0xffffffffu & ~0x2000u;
  lx_root_init(); nw_qrtr_init(); nw_wifi_set_hooks(&hooks);
  int r = mhi_init_hook(); if (r) return r;
  r = nw_qrtr_mhi_register(); if (r) return r;
  nw_wifi_stats.stage = 1;
  r = ath12k_wifi7_pci_init();
  if (r) { nw_wifi_stats.last_err = r; lx_log(3, "wifi: driver start failed: %d", r); return r; }
  nw_wifi_stats.stage = 2; return 0; }
int nw_wifi_step(void) { irq_poll(); return lx_pump(); }
void nw_wifi_stop(void) { ath12k_wifi7_pci_exit(); }
