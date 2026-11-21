/* Run the ath11k glue's link state and transmit counters against the driver's own peer table and station layout, with the original
 * cfg80211 rate calculation; the peer is found through the driver's address table as on the device. */
#include "lx_pci.h"
#include "lx_plat.h"
#include <net/mac80211.h>
#include "nw_abi.h"
#include "mac80211/ieee80211_i.h"
#include "core.h"
#include "peer.h"
int printf(const char *, ...);
void abort(void);
void *calloc(size_t, size_t);
#define check(c) do { if (!(c)) { printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); abort(); } } while (0)

void nw_wifi_hw_ready(struct ieee80211_hw *hw);
void nw_wifi_link_state(char *text, int size);
void nw_wifi_tx_reasons(char *text, int size);

static struct nw_wifi_status status;
static unsigned rate_updates, signal_updates, last_rate; static int last_signal;
void nw_wifi_status_get(struct nw_wifi_status *s) { *s = status; }
void nw_mainline_rate_update(const u8 *bssid, unsigned rate) { check(!memcmp(bssid, status.bssid, 6)); rate_updates++; last_rate = rate; status.tx_rate_100kbps = rate; }
void nw_mainline_signal_update(const u8 *bssid, int signal) { check(!memcmp(bssid, status.bssid, 6)); signal_updates++; last_signal = signal; status.signal_dbm = signal; }
void lx_log(int level, const char *fmt, ...) { (void)level; (void)fmt; }
unsigned int ath11k_debug_mask;
/* the runtime the driver's peer table uses */
void free(void *);
void *lx_alloc(size_t n, int zero) { (void)zero; return calloc(1, n); }
void lx_free(const void *p) { free((void *)p); }
void lx_mutex_lock(struct mutex *m) { check(!m->held); m->held = 1; }
void lx_mutex_unlock(struct mutex *m) { check(m->held); m->held = 0; }
u64 lx_now_ms(void) { return 0; }
int lx_pump(void) { return 0; }
void lx_idle(unsigned int ms) { (void)ms; }

int main(void) {
  static const u8 bssid[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
  struct ath11k_base *ab = calloc(1, sizeof(*ab)); struct ath11k *ar = calloc(1, sizeof(*ar));
  struct ieee80211_hw *hw = calloc(1, sizeof(*hw)); hw->priv = ar; ar->ab = ab;
  spin_lock_init(&ab->base_lock); mutex_init(&ab->tbl_mtx_lock); INIT_LIST_HEAD(&ab->peers); check(!ath11k_peer_rhash_tbl_init(ab));
  struct sta_info *sta = calloc(1, sizeof(*sta) + sizeof(struct ath11k_sta));
  struct ath11k_sta *arsta = ath11k_sta_to_arsta(&sta->sta);
  struct ath11k_peer *peer = calloc(1, sizeof(*peer)); memcpy(peer->addr, bssid, 6); peer->sta = &sta->sta;
  char text[160];

  /* nothing before the hardware is registered or while not joined */
  nw_wifi_link_state(text, sizeof text); check(!text[0]);
  nw_wifi_tx_reasons(text, sizeof text); check(!text[0]);
  nw_wifi_hw_ready(hw);
  nw_wifi_link_state(text, sizeof text); check(!text[0] && !rate_updates && !signal_updates);

  /* joined, but the access point has no peer yet: no update */
  status.state = NW_STA_UP; memcpy(status.bssid, bssid, 6); status.freq_mhz = 5180;
  nw_wifi_link_state(text, sizeof text); check(text[0] && !rate_updates && !signal_updates);

  /* peer without a completion or a frame carrying a signal: no update */
  list_add(&peer->list, &ab->peers);
  check(!rhashtable_insert_fast(ab->rhead_peer_addr, &peer->rhash_addr, ab->rhash_peer_addr_param));
  nw_wifi_link_state(text, sizeof text); check(!rate_updates && !signal_updates);

  /* only the last signal so far */
  sta->deflink.rx_stats.last_signal = -61;
  nw_wifi_link_state(text, sizeof text); check(signal_updates == 1 && last_signal == -61 && !rate_updates);

  /* the average wins over the last signal; VHT MCS 9, 2 streams, 80 MHz, short guard interval is 866.7 Mbps */
  ewma_signal_init(&sta->deflink.rx_stats_avg.signal);
  for (int i = 0; i < 4; i++) ewma_signal_add(&sta->deflink.rx_stats_avg.signal, 55);
  arsta->txrate.flags = RATE_INFO_FLAGS_VHT_MCS | RATE_INFO_FLAGS_SHORT_GI; arsta->txrate.mcs = 9; arsta->txrate.nss = 2; arsta->txrate.bw = RATE_INFO_BW_80;
  nw_wifi_link_state(text, sizeof text);
  check(last_signal == -55 && last_rate == 8667 && rate_updates == 1);
  printf("%s\n", text);
  check(strstr(text, "freq 5180 rssi -55 (last -61) tx 866.7 Mbps"));

  /* legacy 54 Mbps */
  memset(&arsta->txrate, 0, sizeof arsta->txrate); arsta->txrate.legacy = 540;
  nw_wifi_link_state(text, sizeof text); check(last_rate == 540 && rate_updates == 2);

  /* another access point's address finds no peer */
  status.bssid[5] ^= 1;
  nw_wifi_link_state(text, sizeof text); check(rate_updates == 2);

  ab->soc_stats.tx_err.desc_na[0] = 3; ab->soc_stats.tx_err.desc_na[2] = 1; atomic_set(&ab->soc_stats.tx_err.misc_fail, 2);
  nw_wifi_tx_reasons(text, sizeof text); printf("%s\n", text);
  check(!strcmp(text, "no desc 3 0 1 other 2"));
  char small[8]; nw_wifi_tx_reasons(small, sizeof small); check(strlen(small) < sizeof small);
  printf("PASS ath11k glue: link state and transmit counters\n");
  return 0;
}
