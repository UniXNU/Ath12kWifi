/* Station behaviour on top of the driver's mac80211 operations: scan results, authentication, association, the WPA2-Personal four-way
 * handshake, key installation and the data path between 802.11 and Ethernet frames. It plays the part the wireless stack's client code
 * plays for a driver, in the order that driver expects: channel context, interface, station entry, frames, state changes, keys. */
#include "lx_pci.h"
#include "lx_plat.h"
#include <net/mac80211.h>
#include "nw_abi.h"
#include "nw_crypto.h"
#include "nw_mac80211.h"
#include "nw_sta.h"

#define MAX_BSS 48
#define IE_MAX 384
#define EAPOL_RETRY_MS 1500
#define STEP_TIMEOUT_MS 300

static u8 OUI_RSN[3] = { 0x00, 0x0f, 0xac };

/* ---- the lock that protects what board threads touch: requests, the transmit queue, the scan list ---- */
static volatile int g_lock;
static void lock(void) { while (__atomic_exchange_n(&g_lock, 1, __ATOMIC_ACQUIRE)) { } }
static void unlock(void) { __atomic_store_n(&g_lock, 0, __ATOMIC_RELEASE); }

struct bss { u8 bssid[6]; u8 ssid_len; u8 ssid[32]; u32 freq; s8 signal; u16 caps, interval; u64 seen; u16 ie_len; u8 ie[IE_MAX]; };
static struct bss g_bss[MAX_BSS]; static int g_nbss;

static u8 g_no_bssid[6];   /* the driver compares received frames with the interface's access point address, so it is never a null pointer */
static struct ieee80211_hw *g_hw; static const struct ieee80211_ops *g_ops; static struct ieee80211_vif *g_vif;
static struct nw_wifi_events g_ev;

enum { REQ_NONE, REQ_SCAN, REQ_CONNECT, REQ_DISCONNECT };
static struct { int kind; u8 ssid[32]; u8 ssid_len; u8 bssid[6]; int has_bssid; char pass[65]; int pass_len; int has_pass; } g_req;

struct txq_item { struct txq_item *next; u16 len; u8 data[]; };
static struct txq_item *g_txq_head, *g_txq_tail; static unsigned g_txq_n;

/* ---- the connection ---- */
static struct {
  int state, result; struct bss ap; u8 ssid[32]; u8 ssid_len;
  struct ieee80211_chanctx_conf *ctx; struct ieee80211_sta *sta; int sta_state; int chanctx_up;
  int secure; u8 pmk[32]; u8 ptk[48]; u8 anonce[32], snonce[32]; u64 replay; int have_replay; int ptk_ready; int hs_stage;
  struct ieee80211_key_conf *ptk_key, *gtk_key; u16 seq; u8 gtk_id;
  u64 started; u64 last_tx; int tries; int rsn_ok; u16 aid;
  /* message 4 waits for its acknowledgement before the keys go in: the access point may repeat message 3 in the clear meanwhile */
  u8 gtk[32]; int gtk_len, gtk_idx; int m4_done; u64 m4_at;
} C;
static struct delayed_work g_timer; static struct delayed_work g_scan_timer;
static int g_scan_running; static int g_connect_waits; static int g_scan_directed; static u8 g_scan_ssid[32]; static u8 g_scan_ssid_len;

static void tx_frame(struct sk_buff *skb);
static void connect_done(int res);
static void teardown(int notify_lost, int reason);

/* ---- scan list ---- */
static void note_bss(struct sk_buff *skb) {
  struct ieee80211_rx_status *st = IEEE80211_SKB_RXCB(skb); struct ieee80211_mgmt *m = (void *)skb->data;
  u16 fc = le16_to_cpu(m->frame_control); unsigned hdr = 24 + 12;
  if ((fc & 0xfc) != 0x80 && (fc & 0xfc) != 0x50) return;
  if (skb->len < hdr) return;
  const u8 *ie = skb->data + hdr; unsigned len = skb->len - hdr; if (len > IE_MAX) len = IE_MAX;
  const struct element *ssid = cfg80211_find_elem_match(WLAN_EID_SSID, ie, len, 0, 0, 0);
  struct bss b; memset(&b, 0, sizeof b); memcpy(b.bssid, m->bssid, 6);
  if (ssid && ssid->datalen <= 32) { b.ssid_len = ssid->datalen; memcpy(b.ssid, ssid->data, ssid->datalen); }
  b.freq = st->freq; b.signal = st->signal; b.caps = le16_to_cpu(m->u.beacon.capab_info); b.interval = le16_to_cpu(m->u.beacon.beacon_int);
  b.seen = lx_now_ms(); b.ie_len = len; memcpy(b.ie, ie, len);
  lock();
  int at = -1; for (int i = 0; i < g_nbss; i++) if (!memcmp(g_bss[i].bssid, b.bssid, 6) && g_bss[i].freq == b.freq) { at = i; break; }
  if (at < 0) { if (g_nbss < MAX_BSS) at = g_nbss++; else { u64 old = ~0ull; for (int i = 0; i < MAX_BSS; i++) if (g_bss[i].seen < old) { old = g_bss[i].seen; at = i; } } }
  /* a probe response carries the name even when the beacon hides it: keep a name once known */
  if (!b.ssid_len && at < g_nbss && !memcmp(g_bss[at].bssid, b.bssid, 6) && g_bss[at].ssid_len) { b.ssid_len = g_bss[at].ssid_len; memcpy(b.ssid, g_bss[at].ssid, 32); }
  g_bss[at] = b; nw_wifi_stats.bss_seen = g_nbss;
  unlock(); }
int nw_wifi_bss_count(void) { return g_nbss; }
int nw_wifi_bss_get(int i, struct nw_bss_info *o) {
  int r = -1; lock();
  if (i >= 0 && i < g_nbss) { struct bss *b = &g_bss[i]; memcpy(o->bssid, b->bssid, 6); o->ssid_len = b->ssid_len; memcpy(o->ssid, b->ssid, 32);
    o->freq_mhz = b->freq; o->signal_dbm = b->signal; o->caps = b->caps; o->beacon_int = b->interval; u64 now = lx_now_ms(); o->age_ms = now > b->seen ? (u32)(now - b->seen) : 0;
    o->ie_len = b->ie_len; memcpy(o->ie, b->ie, b->ie_len); r = 0; }
  unlock(); return r; }

/* ---- scanning ---- */
static void do_scan(const u8 *ssid, u8 len) {
  if (!g_hw || !g_vif || g_scan_running || g_connect_waits || (C.state >= NW_STA_AUTH && C.state != NW_STA_UP)) return;
  int n = 0; for (int b = 0; b < NUM_NL80211_BANDS; b++) if (g_hw->wiphy->bands[b]) n += g_hw->wiphy->bands[b]->n_channels;
  struct ieee80211_scan_request *rq = lx_alloc(sizeof *rq + sizeof(struct ieee80211_channel *) * n + 2 * sizeof(struct cfg80211_ssid), 1); if (!rq) return;
  struct cfg80211_ssid *ss = (struct cfg80211_ssid *)((u8 *)rq + sizeof *rq + sizeof(struct ieee80211_channel *) * n);
  int k = 0;
  for (int b = 0; b < NUM_NL80211_BANDS; b++) { struct ieee80211_supported_band *sb = g_hw->wiphy->bands[b]; if (!sb) continue;
    for (int i = 0; i < sb->n_channels; i++) if (!(sb->channels[i].flags & IEEE80211_CHAN_DISABLED)) rq->req.channels[k++] = &sb->channels[i]; }
  rq->req.n_channels = k; rq->req.wiphy = g_hw->wiphy; rq->req.flags = 0;
  rq->req.n_ssids = 0; ss[rq->req.n_ssids].ssid_len = 0; rq->req.n_ssids++;      /* the wildcard: every network answers */
  if (len) { memcpy(ss[1].ssid, ssid, len); ss[1].ssid_len = len; rq->req.n_ssids++; }
  rq->req.ssids = ss;
  g_scan_running = 1; nw_wifi_stats.stage = 5;
  lx_log(6, "wifi: scan starts on %d channels", k);
  int r = g_ops->hw_scan(g_hw, g_vif, rq);
  if (r) { lx_log(3, "wifi: scan request failed: %d", r); nw_wifi_stats.last_err = r; g_scan_running = 0; if (g_ev.scan_done) g_ev.scan_done(); }
  lx_free(rq); }
void nw_sta_scan_done(bool aborted) {
  g_scan_running = 0; nw_wifi_stats.scans++; nw_wifi_stats.stage = 6;
  lx_log(6, "wifi: scan %u finished%s, %u networks", nw_wifi_stats.scans, aborted ? " (aborted)" : "", nw_wifi_stats.bss_seen);
  if (C.state == NW_STA_SCANNING) C.state = NW_STA_IDLE;
  if (g_ev.scan_done) g_ev.scan_done(); }

/* ---- element helpers ---- */
static const u8 *find_ie(const u8 *ies, unsigned len, u8 id) { const struct element *e = cfg80211_find_elem_match(id, ies, len, 0, 0, 0); return e ? (const u8 *)e : 0; }
static const u8 *find_rsn(const u8 *ies, unsigned len) { return find_ie(ies, len, WLAN_EID_RSN); }

/* parses the access point's RSN element: returns 0 when it offers CCMP with a pre-shared key (and no mandatory management protection) */
static int rsn_check(const u8 *e) {
  if (!e) return -1;
  const u8 *p = e + 2, *end = e + 2 + e[1]; if (end - p < 2) return -1; p += 2;                         /* version */
  if (end - p < 4) return -1; p += 4;                                                                /* group cipher: any is accepted for receive */
  if (end - p < 2) return -1; unsigned n = p[0] | p[1] << 8; p += 2; int ccmp = 0;
  for (unsigned i = 0; i < n; i++) { if (end - p < 4) return -1; if (!memcmp(p, OUI_RSN, 3) && p[3] == 4) ccmp = 1; p += 4; }
  if (end - p < 2) return -1; n = p[0] | p[1] << 8; p += 2; int psk = 0;
  for (unsigned i = 0; i < n; i++) { if (end - p < 4) return -1; if (!memcmp(p, OUI_RSN, 3) && p[3] == 2) psk = 1; p += 4; }
  u16 caps = end - p >= 2 ? (u16)(p[0] | p[1] << 8) : 0;
  if (!ccmp || !psk) return -2;
  if (caps & 0x0040) return -2;                                                                      /* management frame protection required */
  return 0; }

/* ---- frames out ---- */
static struct sk_buff *new_frame(unsigned body) {
  struct sk_buff *skb = alloc_skb(64 + body + 32, 0); if (!skb) return 0;
  skb_reserve(skb, 32); return skb; }
static void mgmt_header(struct sk_buff *skb, u16 fc) {
  struct ieee80211_hdr *h = skb_put_zero(skb, 24); h->frame_control = cpu_to_le16(fc);
  memcpy(h->addr1, C.ap.bssid, 6); memcpy(h->addr2, g_vif->addr, 6); memcpy(h->addr3, C.ap.bssid, 6); h->seq_ctrl = cpu_to_le16(C.seq++ << 4); }
static void send_auth(void) {
  struct sk_buff *skb = new_frame(8); if (!skb) return;
  mgmt_header(skb, IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_AUTH);
  u8 *b = skb_put_zero(skb, 6); b[0] = 0; b[1] = 0; b[2] = 1; b[3] = 0; b[4] = 0; b[5] = 0;      /* open system, sequence 1, status 0 */
  tx_frame(skb); }
static int rates_2g[] = { 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c };
static int rates_5g[] = { 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c };
static void send_assoc(void) {
  struct sk_buff *skb = new_frame(256); if (!skb) return;
  mgmt_header(skb, IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ASSOC_REQ);
  u16 caps = WLAN_CAPABILITY_ESS | (C.secure ? WLAN_CAPABILITY_PRIVACY : 0) | WLAN_CAPABILITY_SHORT_SLOT_TIME;
  u8 *b = skb_put(skb, 4); b[0] = caps; b[1] = caps >> 8; b[2] = 10; b[3] = 0;                   /* listen interval 10 */
  u8 *e = skb_put(skb, 2 + C.ssid_len); e[0] = WLAN_EID_SSID; e[1] = C.ssid_len; memcpy(e + 2, C.ssid, C.ssid_len);
  int five = C.ap.freq >= 4900; const int *r = five ? rates_5g : rates_2g; int nr = five ? 8 : 12;
  int first = nr > 8 ? 8 : nr; e = skb_put(skb, 2 + first); e[0] = WLAN_EID_SUPP_RATES; e[1] = first; for (int i = 0; i < first; i++) e[2 + i] = r[i];
  if (nr > 8) { e = skb_put(skb, 2 + nr - 8); e[0] = WLAN_EID_EXT_SUPP_RATES; e[1] = nr - 8; for (int i = 8; i < nr; i++) e[2 + i - 8] = r[i]; }
  if (C.secure) {   /* RSN: version 1, group CCMP, pairwise CCMP, key management PSK, no capabilities */
    static const u8 rsn[] = { WLAN_EID_RSN, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0 };
    skb_put_data(skb, rsn, sizeof rsn); }
  tx_frame(skb); }

/* ---- chanctx, interface and station entry, in the order a driver of this kind expects ---- */
static struct ieee80211_channel *chan_for(u32 mhz) { return ieee80211_get_channel_khz(g_hw->wiphy, mhz * 1000); }
static int bring_up_channel(void) {
  struct ieee80211_channel *ch = chan_for(C.ap.freq); if (!ch) return -ENODEV;
  struct ieee80211_chanctx_conf *ctx = lx_alloc(sizeof *ctx + g_hw->chanctx_data_size + 16, 1); if (!ctx) return -ENOMEM;
  ctx->def.chan = ch; ctx->def.width = NL80211_CHAN_WIDTH_20; ctx->def.center_freq1 = ch->center_freq; ctx->def.center_freq2 = 0;
  ctx->min_def = ctx->def; ctx->ap = ctx->def; ctx->rx_chains_static = 1; ctx->rx_chains_dynamic = 1;
  int r = g_ops->add_chanctx(g_hw, ctx); if (r) { lx_free(ctx); return r; }
  C.ctx = ctx; rcu_assign_pointer(g_vif->bss_conf.chanctx_conf, ctx); nw_wifi_chanctx_set(ctx);
  g_vif->bss_conf.bssid = C.ap.bssid; memcpy(g_vif->cfg.ap_addr, C.ap.bssid, 6);
  g_vif->bss_conf.chanreq.oper = ctx->def; g_vif->bss_conf.txpower = ch->max_power; g_vif->bss_conf.txpower_type = NL80211_TX_POWER_AUTOMATIC; g_vif->bss_conf.beacon_int = C.ap.interval ? C.ap.interval : 100; g_vif->bss_conf.dtim_period = 1;
  g_vif->cfg.ssid_len = C.ssid_len; memcpy(g_vif->cfg.ssid, C.ssid, C.ssid_len);
  C.chanctx_up = 1;
  return 0; }
static u32 rate_mask(const u8 *ies, unsigned len, enum nl80211_band band) {
  struct ieee80211_supported_band *sb = g_hw->wiphy->bands[band]; u32 mask = 0; if (!sb) return 0;
  for (int pass = 0; pass < 2; pass++) { const u8 *e = find_ie(ies, len, pass ? WLAN_EID_EXT_SUPP_RATES : WLAN_EID_SUPP_RATES); if (!e) continue;
    for (int i = 0; i < e[1]; i++) { int rate = (e[2 + i] & 0x7f) * 5; for (int k = 0; k < sb->n_bitrates; k++) if (sb->bitrates[k].bitrate == rate) mask |= 1u << k; } }
  return mask; }
static int add_station(void) {
  struct ieee80211_sta *sta = lx_alloc(sizeof *sta + g_hw->sta_data_size + 16, 1); if (!sta) return -ENOMEM;
  memcpy(sta->addr, C.ap.bssid, 6); sta->deflink.sta = sta; memcpy(sta->deflink.addr, C.ap.bssid, 6); sta->deflink.link_id = 0;
  sta->link[0] = &sta->deflink; sta->max_rx_aggregation_subframes = 8; sta->deflink.rx_nss = 1; sta->deflink.bandwidth = IEEE80211_STA_RX_BW_20;
  sta->wme = true;
  enum nl80211_band band = C.ap.freq >= 5925 ? NL80211_BAND_6GHZ : C.ap.freq >= 4900 ? NL80211_BAND_5GHZ : NL80211_BAND_2GHZ;
  sta->deflink.supp_rates[band] = rate_mask(C.ap.ie, C.ap.ie_len, band);
  C.sta = sta; nw_wifi_sta_set(sta); int r = g_ops->sta_state(g_hw, g_vif, sta, IEEE80211_STA_NOTEXIST, IEEE80211_STA_NONE);
  if (r) { nw_wifi_sta_set(0); lx_free(sta); C.sta = 0; return r; }
  C.sta_state = IEEE80211_STA_NONE; return 0; }
static int set_sta_state(int to) {
  int r = g_ops->sta_state(g_hw, g_vif, C.sta, C.sta_state, to); if (r) lx_log(3, "wifi: station state %d -> %d failed: %d", C.sta_state, to, r); else C.sta_state = to; return r; }

/* ---- tx ---- */
static void tx_frame(struct sk_buff *skb) {
  struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb); memset(info, 0, sizeof *info);
  info->control.vif = g_vif;
  struct ieee80211_hdr *h = (void *)skb->data;
  struct ieee80211_tx_control ctl = { .sta = (C.sta && !is_multicast_ether_addr(h->addr1)) ? C.sta : 0 };
  C.last_tx = lx_now_ms(); g_ops->tx(g_hw, &ctl, skb); }
/* The interface hands Ethernet frames to the hardware, which makes the 802.11 frame and encrypts it with the installed key. */
static void tx_eth(const u8 *e, unsigned len) {
  struct sk_buff *skb = new_frame(len); if (!skb) return;
  skb_put_data(skb, e, len); skb->protocol = cpu_to_be16(e[12] << 8 | e[13]);
  struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb); memset(info, 0, sizeof *info);
  info->control.vif = g_vif; info->flags = IEEE80211_TX_CTL_HW_80211_ENCAP; info->control.hw_key = C.ptk_key;
  struct ieee80211_tx_control ctl = { .sta = is_multicast_ether_addr(e) ? 0 : C.sta };
  C.last_tx = lx_now_ms(); g_ops->tx(g_hw, &ctl, skb); }

/* ---- the access point's frames ---- */
static void to_eth(struct sk_buff *skb) {
  struct ieee80211_hdr *h = (void *)skb->data; unsigned hl = ieee80211_hdrlen(h->frame_control);
  struct ieee80211_rx_status *st = IEEE80211_SKB_RXCB(skb);
  if (ieee80211_has_protected(h->frame_control) && !(st->flag & RX_FLAG_IV_STRIPPED)) hl += 8;
  if (skb->len < hl + 8) return;
  const u8 *llc = skb->data + hl; if (llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 3) return;
  unsigned plen = skb->len - hl - 8; if (plen > 2000) return;
  static u8 eth[14 + 2000]; memcpy(eth, h->addr1, 6); memcpy(eth + 6, h->addr3, 6); memcpy(eth + 12, llc + 6, 2); memcpy(eth + 14, llc + 8, plen);
  if (eth[12] == 0x88 && eth[13] == 0x8e) return;   /* EAPOL belongs to the handshake */
  if (g_ev.rx) g_ev.rx(eth, 14 + plen); }

/* ---- the handshake ---- */
struct eapol_key { u8 ver, type, len[2]; u8 desc; u8 info[2]; u8 keylen[2]; u8 replay[8]; u8 nonce[32]; u8 iv[16]; u8 rsc[8]; u8 id[8]; u8 mic[16]; u8 datalen[2]; u8 data[]; } __attribute__((packed));
static u64 be64(const u8 *p) { u64 v = 0; for (int i = 0; i < 8; i++) v = v << 8 | p[i]; return v; }
static void put_be64(u8 *p, u64 v) { for (int i = 7; i >= 0; i--) { p[i] = v; v >>= 8; } }
static void make_nonce(u8 *out) {
  static u64 ctr; u8 in[64]; u64 t = lx_now_ms(); ctr++;
  memset(in, 0, sizeof in); memcpy(in, &t, 8); memcpy(in + 8, &ctr, 8); memcpy(in + 16, g_vif->addr, 6); memcpy(in + 22, C.ap.bssid, 6); memcpy(in + 28, C.anonce, 32);
  u8 h[20]; nw_sha1(in, 60, h); memcpy(out, h, 20); in[63] ^= 0x5a; nw_sha1(in, 64, h); memcpy(out + 20, h, 12); }
static void derive_ptk(void) {
  u8 data[76]; const u8 *a = g_vif->addr, *b = C.ap.bssid;
  const u8 *lo = memcmp(a, b, 6) < 0 ? a : b, *hi = lo == a ? b : a; memcpy(data, lo, 6); memcpy(data + 6, hi, 6);
  const u8 *nl = memcmp(C.anonce, C.snonce, 32) < 0 ? C.anonce : C.snonce, *nh = nl == C.anonce ? C.snonce : C.anonce; memcpy(data + 12, nl, 32); memcpy(data + 44, nh, 32);
  nw_prf(C.pmk, 32, "Pairwise key expansion", data, 76, C.ptk, 384); C.ptk_ready = 1; }
static void send_eapol(const struct eapol_key *k, unsigned total) {
  struct sk_buff *skb = new_frame(total + 64); if (!skb) return;
  struct ieee80211_hdr *h = skb_put_zero(skb, 26); h->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | IEEE80211_FCTL_TODS);
  memcpy(h->addr1, C.ap.bssid, 6); memcpy(h->addr2, g_vif->addr, 6); memcpy(h->addr3, C.ap.bssid, 6); h->seq_ctrl = cpu_to_le16(C.seq++ << 4);
  /* like mac80211's control port frames: the highest priority (voice, TID 7) */
  ((u8 *)h)[24] = 7; skb->priority = 7;
  static const u8 snap[8] = { 0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e }; skb_put_data(skb, snap, 8); skb_put_data(skb, k, total);
  skb->protocol = cpu_to_be16(ETH_P_PAE);   /* the driver sends the handshake as an 802.11 frame on an Ethernet interface */
  tx_frame(skb); }
void nw_wifi_htt_stats(int type);
static void sign(struct eapol_key *k, unsigned total) {
  u8 h[20]; memset(k->mic, 0, 16); nw_hmac_sha1(C.ptk, 16, (const u8 *)k, total, h); memcpy(k->mic, h, 16); }
static int install_key(int pairwise, int idx, const u8 *key, int len) {
  struct ieee80211_key_conf *kc = lx_alloc(sizeof *kc + 32, 1); if (!kc) return -ENOMEM;
  kc->cipher = WLAN_CIPHER_SUITE_CCMP; kc->keyidx = idx; kc->keylen = len; kc->icv_len = 8; kc->iv_len = 8; kc->hw_key_idx = 0xff; kc->link_id = -1;
  kc->flags = pairwise ? IEEE80211_KEY_FLAG_PAIRWISE : 0; memcpy(kc->key, key, len);
  int r = g_ops->set_key(g_hw, SET_KEY, g_vif, pairwise ? C.sta : 0, kc);
  if (r) { lx_log(3, "wifi: installing the %s key failed: %d", pairwise ? "pairwise" : "group", r); lx_free(kc); return r; }
  if (pairwise) { C.ptk_key = kc; } else { C.gtk_key = kc; }
  return 0; }
static void finish_authorized(void);
void nw_wifi_tx_reasons(char *b, int n);
static const char *tx_reasons(void) { static char b[160]; nw_wifi_tx_reasons(b, sizeof b); return b; }
static void install_keys(void) {
  if (install_key(1, 0, C.ptk + 32, 16)) { connect_done(NW_RES_FAILED); return; }
  if (C.gtk_len && install_key(0, C.gtk_idx, C.gtk, 16)) { connect_done(NW_RES_FAILED); return; }
  C.hs_stage = 4; finish_authorized(); }
/* From the completion of a sent handshake frame. */
void nw_sta_eapol_status(bool acked) {
  if (C.hs_stage < 3) return;
  lx_log(6, "wifi: handshake message 4 %s", acked ? "acknowledged" : "not acknowledged"); if (C.hs_stage == 3) C.m4_done = 1; }
static void finish_authorized(void) {
  if (set_sta_state(IEEE80211_STA_AUTHORIZED)) { connect_done(NW_RES_FAILED); return; }
  C.state = NW_STA_UP; nw_wifi_stats.stage = 8; lx_log(6, "wifi: connected"); connect_done(NW_RES_OK); }
static void handle_eapol(const u8 *p, unsigned len) {
  const struct eapol_key *k = (const void *)p;
  if (len < sizeof *k || k->type != 3 || (k->desc != 2 && k->desc != 254)) return;
  unsigned info = k->info[0] << 8 | k->info[1], dlen = k->datalen[0] << 8 | k->datalen[1];
  if (sizeof *k + dlen > len) return;
  if ((info & 7) != 2) { lx_log(4, "wifi: key descriptor version %u not handled", info & 7); return; }
  int pairwise = !!(info & 0x0008), ack = !!(info & 0x0080), mic = !!(info & 0x0100);
  unsigned total = sizeof *k + dlen; u8 buf[512]; if (total > sizeof buf) return;
  if (pairwise && ack && !mic) {   /* message 1: the access point's nonce */
    memcpy(C.anonce, k->nonce, 32); make_nonce(C.snonce); derive_ptk(); C.replay = be64(k->replay); C.have_replay = 1; C.hs_stage = 1;
    struct eapol_key *o = (void *)buf; memset(o, 0, sizeof *o + 22); o->ver = 2; o->type = 3; o->desc = 2;
    static const u8 rsn[] = { WLAN_EID_RSN, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0 };
    unsigned body = sizeof *o - 4 + sizeof rsn; o->len[0] = body >> 8; o->len[1] = body; o->info[0] = 0x01; o->info[1] = 0x0a; o->keylen[0] = 0;
    memcpy(o->replay, k->replay, 8); memcpy(o->nonce, C.snonce, 32); o->datalen[0] = 0; o->datalen[1] = sizeof rsn; memcpy(o->data, rsn, sizeof rsn);
    sign(o, sizeof *o + sizeof rsn); send_eapol(o, sizeof *o + sizeof rsn); lx_log(6, "wifi: handshake message 2 sent"); return; }
  if (!C.ptk_ready || !mic) return;
  memcpy(buf, p, total); struct eapol_key *c = (void *)buf; u8 want[16], h[20]; memset(c->mic, 0, 16); nw_hmac_sha1(C.ptk, 16, buf, total, h); memcpy(want, h, 16);
  if (memcmp(want, k->mic, 16)) { lx_log(4, "wifi: handshake MIC check failed (wrong passphrase?)"); if (C.state == NW_STA_KEYS && pairwise) { connect_done(NW_RES_BAD_KEY); } return; }
  u64 rc = be64(k->replay); if (C.have_replay && rc <= C.replay && !(pairwise && C.hs_stage == 1)) return; C.replay = rc;
  const u8 *kd = k->data; u8 plain[400]; unsigned pl = dlen;
  if (info & 0x1000) {   /* key data is wrapped with the KEK */
    if (dlen < 24 || dlen > sizeof plain + 8) return;
    if (nw_aes_unwrap(C.ptk + 16, k->data, dlen, plain)) { lx_log(4, "wifi: key data did not unwrap"); return; }
    kd = plain; pl = dlen - 8; }
  const u8 *gtk = 0; unsigned gtklen = 0; int gtkid = 0;
  for (unsigned i = 0; i + 2 <= pl;) { u8 t = kd[i], l = kd[i + 1]; if (i + 2 + l > pl) break;
    if (t == 0xdd && l >= 6 && !memcmp(kd + i + 2, OUI_RSN, 3) && kd[i + 5] == 1) { gtkid = kd[i + 6] & 3; gtk = kd + i + 8; gtklen = l - 6; }
    if (t == 0 && l == 0) break; i += 2 + l; }
  if (pairwise && ack) {   /* message 3: install the keys */
    if (memcmp(k->nonce, C.anonce, 32)) { lx_log(4, "wifi: handshake nonce changed"); return; }
    struct eapol_key *o = (void *)buf; memset(o, 0, sizeof *o); o->ver = 2; o->type = 3; o->desc = 2; unsigned body = sizeof *o - 4; o->len[0] = body >> 8; o->len[1] = body;
    o->info[0] = 0x03; o->info[1] = 0x0a; memcpy(o->replay, k->replay, 8); sign(o, sizeof *o);
    /* The keys go in once message 4 completed (the timer does it, at the latest after 300 ms). A repeated message 3 is answered the same way, with
     * its own replay counter. */
    int again = C.hs_stage >= 3;
    send_eapol(o, sizeof *o); lx_log(6, "wifi: handshake message 4 sent%s (tx acked %u, not acked %u, dropped %u; %s)", again ? " again" : "", nw_eapol_tx[0], nw_eapol_tx[1], nw_eapol_tx[2], tx_reasons());
    if (again) return;
    C.gtk_len = gtk && gtklen >= 16 ? 16 : 0; C.gtk_idx = gtkid; if (C.gtk_len) memcpy(C.gtk, gtk, 16);
    C.hs_stage = 3; C.m4_done = 0; C.m4_at = lx_now_ms(); return; }
  if (!pairwise && ack) {   /* group key update */
    if (gtk && gtklen >= 16) install_key(0, gtkid, gtk, 16);
    struct eapol_key *o = (void *)buf; memset(o, 0, sizeof *o); o->ver = 2; o->type = 3; o->desc = 2; unsigned body = sizeof *o - 4; o->len[0] = body >> 8; o->len[1] = body;
    o->info[0] = 0x03; o->info[1] = 0x02; memcpy(o->replay, k->replay, 8); sign(o, sizeof *o); send_eapol(o, sizeof *o); } }

/* ---- association results ---- */
static void on_mgmt(struct sk_buff *skb) {
  struct ieee80211_mgmt *m = (void *)skb->data; u16 fc = le16_to_cpu(m->frame_control);
  if (memcmp(m->sa, C.ap.bssid, 6)) return;
  if (C.state == NW_STA_AUTH && ieee80211_is_auth(m->frame_control) && skb->len >= 30) {
    u16 status = le16_to_cpu(m->u.auth.status_code), seq = le16_to_cpu(m->u.auth.auth_transaction);
    if (seq != 2) return;
    if (status) { lx_log(4, "wifi: authentication refused: %u", status); connect_done(NW_RES_REJECTED); return; }
    if (set_sta_state(IEEE80211_STA_AUTH)) { connect_done(NW_RES_FAILED); return; }
    C.state = NW_STA_ASSOC; C.tries = 0; C.started = lx_now_ms(); send_assoc(); return; }
  if (C.state == NW_STA_ASSOC && ieee80211_is_assoc_resp(m->frame_control) && skb->len >= 30) {
    u16 status = le16_to_cpu(m->u.assoc_resp.status_code), aid = le16_to_cpu(m->u.assoc_resp.aid) & 0x3fff;
    if (status) { lx_log(4, "wifi: association refused: %u", status); connect_done(NW_RES_REJECTED); return; }
    C.aid = aid; g_vif->cfg.aid = aid; g_vif->cfg.assoc = true; C.sta->aid = aid;
    enum nl80211_band band = C.ap.freq >= 5925 ? NL80211_BAND_6GHZ : C.ap.freq >= 4900 ? NL80211_BAND_5GHZ : NL80211_BAND_2GHZ;
    const u8 *e = find_ie(C.ap.ie, C.ap.ie_len, WLAN_EID_SUPP_RATES); struct ieee80211_supported_band *sb = g_hw->wiphy->bands[band];
    g_vif->bss_conf.basic_rates = 0; for (int i = 0; e && sb && i < e[1]; i++) if (e[2 + i] & 0x80) { int rate = (e[2 + i] & 0x7f) * 5; for (int k = 0; k < sb->n_bitrates; k++) if (sb->bitrates[k].bitrate == rate) g_vif->bss_conf.basic_rates |= 1u << k; }
    if (!g_vif->bss_conf.basic_rates) g_vif->bss_conf.basic_rates = 1;
    g_vif->bss_conf.assoc_capability = C.ap.caps; g_vif->bss_conf.use_short_slot = true;
    const u8 *tim = find_ie(C.ap.ie, C.ap.ie_len, WLAN_EID_TIM); if (tim && tim[1] >= 2 && tim[3]) g_vif->bss_conf.dtim_period = tim[3];
    if (set_sta_state(IEEE80211_STA_ASSOC)) { connect_done(NW_RES_FAILED); return; }
    g_ops->link_info_changed(g_hw, g_vif, &g_vif->bss_conf, BSS_CHANGED_BSSID | BSS_CHANGED_BASIC_RATES | BSS_CHANGED_BEACON_INT | BSS_CHANGED_ERP_SLOT);   /* the association itself is a change of the interface, below */
    g_ops->vif_cfg_changed(g_hw, g_vif, BSS_CHANGED_ASSOC | BSS_CHANGED_IDLE | BSS_CHANGED_SSID);
    C.started = lx_now_ms(); C.tries = 0;
    if (C.secure) { C.state = NW_STA_KEYS; lx_log(6, "wifi: associated, waiting for the key handshake"); }
    else finish_authorized();
    return; }
  if ((ieee80211_is_deauth(m->frame_control) || ieee80211_is_disassoc(m->frame_control)) && C.state >= NW_STA_AUTH) {
    u16 reason = le16_to_cpu(m->u.deauth.reason_code); lx_log(4, "wifi: access point ended the connection: reason %u (%s)", reason, tx_reasons()); nw_wifi_htt_stats(8);
    if (C.state == NW_STA_UP) { teardown(1, reason); } else connect_done(NW_RES_REJECTED); }
  (void)fc; }
void nw_sta_rx(struct sk_buff *skb) {
  { struct ieee80211_rx_status *rs = IEEE80211_SKB_RXCB(skb);
    if (rs->flag & RX_FLAG_8023) {   /* the hardware already made an Ethernet frame of it */
      nw_wifi_stats.frames++;
      if (skb->len >= 14 && !(skb->data[12] == 0x88 && skb->data[13] == 0x8e) && C.state >= NW_STA_KEYS && g_ev.rx) g_ev.rx(skb->data, skb->len);
      return; } }
  if (skb->len < 24) return; nw_wifi_stats.frames++;
  struct ieee80211_hdr *h = (void *)skb->data;
  if (ieee80211_is_beacon(h->frame_control) || ieee80211_is_probe_resp(h->frame_control)) { nw_wifi_stats.beacons++; static int n; if (n < 12) lx_log(6, "wifi: beacon %d: %u bytes", ++n, skb->len); note_bss(skb); return; }
  if (C.state < NW_STA_AUTH) return;
  if (ieee80211_is_mgmt(h->frame_control)) { on_mgmt(skb); return; }
  if (ieee80211_is_data(h->frame_control) && !memcmp(h->addr2, C.ap.bssid, 6)) {
    unsigned hl = ieee80211_hdrlen(h->frame_control); struct ieee80211_rx_status *st = IEEE80211_SKB_RXCB(skb);
    if (ieee80211_has_protected(h->frame_control) && !(st->flag & RX_FLAG_IV_STRIPPED)) hl += 8;
    if (skb->len >= hl + 8 && skb->data[hl + 6] == 0x88 && skb->data[hl + 7] == 0x8e && skb->data[hl] == 0xaa) { if (C.secure) handle_eapol(skb->data + hl + 8, skb->len - hl - 8); return; }
    if (C.state == NW_STA_UP || (C.state == NW_STA_KEYS && C.ptk_key)) to_eth(skb); } }

/* ---- the connection's life ---- */
static void connect_done(int res) {
  C.result = res; lx_cancel_delayed(&g_timer);
  if (res != NW_RES_OK) { teardown(0, 0); C.state = NW_STA_IDLE; C.result = res; } nw_wifi_stats.last_err = -res;
  if (g_ev.connect_done) g_ev.connect_done(res); }
static void teardown(int notify_lost, int reason) {
  if (C.sta) {
    if (C.ptk_key) { g_ops->set_key(g_hw, DISABLE_KEY, g_vif, C.sta, C.ptk_key); lx_free(C.ptk_key); C.ptk_key = 0; }
    if (C.gtk_key) { g_ops->set_key(g_hw, DISABLE_KEY, g_vif, 0, C.gtk_key); lx_free(C.gtk_key); C.gtk_key = 0; }
    if (g_vif->cfg.assoc) { g_vif->cfg.assoc = false; g_vif->cfg.aid = 0; g_ops->vif_cfg_changed(g_hw, g_vif, BSS_CHANGED_ASSOC); }
    while (C.sta_state > IEEE80211_STA_NOTEXIST) { if (g_ops->sta_state(g_hw, g_vif, C.sta, C.sta_state, C.sta_state - 1)) break; C.sta_state--; }
    nw_wifi_sta_set(0); lx_free(C.sta); C.sta = 0; }
  if (C.ctx) { g_ops->unassign_vif_chanctx(g_hw, g_vif, &g_vif->bss_conf, C.ctx); g_ops->remove_chanctx(g_hw, C.ctx); RCU_INIT_POINTER(g_vif->bss_conf.chanctx_conf, NULL); nw_wifi_chanctx_set(0); lx_free(C.ctx); C.ctx = 0; }
  nw_wifi_bss_set(0, 0, 0, 0);
  g_vif->bss_conf.bssid = g_no_bssid; C.ptk_ready = 0; C.hs_stage = 0; C.have_replay = 0; C.chanctx_up = 0;
  if (notify_lost) { C.state = NW_STA_IDLE; if (g_ev.link_lost) g_ev.link_lost(reason); } }
static void timer_fn(struct work_struct *w) {
  (void)w; u64 now = lx_now_ms();
  switch (C.state) {
  case NW_STA_AUTH: if (now - C.last_tx >= STEP_TIMEOUT_MS) { if (++C.tries > 7) { connect_done(NW_RES_TIMEOUT); return; } lx_log(6, "wifi: authentication sent again (try %d)", C.tries + 1); send_auth(); } break;
  case NW_STA_ASSOC: if (now - C.last_tx >= STEP_TIMEOUT_MS) { if (++C.tries > 7) { connect_done(NW_RES_TIMEOUT); return; } send_assoc(); } break;
  case NW_STA_KEYS:
    if (C.hs_stage == 3 && (C.m4_done || now - C.m4_at >= 300)) {
      lx_log(6, "wifi: keys installed %s (tx acked %u, not acked %u, dropped %u; %s)", C.m4_done ? "after message 4 completed" : "300 ms after message 4",
             nw_eapol_tx[0], nw_eapol_tx[1], nw_eapol_tx[2], tx_reasons());
      nw_wifi_htt_stats(8); install_keys(); break; }
    if (C.state == NW_STA_KEYS && now - C.started >= 8000) { lx_log(4, "wifi: key handshake timed out at stage %d (tx acked %u, not acked %u, dropped %u)", C.hs_stage, nw_eapol_tx[0], nw_eapol_tx[1], nw_eapol_tx[2]); connect_done(C.hs_stage ? NW_RES_BAD_KEY : NW_RES_TIMEOUT); return; } break;
  default: return; }
  lx_queue_delayed(&g_timer, 100); }

static void start_connect(void) {
  if (C.state != NW_STA_IDLE && C.state != NW_STA_SCANNING) return;
  struct bss *best = 0;
  lock();
  for (int i = 0; i < g_nbss; i++) { struct bss *b = &g_bss[i]; if (b->ssid_len != g_req.ssid_len || memcmp(b->ssid, g_req.ssid, b->ssid_len)) continue;
    if (g_req.has_bssid && memcmp(b->bssid, g_req.bssid, 6)) continue; if (!best || b->signal > best->signal) best = b; }
  if (best) C.ap = *best;
  unlock();
  memcpy(C.ssid, g_req.ssid, 32); C.ssid_len = g_req.ssid_len; C.result = 0;
  if (!best) { lx_log(4, "wifi: network not in the scan list"); connect_done(NW_RES_NOT_FOUND); return; }
  const u8 *rsn = find_rsn(C.ap.ie, C.ap.ie_len); C.secure = g_req.has_pass;
  if (C.secure) {
    if (rsn_check(rsn)) { lx_log(4, "wifi: network security not supported"); connect_done(NW_RES_UNSUPPORTED); return; }
    if (g_req.pass_len == 64) { for (int i = 0; i < 32; i++) { unsigned v; const char *s = g_req.pass + 2 * i; int hi = (s[0] <= '9' ? s[0] - '0' : (s[0] | 32) - 'a' + 10), lo = (s[1] <= '9' ? s[1] - '0' : (s[1] | 32) - 'a' + 10); v = hi << 4 | lo; C.pmk[i] = v; } }
    else nw_pbkdf2_sha1(g_req.pass, g_req.pass_len, C.ssid, C.ssid_len, 4096, C.pmk, 32);
  } else if (rsn) { lx_log(4, "wifi: network needs a passphrase"); connect_done(NW_RES_BAD_KEY); return; }
  int r = bring_up_channel(); if (r) { lx_log(3, "wifi: channel setup failed: %d", r); connect_done(NW_RES_FAILED); return; }
  nw_wifi_bss_set(C.ap.bssid, chan_for(C.ap.freq), C.ap.ie, C.ap.ie_len);
  r = g_ops->assign_vif_chanctx(g_hw, g_vif, &g_vif->bss_conf, C.ctx); if (r) { lx_log(3, "wifi: channel assign failed: %d", r); connect_done(NW_RES_FAILED); return; }
  r = add_station(); if (r) { lx_log(3, "wifi: station setup failed: %d", r); connect_done(NW_RES_FAILED); return; }
  g_ops->link_info_changed(g_hw, g_vif, &g_vif->bss_conf, BSS_CHANGED_BSSID | BSS_CHANGED_TXPOWER);
  C.state = NW_STA_AUTH; C.tries = 0; C.started = lx_now_ms(); nw_wifi_stats.stage = 7;
  lx_log(6, "wifi: connecting to %02x:%02x:%02x:%02x:%02x:%02x on %u MHz, signal %d dBm, transmit power %d dBm", C.ap.bssid[0], C.ap.bssid[1], C.ap.bssid[2], C.ap.bssid[3], C.ap.bssid[4], C.ap.bssid[5], C.ap.freq, C.ap.signal, g_vif->bss_conf.txpower);
  send_auth(); lx_queue_delayed(&g_timer, 100); }

/* ---- the data path ---- */
static void send_queued(void) {
  for (;;) {
    lock(); struct txq_item *it = g_txq_head; if (it) { g_txq_head = it->next; if (!g_txq_head) g_txq_tail = 0; g_txq_n--; } unlock();
    if (!it) return;
    if (C.state == NW_STA_UP && it->len >= 14) tx_eth(it->data, it->len);
    lx_free(it); } }
int nw_wifi_tx(const uint8_t *eth, size_t len) {
  if (len < 14 || len > 2000) return -1; if (g_txq_n >= 128) return -2;
  struct txq_item *it = lx_plat->alloc(sizeof *it + len); if (!it) return -3; it->len = len; it->next = 0; memcpy(it->data, eth, len);
  lock(); if (g_txq_tail) g_txq_tail->next = it; else g_txq_head = it; g_txq_tail = it; g_txq_n++; unlock(); return 0; }

/* ---- requests from the board ---- */
void nw_wifi_set_events(const struct nw_wifi_events *ev) { g_ev = *ev; }
int nw_wifi_scan(const uint8_t *ssid, size_t len) { lock(); g_req.kind = REQ_SCAN; g_scan_directed = len != 0; g_scan_ssid_len = len > 32 ? 32 : len; if (ssid) memcpy(g_scan_ssid, ssid, g_scan_ssid_len); unlock(); return 0; }
int nw_wifi_connect(const uint8_t *ssid, size_t len, const uint8_t *bssid, const char *pass, size_t plen) {
  if (len > 32 || plen > 64) return -1; if (pass && plen < 8) return -1;
  lock(); g_req.kind = REQ_CONNECT; g_req.ssid_len = len; memset(g_req.ssid, 0, 32); memcpy(g_req.ssid, ssid, len);
  g_req.has_bssid = bssid != 0; if (bssid) memcpy(g_req.bssid, bssid, 6); g_req.has_pass = pass != 0; g_req.pass_len = pass ? plen : 0; if (pass) memcpy(g_req.pass, pass, plen); unlock(); return 0; }
void nw_wifi_disconnect(void) { lock(); g_req.kind = REQ_DISCONNECT; unlock(); }
void nw_wifi_status_get(struct nw_wifi_status *st) {
  memset(st, 0, sizeof *st); st->state = C.state; st->result = C.result; if (g_vif) memcpy(st->mac, g_vif->addr, 6);
  if (C.state >= NW_STA_AUTH) { memcpy(st->bssid, C.ap.bssid, 6); st->ssid_len = C.ssid_len; memcpy(st->ssid, C.ssid, 32); st->freq_mhz = C.ap.freq; st->signal_dbm = C.ap.signal; }
  if (g_hw) for (int b = 0; b < NUM_NL80211_BANDS; b++) if (g_hw->wiphy->bands[b]) st->channels += g_hw->wiphy->bands[b]->n_channels; }
void nw_sta_run(void) {
  int kind; lock(); kind = g_req.kind; g_req.kind = REQ_NONE; unlock();
  if (g_vif) {
    if (kind == REQ_SCAN) do_scan(g_scan_directed ? g_scan_ssid : 0, g_scan_directed ? g_scan_ssid_len : 0);
    else if (kind == REQ_CONNECT && g_scan_running) {   /* the radio leaves the channel while it scans: the join waits for the scan's end */
      if (!g_connect_waits) { g_connect_waits = 1; lx_log(6, "wifi: join waits for the running scan, which is cancelled"); g_ops->cancel_hw_scan(g_hw, g_vif); } }
    else if (kind == REQ_CONNECT) start_connect();
    if (g_connect_waits && !g_scan_running) { g_connect_waits = 0; start_connect(); }
    else if (kind == REQ_DISCONNECT && C.state >= NW_STA_AUTH) { teardown(0, 0); C.state = NW_STA_IDLE; }
    if (C.state == NW_STA_UP || C.state >= NW_STA_AUTH) send_queued(); } }
void nw_sta_link_lost(void) { if (C.state >= NW_STA_AUTH) teardown(1, 0); }
void nw_sta_ready(struct ieee80211_hw *hw) {
  int r; g_hw = hw; g_ops = nw_wifi_ops(); nw_wifi_stats.stage = 3;
  r = g_ops->start(hw); if (r) { lx_log(3, "wifi: start failed: %d", r); nw_wifi_stats.last_err = r; return; }
  g_vif = lx_alloc(sizeof *g_vif + hw->vif_data_size + 64, 1); if (!g_vif) return;
  g_vif->type = NL80211_IFTYPE_STATION; g_vif->bss_conf.vif = g_vif; g_vif->bss_conf.link_id = 0; g_vif->link_conf[0] = &g_vif->bss_conf;
  memcpy(g_vif->addr, hw->wiphy->perm_addr, 6); g_vif->addr_valid = true; memcpy(g_vif->bss_conf.addr, hw->wiphy->perm_addr, 6); g_vif->bss_conf.bssid = g_no_bssid;   /* a link's own address: the driver makes its vdev with it */ g_vif->cab_queue = IEEE80211_INVAL_HW_QUEUE;
  for (int i = 0; i < IEEE80211_NUM_ACS; i++) g_vif->hw_queue[i] = IEEE80211_INVAL_HW_QUEUE;
  g_vif->offload_flags = IEEE80211_OFFLOAD_ENCAP_ENABLED | IEEE80211_OFFLOAD_DECAP_ENABLED;   /* what the wireless stack gives a station of a driver that supports both */
  r = g_ops->add_interface(hw, g_vif); if (r) { lx_log(3, "wifi: add interface failed: %d", r); nw_wifi_stats.last_err = r; return; }
  nw_wifi_vif_add(g_vif); nw_wifi_stats.stage = 4; C.state = NW_STA_IDLE;
  INIT_DELAYED_WORK(&g_timer, timer_fn);
  g_req.kind = REQ_SCAN; g_scan_directed = 0; }   /* the first scan starts by itself */
