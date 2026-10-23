#ifndef NW_MAC80211_H
#define NW_MAC80211_H
struct ieee80211_hw; struct ieee80211_vif; struct sk_buff; struct ieee80211_ops;
struct nw_wifi_hooks {
  void (*registered)(struct ieee80211_hw *);
  void (*rx)(struct ieee80211_hw *, struct sk_buff *);          /* every received frame; the callee does not keep the buffer */
  void (*scan_done)(struct ieee80211_hw *, bool aborted);
  void (*beacon_loss)(void);
};
void nw_wifi_set_hooks(const struct nw_wifi_hooks *h);
struct ieee80211_hw *nw_wifi_hw(void);
const struct ieee80211_ops *nw_wifi_ops(void);
void nw_wifi_vif_add(struct ieee80211_vif *v);
void nw_wifi_vif_del(struct ieee80211_vif *v);
#endif
