/* Packet buffers, hash tables, polling contexts and the Michael MIC hash for the WiFi data path. */
#include "lx_pci.h"
#include "lx_plat.h"

/* ---- packet buffers: one allocation holds the shared info, the head room, the data and the tail room ---- */
struct sk_buff *alloc_skb(unsigned int size, gfp_t f) {
  (void)f; struct sk_buff *s = lx_alloc(sizeof *s, 1); if (!s) return 0;
  /* packet data lives in the DMA window: the device reads and writes it */
  size = ALIGN(size, 4); u64 bus; u8 *b = lx_plat->dma_alloc(size + sizeof(struct skb_shared_info) + 64, &bus); if (!b) { lx_free(s); return 0; }
  s->head = s->data = s->tail = b; s->end = b + size; s->truesize = size; return s; }
struct sk_buff *__dev_alloc_skb(unsigned int size, gfp_t f) { struct sk_buff *s = alloc_skb(size + 32, f); if (s) skb_reserve(s, 32); return s; }
void kfree_skb(struct sk_buff *s) { if (!s) return; lx_plat->dma_free(0, s->head, 0); lx_free(s); }
struct sk_buff *skb_copy(const struct sk_buff *s, gfp_t f) {
  struct sk_buff *n = alloc_skb(s->end - s->head, f); if (!n) return 0;
  skb_reserve(n, s->data - s->head); skb_put_data(n, s->data, s->len); memcpy(n->cb, s->cb, sizeof n->cb);
  n->protocol = s->protocol; n->queue_mapping = s->queue_mapping; n->priority = s->priority; return n; }
struct sk_buff *skb_clone(struct sk_buff *s, gfp_t f) { return skb_copy(s, f); }
struct sk_buff *skb_copy_expand(const struct sk_buff *s, int h, int t, gfp_t f) {
  struct sk_buff *n = alloc_skb(h + s->len + t, f); if (!n) return 0; skb_reserve(n, h); skb_put_data(n, s->data, s->len); return n; }
struct sk_buff *skb_realloc_headroom(struct sk_buff *s, unsigned int h) { return skb_copy_expand(s, h, skb_tailroom(s), 0); }
int skb_cow_data(struct sk_buff *s, int tail, struct sk_buff **trailer) { (void)tail; *trailer = s; return 1; }
void *pskb_put(struct sk_buff *s, struct sk_buff *tail, int n) { (void)tail; return skb_put(s, n); }

/* ---- rhashtable: a single chain; peer tables are small ---- */
int rhashtable_init(struct rhashtable *t, const struct rhashtable_params *p) { t->head = 0; t->p = *p; t->n = 0; return 0; }
void rhashtable_destroy(struct rhashtable *t) { t->head = 0; t->n = 0; }
static void *key_of(const struct rhashtable *t, const struct rhash_head *h, struct rhashtable_params p) {
  (void)t; return (u8 *)h - p.head_offset + p.key_offset; }
void *rhashtable_lookup_fast(struct rhashtable *t, const void *key, struct rhashtable_params p) {
  for (struct rhash_head *h = t->head; h; h = h->next) if (!memcmp(key_of(t, h, p), key, p.key_len)) return (u8 *)h - p.head_offset;
  return 0; }
void *rhashtable_lookup_get_insert_fast(struct rhashtable *t, struct rhash_head *obj, struct rhashtable_params p) {
  void *o = rhashtable_lookup_fast(t, key_of(t, obj, p), p); if (o) return o;
  obj->next = t->head; t->head = obj; t->n++; return 0; }
int rhashtable_insert_fast(struct rhashtable *t, struct rhash_head *obj, struct rhashtable_params p) {
  return rhashtable_lookup_get_insert_fast(t, obj, p) ? -EEXIST : 0; }
int rhashtable_remove_fast(struct rhashtable *t, struct rhash_head *obj, struct rhashtable_params p) {
  (void)p; for (struct rhash_head **pp = &t->head; *pp; pp = &(*pp)->next) if (*pp == obj) { *pp = obj->next; t->n--; return 0; }
  return -ENOENT; }

/* ---- polling contexts run from the dispatcher ---- */
static struct napi_struct *g_napi[16];
static void napi_run(struct work_struct *w);
static struct work_struct g_napi_work;
void lx_napi_add(struct net_device *d, struct napi_struct *n, int (*poll)(struct napi_struct *, int), int weight) {
  n->dev = d; n->poll = poll; n->weight = weight; n->scheduled = 0;
  for (int i = 0; i < 16; i++) if (!g_napi[i] || g_napi[i] == n) { g_napi[i] = n; break; }
  INIT_WORK(&g_napi_work, napi_run); }
void lx_napi_schedule(struct napi_struct *n) { n->scheduled = 1; lx_queue_work(&g_napi_work); }
bool lx_napi_complete_done(struct napi_struct *n, int done) { (void)done; n->scheduled = 0; return true; }
static void napi_run(struct work_struct *w) {
  (void)w; int again = 0;
  for (int i = 0; i < 16; i++) if (g_napi[i] && g_napi[i]->scheduled) {
    int done = g_napi[i]->poll(g_napi[i], g_napi[i]->weight);
    if (done >= g_napi[i]->weight) again = 1; }
  if (again) lx_queue_work(&g_napi_work); }

/* ---- Michael MIC (the TKIP integrity hash) ---- */
struct crypto_shash *crypto_alloc_shash(const char *alg, u32 type, u32 mask) {
  (void)type; (void)mask; if (strcmp(alg, "michael_mic")) return (struct crypto_shash *)ERR_PTR(-ENOENT);
  return lx_alloc(sizeof(struct crypto_shash) + 16, 1); }
void crypto_free_shash(struct crypto_shash *t) { lx_free(t); }
struct mm { u32 l, r; u32 key[2]; u32 pend, pendlen; };
static u32 rol(u32 v, int n) { return (v << n) | (v >> (32 - n)); }
static u32 ror(u32 v, int n) { return (v >> n) | (v << (32 - n)); }
static u32 xswap(u32 v) { return ((v & 0xff00ff00u) >> 8) | ((v & 0x00ff00ffu) << 8); }
static void mix(struct mm *m) {
  m->r ^= rol(m->l, 17); m->l += m->r; m->r ^= xswap(m->l); m->l += m->r; m->r ^= rol(m->l, 3); m->l += m->r; m->r ^= ror(m->l, 2); m->l += m->r; }
int crypto_shash_setkey(struct crypto_shash *t, const u8 *key, unsigned int len) {
  if (len != 8) return -EINVAL; memcpy((u8 *)t + sizeof *t, key, 8); return 0; }
int crypto_shash_init(struct shash_desc *d) {
  struct mm *m = (struct mm *)d->ctx; const u8 *k = (u8 *)d->tfm + sizeof *d->tfm;
  memcpy(m->key, k, 8); m->l = m->key[0]; m->r = m->key[1]; m->pend = 0; m->pendlen = 0; return 0; }
int crypto_shash_update(struct shash_desc *d, const u8 *data, unsigned int len) {
  struct mm *m = (struct mm *)d->ctx;
  while (len--) { m->pend |= (u32)*data++ << (8 * m->pendlen); if (++m->pendlen == 4) { m->l ^= m->pend; mix(m); m->pend = 0; m->pendlen = 0; } }
  return 0; }
int crypto_shash_final(struct shash_desc *d, u8 *out) {
  struct mm *m = (struct mm *)d->ctx; static const u8 pad[5] = { 0x5a, 0, 0, 0, 0 };
  crypto_shash_update(d, pad, 1); while (m->pendlen) crypto_shash_update(d, pad + 1, 1);
  for (int i = 0; i < 4; i++) crypto_shash_update(d, pad + 1, 1); memcpy(out, &m->l, 4); memcpy(out + 4, &m->r, 4); return 0; }
