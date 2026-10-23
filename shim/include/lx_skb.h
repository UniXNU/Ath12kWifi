/* Packet buffers and the network device bits the wireless headers refer to. */
#ifndef LX_SKB_H
#define LX_SKB_H
#include "lx_net.h"
typedef u8 __u8; typedef u16 __u16; typedef u32 __u32x; typedef s8 __s8; typedef s16 __s16; typedef s32 __s32; typedef u64 __u64;
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_TDLS 0x890d
#define ETH_P_PAE 0x888e
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_ARP 0x0806
#define ETH_P_8021Q 0x8100
#define ETH_FCS_LEN 4
#define ETH_ZLEN 60
#define NSEC_PER_USEC 1000L
#define NSEC_PER_SEC 1000000000L
#define CLOCK_BOOTTIME 7
#define ETHTOOL_FWVERS_LEN 32
#define NETDEV_ALIGN 32
#define IS_ENABLED(x) 0
#define IFNAMSIZ 16
#define offsetofend(t, m) (__builtin_offsetof(t, m) + sizeof(((t *)0)->m))
#define hweight8(x) __builtin_popcount((u8)(x))
#define hweight16(x) __builtin_popcount((u16)(x))
#define hweight32(x) __builtin_popcount((u32)(x))
#define hweight64(x) __builtin_popcountll(x)
#define hweight_long(x) __builtin_popcountl(x)
static inline u8 u8_get_bits(u8 v, u8 m) { return (v & m) >> __builtin_ctz(m); }
static inline u16 u16_get_bits(u16 v, u16 m) { return (v & m) >> __builtin_ctz(m); }
static inline u32 u32_get_bits(u32 v, u32 m) { return (v & m) >> __builtin_ctz(m); }
static inline u64 u64_get_bits(u64 v, u64 m) { return (v & m) >> __builtin_ctzll(m); }
static inline u8 u8_encode_bits(u8 v, u8 m) { return (u8)(v << __builtin_ctz(m)) & m; }
static inline u16 u16_encode_bits(u16 v, u16 m) { return (u16)(v << __builtin_ctz(m)) & m; }
static inline u32 u32_encode_bits(u32 v, u32 m) { return (v << __builtin_ctz(m)) & m; }
static inline u64 u64_encode_bits(u64 v, u64 m) { return (v << __builtin_ctzll(m)) & m; }
static inline u32 u32_replace_bits(u32 old, u32 v, u32 m) { return (old & ~m) | u32_encode_bits(v, m); }
typedef struct { long long v; } atomic64_t;
typedef u64 netdev_features_t;
typedef struct { int unused; } possible_net_t;
#define write_pnet(p, n) ((void)0)
#define read_pnet(p) (&init_net)
struct rcu_head { struct rcu_head *next; void (*func)(struct rcu_head *); };
struct hrtimer { int unused; };
#define HRTIMER_MODE_REL 0
struct net_device { char name[IFNAMSIZ]; u8 dev_addr[ETH_ALEN]; u32 flags; u32 mtu; void *priv; netdev_features_t features; int ifindex; struct net *nd_net; };
#define netif_running(d) 1
#define rfkill_pause_polling(r) ((void)0)
struct rfkill;
struct sk_buff {
  struct sk_buff *next, *prev;
  u8 *head, *data, *tail, *end;
  u32 len, data_len, truesize;
  char cb[48] __attribute__((aligned(8)));
  struct sock *sk; struct net_device *dev;
  u16 protocol, queue_mapping; u8 priority, ip_summed, pkt_type, cloned; u32 mark; u64 tstamp;
  u16 network_header, transport_header;
};
struct sk_buff_head { struct sk_buff *next, *prev; u32 qlen; spinlock_t lock; };
struct sk_buff *alloc_skb(unsigned int size, gfp_t f);
struct sk_buff *__dev_alloc_skb(unsigned int size, gfp_t f);
#define dev_alloc_skb(n) __dev_alloc_skb(n, 0)
#define netdev_alloc_skb(d, n) __dev_alloc_skb(n, 0)
void kfree_skb(struct sk_buff *skb);
#define dev_kfree_skb(s) kfree_skb(s)
#define dev_kfree_skb_any(s) kfree_skb(s)
#define dev_kfree_skb_irq(s) kfree_skb(s)
#define consume_skb(s) kfree_skb(s)
#define kfree_skb_reason(s, r) kfree_skb(s)
static inline u32 skb_headroom(const struct sk_buff *s) { return s->data - s->head; }
static inline u32 skb_tailroom(const struct sk_buff *s) { return s->end - s->tail; }
static inline void skb_reserve(struct sk_buff *s, int n) { s->data += n; s->tail += n; }
static inline void *skb_put(struct sk_buff *s, u32 n) { void *p = s->tail; s->tail += n; s->len += n; return p; }
static inline void *skb_put_zero(struct sk_buff *s, u32 n) { void *p = skb_put(s, n); memset(p, 0, n); return p; }
static inline void *skb_put_data(struct sk_buff *s, const void *d, u32 n) { void *p = skb_put(s, n); memcpy(p, d, n); return p; }
static inline void *skb_push(struct sk_buff *s, u32 n) { s->data -= n; s->len += n; return s->data; }
static inline void *skb_pull(struct sk_buff *s, u32 n) { if (n > s->len) return 0; s->len -= n; return s->data += n; }
static inline void skb_trim(struct sk_buff *s, u32 n) { if (s->len > n) { s->len = n; s->tail = s->data + n; } }
static inline int skb_linearize(struct sk_buff *s) { (void)s; return 0; }
static inline int skb_is_nonlinear(const struct sk_buff *s) { return s->data_len != 0; }
static inline unsigned char *skb_network_header(const struct sk_buff *s) { return s->head + s->network_header; }
static inline int skb_network_offset(const struct sk_buff *s) { return skb_network_header(s) - s->data; }
static inline void skb_reset_network_header(struct sk_buff *s) { s->network_header = s->data - s->head; }
static inline void skb_set_network_header(struct sk_buff *s, int off) { s->network_header = s->data - s->head + off; }
static inline int skb_cloned(const struct sk_buff *s) { return s->cloned; }
static inline int skb_cow_head(struct sk_buff *s, unsigned int h) { return skb_headroom(s) >= h ? 0 : -ENOMEM; }
static inline int pskb_expand_head(struct sk_buff *s, int a, int b, gfp_t f) { (void)s; (void)a; (void)b; (void)f; return 0; }
static inline int skb_ensure_writable(struct sk_buff *s, int n) { (void)s; (void)n; return 0; }
struct sk_buff *skb_copy(const struct sk_buff *s, gfp_t f);
struct sk_buff *skb_clone(struct sk_buff *s, gfp_t f);
struct sk_buff *skb_copy_expand(const struct sk_buff *s, int h, int t, gfp_t f);
static inline void skb_queue_head_init(struct sk_buff_head *q) { q->next = q->prev = (struct sk_buff *)q; q->qlen = 0; spin_lock_init(&q->lock); }
#define __skb_queue_head_init(q) skb_queue_head_init(q)
static inline int skb_queue_empty(const struct sk_buff_head *q) { return q->next == (const struct sk_buff *)q; }
static inline u32 skb_queue_len(const struct sk_buff_head *q) { return q->qlen; }
static inline void __skb_queue_tail(struct sk_buff_head *q, struct sk_buff *s) { struct sk_buff *l = q->prev; s->next = (struct sk_buff *)q; s->prev = l; l->next = s; q->prev = s; q->qlen++; }
static inline void __skb_queue_head(struct sk_buff_head *q, struct sk_buff *s) { struct sk_buff *f = q->next; s->next = f; s->prev = (struct sk_buff *)q; f->prev = s; q->next = s; q->qlen++; }
static inline struct sk_buff *skb_peek(const struct sk_buff_head *q) { struct sk_buff *s = q->next; return s == (const struct sk_buff *)q ? 0 : s; }
static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *q) { struct sk_buff *s = skb_peek(q); if (s) { q->next = s->next; s->next->prev = (struct sk_buff *)q; q->qlen--; s->next = s->prev = 0; } return s; }
static inline void __skb_unlink(struct sk_buff *s, struct sk_buff_head *q) { s->prev->next = s->next; s->next->prev = s->prev; q->qlen--; s->next = s->prev = 0; }
static inline void skb_queue_tail(struct sk_buff_head *q, struct sk_buff *s) { __skb_queue_tail(q, s); }
static inline void skb_queue_head(struct sk_buff_head *q, struct sk_buff *s) { __skb_queue_head(q, s); }
static inline struct sk_buff *skb_dequeue(struct sk_buff_head *q) { return __skb_dequeue(q); }
static inline void skb_unlink(struct sk_buff *s, struct sk_buff_head *q) { __skb_unlink(s, q); }
static inline void skb_queue_purge(struct sk_buff_head *q) { struct sk_buff *s; while ((s = __skb_dequeue(q))) kfree_skb(s); }
#define __skb_queue_purge(q) skb_queue_purge(q)
static inline void skb_queue_splice_tail_init(struct sk_buff_head *a, struct sk_buff_head *b) { struct sk_buff *s; while ((s = __skb_dequeue(a))) __skb_queue_tail(b, s); }
#define skb_queue_walk(q, s) for (s = (q)->next; s != (struct sk_buff *)(q); s = s->next)
#define skb_queue_walk_safe(q, s, t) for (s = (q)->next, t = s->next; s != (struct sk_buff *)(q); s = t, t = s->next)
#define skb_cb_lx(s) ((s)->cb)

#define struct_group(name, ...) union { struct { __VA_ARGS__ }; struct { __VA_ARGS__ } name; }
#define struct_group_attr(name, attrs, ...) union { struct { __VA_ARGS__ }; struct attrs { __VA_ARGS__ } name; }
#define __struct_group(tag, name, attrs, ...) union { struct { __VA_ARGS__ } attrs; struct tag { __VA_ARGS__ } attrs name; }
#define DECLARE_FLEX_ARRAY(t, n) struct { struct { } __empty_##n; t n[]; }
#define __counted_by(x)
#define __counted_by_le(x)
#define __must_be_array(x) 0
#define memset_after(p, v, m) memset((char *)(p) + offsetofend(__typeof__(*(p)), m), v, sizeof(*(p)) - offsetofend(__typeof__(*(p)), m))
#define lockdep_is_held(l) 1
#define lockdep_rtnl_is_held() 1
#define rcu_dereference_protected(p, c) (p)
#define rcu_dereference_check(p, c) (p)
#define rcu_access_pointer(p) (p)
#define RCU_INIT_POINTER(p, v) ((p) = (v))
#define rcu_pointer_handoff(p) (p)
#define kfree_rcu(p, m) lx_free(p)
#define call_rcu(h, f) ((f)(h))
#define list_for_each_entry_rcu(p, h, m, ...) list_for_each_entry(p, h, m)
#define ktime_get_ns() ((u64)ktime_get())
#define ktime_get_boottime() ktime_get()
#define ktime_get_real_ns() ((u64)ktime_get())
#define hrtimer_setup(t, f, c, m) ((void)0)
#define get_random_bytes(p, n) do { for (size_t _i = 0; _i < (n); _i++) ((u8 *)(p))[_i] = (u8)lx_random_u32(); } while (0)
#define do_div(n, b) ({ u32 _r = (u32)((n) % (b)); (n) /= (b); _r; })
static inline u16 get_unaligned_be16(const void *p) { const u8 *b = p; return (b[0] << 8) | b[1]; }
static inline u32 get_unaligned_be32(const void *p) { const u8 *b = p; return ((u32)b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]; }
static inline u16 get_unaligned_le16x(const void *p) { u16 v; memcpy(&v, p, 2); return v; }
static inline u16 le16_get_bits(__le16 v, u16 m) { return (v & m) >> __builtin_ctz(m); }
static inline u32 le32_get_bits(__le32 v, u32 m) { return (v & m) >> __builtin_ctz(m); }
static inline __le16 le16_encode_bits(u16 v, u16 m) { return (u16)(v << __builtin_ctz(m)) & m; }
static inline __le32 le32_encode_bits(u32 v, u32 m) { return (v << __builtin_ctz(m)) & m; }
static inline __le16 cpu_to_be16x(u16 v) { return (v >> 8) | (v << 8); }
#define cpu_to_be16(x) ((u16)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#define be16_to_cpu(x) cpu_to_be16(x)
#define swab16(x) cpu_to_be16(x)
#define htons(x) cpu_to_be16(x)
#define ntohs(x) cpu_to_be16(x)
static inline int is_multicast_ether_addr(const u8 *a) { return 0x01 & a[0]; }
static inline int is_broadcast_ether_addr(const u8 *a) { return (a[0] & a[1] & a[2] & a[3] & a[4] & a[5]) == 0xff; }
static inline int is_zero_ether_addr(const u8 *a) { return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]); }
static inline int is_valid_ether_addr(const u8 *a) { return !is_multicast_ether_addr(a) && !is_zero_ether_addr(a); }
static inline int ether_addr_equal(const u8 *a, const u8 *b) { return !memcmp(a, b, 6); }
static inline void ether_addr_copy(u8 *d, const u8 *s) { memcpy(d, s, 6); }
static inline u64 ether_addr_to_u64(const u8 *a) { u64 v = 0; for (int i = 0; i < 6; i++) v = (v << 8) | a[i]; return v; }
static inline void u64_to_ether_addr(u64 v, u8 *a) { for (int i = 5; i >= 0; i--) { a[i] = v & 0xff; v >>= 8; } }
static inline void eth_zero_addr(u8 *a) { memset(a, 0, 6); }
static inline void eth_broadcast_addr(u8 *a) { memset(a, 0xff, 6); }
#define EXPORT_SYMBOL_NS_GPL(a, b)
static inline void __set_bit(int n, unsigned long *p) { p[n / 64] |= 1UL << (n % 64); }
static inline void __clear_bit(int n, unsigned long *p) { p[n / 64] &= ~(1UL << (n % 64)); }
static inline int __test_and_set_bit(int n, unsigned long *p) { int o = (p[n / 64] >> (n % 64)) & 1; __set_bit(n, p); return o; }
#define __acquires(x)
#define __releases(x)
#define __must_hold(x)
#define __acquire(x)
#define __release(x)
#define __attribute_const__ __attribute__((const))
#define __ro_after_init
#define __percpu
#define static_assert(c, ...) _Static_assert(c, "")
enum rfkill_hard_block_reasons { RFKILL_HARD_BLOCK_SIGNAL = 1 << 0, RFKILL_HARD_BLOCK_NOT_OWNER = 1 << 1 };
#define DEFINE_GUARD(name, type, lock, unlock)
#define DEFINE_GUARD_COND(...)
#define DEFINE_FREE(...)
#define __bitwise
#define __rcu_lx
#endif
