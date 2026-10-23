/* Kernel facilities the ath12k sources use beyond the basics: hash tables, polling contexts, device tree and PCI stand-ins. */
#ifndef LX_ATH_H
#define LX_ATH_H
#include "lx_skb.h"
typedef struct { u8 b[16]; } guid_t;
typedef guid_t uuid_t;
#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) { { (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, (b) & 0xff, ((b) >> 8) & 0xff, (c) & 0xff, ((c) >> 8) & 0xff, d0, d1, d2, d3, d4, d5, d6, d7 } }
struct lock_class_key { int unused; };
#define lockdep_register_key(k)
#define lockdep_unregister_key(k)
#define lockdep_set_class(l, k)
#define RCU_LOCKDEP_WARN(c, ...) ((void)0)
#define rcu_read_lock_held() 1
#define rcu_read_lock_bh_held() 1
#define rcu_read_lock_bh() ((void)0)
#define rcu_read_unlock_bh() ((void)0)

/* rhashtable: chained buckets keyed by a byte range inside the element */
struct rhash_head { struct rhash_head *next; };
struct rhashtable_params {
  u16 nelem_hint, key_len, key_offset, head_offset; u32 max_size; u16 min_size; bool automatic_shrinking;
  int (*obj_cmpfn)(void *, const void *); u32 (*hashfn)(const void *, u32, u32); void *obj_hashfn;
};
struct rhashtable { struct rhash_head *head; struct rhashtable_params p; unsigned int n; };
int rhashtable_init(struct rhashtable *t, const struct rhashtable_params *p);
void rhashtable_destroy(struct rhashtable *t);
void *rhashtable_lookup_fast(struct rhashtable *t, const void *key, struct rhashtable_params p);
void *rhashtable_lookup_get_insert_fast(struct rhashtable *t, struct rhash_head *obj, struct rhashtable_params p);
int rhashtable_insert_fast(struct rhashtable *t, struct rhash_head *obj, struct rhashtable_params p);
int rhashtable_remove_fast(struct rhashtable *t, struct rhash_head *obj, struct rhashtable_params p);
#define rht_head_lx(x) (x)
#define IS_ERR_OR_NULL_LX(p) IS_ERR_OR_NULL(p)

/* polling context: the data path runs it from the dispatcher */
struct napi_struct { struct net_device *dev; int (*poll)(struct napi_struct *, int); int weight; int scheduled; struct list_head poll_list; int state; };
void lx_napi_add(struct net_device *d, struct napi_struct *n, int (*poll)(struct napi_struct *, int), int weight);
void lx_napi_schedule(struct napi_struct *n);
bool lx_napi_complete_done(struct napi_struct *n, int done);
#define netif_napi_add(d, n, p) lx_napi_add(d, n, p, 64)
#define netif_napi_add_weight(d, n, p, w) lx_napi_add(d, n, p, w)
#define netif_napi_del(n) ((n)->scheduled = 0)
#define napi_enable(n) ((void)(n))
#define napi_disable(n) ((void)(n))
#define napi_schedule(n) lx_napi_schedule(n)
#define napi_complete_done(n, d) lx_napi_complete_done(n, d)
#define napi_synchronize(n) ((void)(n))
#define napi_schedule_prep(n) 1
#define __napi_schedule(n) lx_napi_schedule(n)
#define init_dummy_netdev(d) memset(d, 0, sizeof *d)
#define free_netdev(d) ((void)(d))
#define alloc_netdev_dummy(n) ((struct net_device *)lx_alloc(sizeof(struct net_device), 1))

struct dmi_header { u8 type, length; u16 handle; };
struct notifier_block { int (*notifier_call)(struct notifier_block *, unsigned long, void *); struct notifier_block *next; int priority; };
#define NOTIFY_DONE 0
#define NOTIFY_OK 1
#define NOTIFY_BAD 2
struct atomic_notifier_head { int unused; };
#define atomic_notifier_chain_register(h, n) 0
#define atomic_notifier_chain_unregister(h, n) 0
#define panic_notifier_list lx_panic_list
extern struct atomic_notifier_head lx_panic_list;
#define register_pm_notifier(n) 0
struct device_node { int unused; };
#define of_property_read_string(np, n, out) (-ENOENT)
#define of_property_read_u32(np, n, out) (-ENOENT)
#define of_property_read_bool(np, n) 0
#define of_device_is_compatible(np, c) 0
#define of_find_property(np, n, l) ((void *)0)
#define of_node_put(n) ((void)0)
#define of_get_child_by_name(n, c) ((struct device_node *)0)
#define of_get_property(np, n, l) ((const void *)0)
#define of_address_to_resource(np, i, r) (-ENOENT)
#define of_reserved_mem_lookup(n) ((void *)0)
#define of_parse_phandle(np, p, i) ((struct device_node *)0)
#define of_graph_get_remote_node(...) ((struct device_node *)0)
#define for_each_available_child_of_node_scoped(...) if (0)
#define of_match_node(m, n) ((void *)0)
#define of_match_device(m, d) ((void *)0)
#define device_property_read_string(d, n, o) (-ENOENT)
#define device_property_read_u32(d, n, o) (-ENOENT)
#endif
