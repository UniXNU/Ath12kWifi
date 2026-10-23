/* Devices, waiting, deferred work, interrupts, DMA, firmware, packets. See lx.h for the execution model. */
#ifndef LX_OS_H
#define LX_OS_H
#include "lx.h"
#include <stdio.h>
typedef unsigned long ulong;

struct device; struct firmware; struct sk_buff; struct module; struct kobj_uevent_env; struct attribute_group;
struct kobject { int unused; };
struct device_node;
struct attribute { const char *name; };
struct device_attribute { struct attribute attr; };
struct bus_type;
struct device_driver { const char *name; const struct bus_type *bus; struct module *owner; int (*probe)(struct device *); const struct dev_pm_ops *pm; };
struct dev_pm_ops;
struct device_type { const char *name; void (*release)(struct device *); };
struct device {
  const char *name; char namebuf[64]; struct device *parent; void *drvdata; u64 dma_mask; void *platform_data;
  struct device_driver *driver; const struct bus_type *bus; const struct device_type *type; void (*release)(struct device *);
  struct kobject kobj; struct list_head children, sibling; int registered; struct device_node *of_node;
};
struct bus_type {
  const char *name; const char *dev_name; int (*match)(struct device *, const struct device_driver *); int (*probe)(struct device *);
  void (*remove)(struct device *); int (*uevent)(const struct device *, struct kobj_uevent_env *);
  const struct attribute_group **dev_groups;
};
#define THIS_MODULE ((struct module *)0)
#define DEVICE_ATTR_RO(n) static struct device_attribute dev_attr_##n = { { #n } }
#define DEVICE_ATTR_WO(n) static struct device_attribute dev_attr_##n = { { #n } }
#define ATTRIBUTE_GROUPS(n) static const struct attribute_group *n##_groups[] = { 0 }
#define sysfs_emit(buf, ...) snprintf(buf, 4096, __VA_ARGS__)
#define sysfs_emit_at(buf, at, ...) snprintf((buf) + (at), 4096 - (at), __VA_ARGS__)
#define sysfs_create_file(k, a) 0
#define sysfs_remove_file(k, a) ((void)0)
#define KOBJ_CHANGE 0
#define kobject_uevent_env(k, a, e) 0
#define add_uevent_var(env, ...) 0
#define kasprintf(f, ...) lx_strdup("")
#define U32_MAX 0xffffffffu
#define dma_wmb() mb()
#define dma_rmb() mb()
#define fsleep(us) lx_delay_us(us)
#define __ffs(x) __builtin_ctzl(x)
#define __fls(x) (63 - __builtin_clzl(x))
#define container_of_const(p, t, m) container_of(p, t, m)
#define vcalloc(n, s) lx_alloc((n) * (s), 1)
#define read_lock_irq(l) ((l)->readers++)
#define read_unlock_irq(l) ((l)->readers--)
unsigned long find_last_bit(const unsigned long *a, unsigned long n);
unsigned long find_first_bit(const unsigned long *a, unsigned long n);
int device_register(struct device *d);
#define device_add(d) device_register(d)
#define device_del(d) device_unregister(d)
/* device memory takes only aligned accesses of a single width: never the string functions on a mapped BAR */
static inline void memset_io(volatile void *a, int v, unsigned long n) {
  volatile unsigned char *b = (volatile unsigned char *)a; unsigned int w = (unsigned char)v * 0x01010101u;
  while (n && ((unsigned long)b & 3)) { *b++ = (unsigned char)v; n--; }
  while (n >= 4) { *(volatile unsigned int *)b = w; b += 4; n -= 4; }
  while (n) { *b++ = (unsigned char)v; n--; } }
static inline void memcpy_fromio(void *d, const volatile void *s, unsigned long n) {
  unsigned char *o = d; const volatile unsigned char *i = (const volatile unsigned char *)s;
  while (n && (((unsigned long)i | (unsigned long)o) & 3)) { *o++ = *i++; n--; }
  while (n >= 4) { *(unsigned int *)o = *(const volatile unsigned int *)i; o += 4; i += 4; n -= 4; }
  while (n) { *o++ = *i++; n--; } }
static inline void memcpy_toio(volatile void *d, const void *s, unsigned long n) {
  volatile unsigned char *o = (volatile unsigned char *)d; const unsigned char *i = s;
  while (n && (((unsigned long)i | (unsigned long)o) & 3)) { *o++ = *i++; n--; }
  while (n >= 4) { *(volatile unsigned int *)o = *(const unsigned int *)i; o += 4; i += 4; n -= 4; }
  while (n) { *o++ = *i++; n--; } }
#define alloc_ordered_workqueue(...) alloc_workqueue(0)
#define postcore_initcall(f)
#define module_init(f)
#define module_exit(f)
#define kstrtoul(s, b, r) lx_kstrtoul(s, b, r)
int lx_kstrtoul(const char *s, int base, unsigned long *r);

#define tasklet_init(t, f, d) ((t)->legacy = (f), (t)->data = (d))
void device_unregister(struct device *d);
int device_for_each_child(struct device *d, void *data, int (*fn)(struct device *, void *));
int driver_register(struct device_driver *d);
void driver_unregister(struct device_driver *d);
int bus_register(const struct bus_type *b);
void bus_unregister(const struct bus_type *b);
#define dev_name(d) ((d)->name ? (d)->name : "dev")
#define dev_get_drvdata(d) ((d)->drvdata)
#define dev_set_drvdata(d, p) ((d)->drvdata = (p))
#define dev_err(d, ...) lx_log(3, __VA_ARGS__)
#define dev_warn(d, ...) lx_log(4, __VA_ARGS__)
#define dev_info(d, ...) lx_log(6, __VA_ARGS__)
#define dev_dbg(d, ...) lx_log(7, __VA_ARGS__)
#define dev_err_ratelimited(d, ...) lx_log(3, __VA_ARGS__)
#define dev_warn_ratelimited(d, ...) lx_log(4, __VA_ARGS__)
#define pr_err(...) lx_log(3, __VA_ARGS__)
#define pr_warn(...) lx_log(4, __VA_ARGS__)
#define pr_info(...) lx_log(6, __VA_ARGS__)
#define pr_debug(...) lx_log(7, __VA_ARGS__)
#define pr_fmt(x) x
#define dev_WARN(d, ...) lx_log(4, __VA_ARGS__)
static inline void get_device(struct device *d) { (void)d; }
static inline void put_device(struct device *d) { (void)d; }
static inline void device_initialize(struct device *d) { (void)d; }
static inline int dev_set_name(struct device *d, const char *f, ...) { (void)d; (void)f; return 0; }
static inline void device_init_wakeup(struct device *d, int e) { (void)d; (void)e; }
static inline int device_may_wakeup(struct device *d) { (void)d; return 0; }
static inline void pm_wakeup_event(struct device *d, int ms) { (void)d; (void)ms; }
static inline void pm_runtime_get_noresume(struct device *d) { (void)d; }
static inline void pm_runtime_put_noidle(struct device *d) { (void)d; }

/* waiting: wait_event runs the dispatcher (lx_pump) instead of sleeping */
typedef struct { int unused; } wait_queue_head_t;
#define init_waitqueue_head(w) ((void)(w))
#define wake_up(w) ((void)(w))
#define wake_up_all(w) ((void)(w))
#define wake_up_interruptible(w) ((void)(w))
int lx_pump(void);               /* runs one round of ready work; returns nonzero if anything ran */
void lx_idle(unsigned int ms);   /* nothing ready: let the clock advance and device events arrive */
/* The condition may have side effects (a command is sent when it is evaluated): it is evaluated once per round, and never again after the wait ends. */
#define wait_event_timeout(w, cond, tmo_j) ({ \
    unsigned long _end = jiffies + (tmo_j); long _r; (void)(w); \
    for (;;) { \
      if (cond) { _r = (long)((_end - jiffies) > 0 ? (_end - jiffies) : 1); break; } \
      if (!lx_pump()) { if (time_after(jiffies, _end) || jiffies == _end) { _r = (cond) ? 1 : 0; break; } lx_idle(1); } } \
    _r; })
#define wait_event(w, cond) ({ (void)(w); while (!(cond)) { if (!lx_pump()) lx_idle(1); } })
#define wait_event_interruptible(w, cond) ({ wait_event(w, cond); 0; })
#define wait_event_interruptible_timeout(w, cond, t) wait_event_timeout(w, cond, t)
struct completion { int done; };
#define init_completion(c) ((c)->done = 0)
#define reinit_completion(c) ((c)->done = 0)
#define complete(c) ((c)->done = 1)
#define complete_all(c) ((c)->done = 1)
#define DECLARE_COMPLETION(n) struct completion n = { 0 }
#define wait_for_completion(c) ({ while (!(c)->done) { if (!lx_pump()) lx_idle(1); } })
#define wait_for_completion_timeout(c, t) ({ long _r = wait_event_timeout(0, (c)->done, t); _r; })
#define completion_done(c) ((c)->done)

/* deferred work */
struct work_struct { struct list_head entry; void (*func)(struct work_struct *); int queued; };
struct delayed_work { struct work_struct work; u64 due; int armed; };
struct workqueue_struct { int unused; };
#define INIT_WORK(w, f) do { (w)->func = (f); (w)->queued = 0; INIT_LIST_HEAD(&(w)->entry); } while (0)
#define INIT_DELAYED_WORK(d, f) do { INIT_WORK(&(d)->work, f); (d)->armed = 0; } while (0)
#define to_delayed_work(w) container_of(w, struct delayed_work, work)
int lx_queue_work(struct work_struct *w);
int lx_queue_delayed(struct delayed_work *d, unsigned long delay_ms);
int lx_cancel_work(struct work_struct *w);
int lx_cancel_delayed(struct delayed_work *d);
#define schedule_work(w) lx_queue_work(w)
#define queue_work(q, w) lx_queue_work(w)
#define queue_delayed_work(q, d, t) lx_queue_delayed(d, t)
#define schedule_delayed_work(d, t) lx_queue_delayed(d, t)
#define cancel_work_sync(w) lx_cancel_work(w)
#define cancel_delayed_work_sync(d) lx_cancel_delayed(d)
#define cancel_delayed_work(d) lx_cancel_delayed(d)
#define flush_work(w) lx_cancel_work(w)
#define flush_workqueue(q) ((void)(q))
#define destroy_workqueue(q) ((void)(q))
#define alloc_workqueue(...) ((struct workqueue_struct *)lx_alloc(sizeof(struct workqueue_struct), 1))
#define create_singlethread_workqueue(n) alloc_workqueue(n)
#define WQ_UNBOUND 0
#define WQ_HIGHPRI 0
#define WQ_MEM_RECLAIM 0
struct timer_list { struct delayed_work d; void (*function)(struct timer_list *); };
#define timer_setup(t, f, fl) do { (t)->function = (f); INIT_DELAYED_WORK(&(t)->d, 0); } while (0)
int lx_timer_mod(struct timer_list *t, unsigned long expires_j);
int lx_timer_del(struct timer_list *t);
#define mod_timer(t, e) lx_timer_mod(t, e)
#define del_timer(t) lx_timer_del(t)
#define del_timer_sync(t) lx_timer_del(t)
#define timer_delete_sync(t) lx_timer_del(t)
#define from_timer(v, t, f) container_of(t, __typeof__(*v), f)
struct tasklet_struct { struct work_struct w; void (*func)(struct tasklet_struct *); void (*legacy)(unsigned long); unsigned long data; };
#define tasklet_setup(t, f) do { (t)->func = (f); } while (0)
void lx_tasklet_schedule(struct tasklet_struct *t);
#define tasklet_schedule(t) lx_tasklet_schedule(t)
#define tasklet_kill(t) ((void)(t))
#define tasklet_disable(t) ((void)(t))
#define tasklet_enable(t) ((void)(t))

/* interrupts: the handler runs from the dispatcher after lx_irq_raise */
typedef int irqreturn_t;
#define IRQ_NONE 0
#define IRQ_HANDLED 1
#define IRQ_WAKE_THREAD 2
#define IRQF_SHARED 0x80
#define IRQF_NOBALANCING 0x800
#define IRQF_NO_SUSPEND 0
typedef irqreturn_t (*irq_handler_t)(int, void *);
int lx_request_irq(unsigned int irq, irq_handler_t h, irq_handler_t thread, unsigned long fl, const char *n, void *id);
void lx_free_irq(unsigned int irq, void *id);
void lx_irq_raise(unsigned int irq);
#define request_irq(i, h, f, n, d) lx_request_irq(i, h, 0, f, n, d)
#define request_threaded_irq(i, h, t, f, n, d) lx_request_irq(i, h, t, f, n, d)
#define free_irq(i, d) lx_free_irq(i, d)
#define enable_irq(i) ((void)(i))
#define disable_irq(i) ((void)(i))
#define disable_irq_nosync(i) ((void)(i))
#define synchronize_irq(i) ((void)(i))
#define irq_set_affinity_hint(i, m) 0
#define in_interrupt() 0
#define in_irq() 0

/* DMA: buffers come from a window the endpoint's IOMMU stream maps; the platform hook returns the bus address */
enum dma_data_direction { DMA_BIDIRECTIONAL = 0, DMA_TO_DEVICE = 1, DMA_FROM_DEVICE = 2, DMA_NONE = 3 };
void *lx_dma_alloc(struct device *d, size_t n, dma_addr_t *bus);
void lx_dma_free(struct device *d, size_t n, void *p, dma_addr_t bus);
dma_addr_t lx_dma_map(struct device *d, void *p, size_t n, int dir);
void lx_dma_sync(struct device *d, dma_addr_t bus, size_t n, int dir);
#define dma_alloc_coherent(d, n, h, f) lx_dma_alloc(d, n, h)
#define dma_free_coherent(d, n, p, h) lx_dma_free(d, n, p, h)
#define dma_map_single(d, p, n, dir) lx_dma_map(d, p, n, dir)
#define dma_unmap_single(d, h, n, dir) lx_dma_sync(d, h, n, dir)
#define dma_mapping_error(d, h) ((h) == 0)
#define dma_sync_single_for_cpu(d, h, n, dir) lx_dma_sync(d, h, n, dir)
#define dma_sync_single_for_device(d, h, n, dir) lx_dma_sync(d, h, n, dir)
#define DMA_BIT_MASK(n) ((n) == 64 ? ~0ULL : ((1ULL << (n)) - 1))
#define dma_set_mask_and_coherent(d, m) ((d)->dma_mask = (m), 0)
#define dma_set_mask(d, m) ((d)->dma_mask = (m), 0)
#define dma_set_coherent_mask(d, m) 0

/* firmware: served from files the platform provides */
struct firmware { const u8 *data; size_t size; };
int lx_request_firmware(const struct firmware **fw, const char *name);
void lx_release_firmware(const struct firmware *fw);
#define request_firmware(fw, n, d) lx_request_firmware(fw, n)
#define request_firmware_direct(fw, n, d) lx_request_firmware(fw, n)
#define release_firmware(fw) lx_release_firmware(fw)

/* id allocation */
struct ida { unsigned long bits[8]; };
#define DEFINE_IDA(n) struct ida n = { { 0 } }
int ida_alloc_range(struct ida *i, unsigned int lo, unsigned int hi, gfp_t f);
void ida_free(struct ida *i, unsigned int id);
#define ida_alloc(i, f) ida_alloc_range(i, 0, 511, f)
#define ida_simple_get(i, lo, hi, f) ida_alloc_range(i, lo, (hi) - 1, f)
#define ida_simple_remove(i, id) ida_free(i, id)





#define U8_MAX 0xffu
#define U16_MAX 0xffffu
#define S16_MAX 0x7fff
#define S32_MAX 0x7fffffff
#define ETOOSMALL 525
#define __cpu_to_le16(x) cpu_to_le16(x)
#define __cpu_to_le32(x) cpu_to_le32(x)
#define __cpu_to_le64(x) cpu_to_le64(x)
#define __le16_to_cpu(x) le16_to_cpu(x)
#define __le32_to_cpu(x) le32_to_cpu(x)
#define __le64_to_cpu(x) le64_to_cpu(x)
/* idr: ids index a growable pointer array */
struct idr { void **slot; unsigned int cap; unsigned int next; };
void idr_init(struct idr *i);
void idr_destroy(struct idr *i);
int idr_alloc(struct idr *i, void *p, int start, int end, gfp_t f);
int idr_alloc_cyclic(struct idr *i, void *p, int start, int end, gfp_t f);
void *idr_find(const struct idr *i, unsigned long id);
void *idr_remove(struct idr *i, unsigned long id);
int idr_for_each(const struct idr *i, int (*fn)(int id, void *p, void *data), void *data);
#define DEFINE_IDR(n) struct idr n = { 0, 0, 0 }
#define idr_preload(f)
#define idr_preload_end()
#endif
