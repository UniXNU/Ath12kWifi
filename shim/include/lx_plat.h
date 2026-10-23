/* What the platform below the Linux-derived code must provide. */
#ifndef LX_PLAT_H
#define LX_PLAT_H
#include "lx_os.h"
struct lx_platform {
  u64 (*now_ms)(void);
  void (*sleep_ms)(unsigned int ms);        /* advance time by ms (idle) */
  void (*poll)(void);                       /* gather device events; may call lx_irq_raise */
  void (*log)(int level, const char *line);
  void (*halt)(void);
  void *(*alloc)(size_t n);
  void (*free)(void *p);
  void *(*dma_alloc)(size_t n, dma_addr_t *bus);
  void (*dma_free)(size_t n, void *p, dma_addr_t bus);
  dma_addr_t (*dma_map)(void *p, size_t n, int dir);
  void (*dma_sync)(dma_addr_t bus, size_t n, int dir);
  int (*fw_get)(const char *name, const u8 **data, size_t *size);
};
extern const struct lx_platform *lx_plat;
void lx_root_init(void);
#endif
