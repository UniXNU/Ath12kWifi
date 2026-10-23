/* The boundary between the board code and the WiFi module: what the board provides, and the calls into the module. Plain C types only. */
#ifndef NW_ABI_H
#define NW_ABI_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
struct lx_platform {
  uint64_t (*now_ms)(void);
  void (*sleep_ms)(unsigned int ms);        /* let the clock advance while nothing is ready */
  void (*poll)(void);                       /* gather device events */
  void (*log)(int level, const char *line);
  void (*halt)(void);
  void *(*alloc)(size_t n);
  void (*free)(void *p);
  void *(*dma_alloc)(size_t n, uint64_t *bus);     /* zeroed memory the endpoint reaches at *bus */
  void (*dma_free)(size_t n, void *p, uint64_t bus);
  uint64_t (*dma_map)(void *p, size_t n, int dir); /* bus address of memory that lies in the DMA window, 0 if it does not */
  void (*dma_sync)(uint64_t bus, size_t n, int dir);
  int (*fw_get)(const char *name, const uint8_t **data, size_t *size);   /* firmware file by its last path component */
};
struct nw_board {
  void *bar; size_t bar_len;                         /* register window of the endpoint, mapped */
  uint16_t device_id, msi_cap; int irq_base;         /* PCI device id; offset of the MSI capability; first irq number given to vectors */
  int (*cfg_read)(int off, int size, uint32_t *v);   /* config space; offsets with bit 31 set are inside the PCIe capability */
  int (*cfg_write)(int off, int size, uint32_t v);
  int (*msi_target)(uint32_t *lo, uint32_t *hi, uint32_t *data);   /* where the endpoint writes to raise vector 0 */
  void *(*map_phys)(uint64_t pa, size_t n);
};
struct nw_wifi_stats { uint32_t stage, scans, frames, beacons, bss_seen; int last_err; };
int nw_wifi_start(const struct lx_platform *p, const struct nw_board *b);
int nw_wifi_step(void);
void nw_wifi_stop(void);
extern struct nw_wifi_stats nw_wifi_stats;
#ifdef __cplusplus
}
#endif
#endif
