/* What the board code provides to the PCI layer of the WiFi driver. */
#ifndef NW_BOARD_H
#define NW_BOARD_H
#include "lx_os.h"
struct nw_board {
  void *bar; size_t bar_len;                         /* register window of the endpoint, mapped */
  u16 device_id, msi_cap; int irq_base;              /* PCI device id; offset of the MSI capability; first irq number given to vectors */
  int (*cfg_read)(int off, int size, u32 *v);        /* config space; offsets with bit 31 set are inside the PCIe capability */
  int (*cfg_write)(int off, int size, u32 v);
  int (*msi_target)(u32 *lo, u32 *hi, u32 *data);    /* where the endpoint writes to raise vector 0 */
  void *(*map_phys)(phys_addr_t pa, size_t n);
};
extern const struct nw_board *nw_board;
#endif
