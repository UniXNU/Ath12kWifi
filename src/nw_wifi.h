#ifndef NW_WIFI_H
#define NW_WIFI_H
#include "lx_plat.h"
#include "nw_board.h"
struct nw_wifi_stats { u32 stage; u32 scans; u32 frames; u32 beacons; u32 bss_seen; int last_err; };
extern struct nw_wifi_stats nw_wifi_stats;
/* Brings up the runtime and the driver stack; returns 0 when started (progress continues from nw_wifi_step). */
int nw_wifi_start(const struct lx_platform *p, const struct nw_board *b);
/* Runs one round of the dispatcher; the platform calls this from its event loop. */
int nw_wifi_step(void);
void nw_wifi_stop(void);
#endif
