/* Small kernel helpers and stubs that only the ath11k sources use; this board has no device tree and no DMI table. */
#ifndef LX_ATH11K_H
#define LX_ATH11K_H
#include <lx_pci.h>
#include <lx_os.h>
static inline u32 swab32(u32 x) { return __builtin_bswap32(x); }
static inline void memset32(u32 *p, u32 v, size_t n) { while (n--) *p++ = v; }
#define prefetch(p) ((void)(p))
#define of_machine_is_compatible(c) ((void)(c), 0)
#define of_find_node_by_type(f, t) ((void)(f), (void)(t), (struct device_node *)0)
#define of_property_present(np, n) ((void)(np), (void)(n), 0)
/* the board's address (nw_board.mac) when it gives one; ath11k then prefers it to the zero the firmware reports without OTP */
int nw_board_mac_address(u8 *a);
#define device_get_mac_address(d, a) ((void)(d), nw_board_mac_address(a))
#define dma_alloc_noncoherent(d, n, h, dir, f) lx_dma_alloc(d, n, h)
#define dma_free_noncoherent(d, n, p, h, dir) lx_dma_free(d, n, p, h)
typedef unsigned long kernel_ulong_t;
#define resource_size(r) ((r)->end - (r)->start + 1)
/* placeholder: this board has no device tree, so the reserved host memory region is not looked up here yet */
#define of_reserved_mem_region_to_resource(np, i, res) ((void)(np), (void)(i), (void)(res), -ENODEV)
#define devm_ioremap(d, pa, n) ((void)(d), lx_ioremap(pa, n))
/* debug dumps only: hex bytes of one row, optionally followed by their printable characters; never writes past linebuflen */
static inline int hex_dump_to_buffer(const void *buf, size_t len, int rowsize, int groupsize, char *linebuf, size_t linebuflen, bool ascii)
{
	const u8 *p = buf; size_t i, o = 0, n = len < (size_t)rowsize ? len : (size_t)rowsize;
	static const char hx[] = "0123456789abcdef";
	(void)groupsize;
	if (!linebuflen) return 0;
	for (i = 0; i < n && o + 3 < linebuflen; i++) { linebuf[o++] = hx[p[i] >> 4]; linebuf[o++] = hx[p[i] & 15]; linebuf[o++] = ' '; }
	if (ascii) {
		for (; i < (size_t)rowsize && o + 3 < linebuflen; i++) { linebuf[o++] = ' '; linebuf[o++] = ' '; linebuf[o++] = ' '; }
		if (o + 1 < linebuflen) linebuf[o++] = ' ';
		for (i = 0; i < n && o + 1 < linebuflen; i++) linebuf[o++] = (p[i] >= 0x20 && p[i] < 0x7f) ? (char)p[i] : '.';
	}
	linebuf[o] = 0;
	return (int)o;
}
#endif
