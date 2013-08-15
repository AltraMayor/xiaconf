#ifndef _XIART_H
#define _XIART_H

/* XIA RT is meant to provide common route netlink functions to all principals
 * to reduce the cost of developing an extension for application xip, and
 * increase code reuse.
 */

#include <net/xia.h>

/* Function to help reading XIDs and ID. */
typedef int (*help_func_t)(void);
void xrt_get_ppalty_id(xid_type_t ppal_ty, help_func_t usage,
	struct xia_xid *dst, const char *s);
void xrt_get_ppal_id(const char *ppal, help_func_t usage, struct xia_xid *dst,
	const char *s);
void xrt_get_xid(help_func_t usage, struct xia_xid *dst, const char *s);

/* Functions to implement routing redirects. */
int xrt_modify_route(const struct xia_xid *dst, const struct xia_xid *gw);
int xrt_list_rt_redirects(__u32 tbl_id, xid_type_t ppal_ty);

#endif	/* _XIART_H */
