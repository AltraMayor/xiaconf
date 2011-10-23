#ifndef HEADER_PPAL_MAP_H
#define HEADER_PPAL_MAP_H

#include <net/xia.h>

/* load_ppal_map - Load the principal map from disk into memory.
 * RETURN
 *	Return zero on success, and a negative number on failure.
 */
int init_ppal_map(void);

/* Simple function to print out an XIA address. */
void print_xia_addr(const struct xia_addr *addr);

/* Simple function to print out an XID. */
void print_xia_xid(const struct xia_xid *xid);

#endif /* HEADER_PPAL_MAP_H */
