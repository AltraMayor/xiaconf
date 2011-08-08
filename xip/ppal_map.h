#ifndef HEADER_PPAL_MAP_H
#define HEADER_PPAL_MAP_H

#include <net/xia.h>

/* It is assumed to be greater than, or equal to 4; it includes '\0'. */
#define MAX_PPAL_NAME_SIZE	32

/* init_ppal_map - starts the library. Essentially, it just loads the map
 * from disk into memory.
 * RETURN
 *	Return zero on success, and a negative number on failure.
 */
int init_ppal_map(void);

/* ppal_name_to_type - provides the principal type for @name.
 * If @name is not in the map, it returns XIDTYPE_NAT.
 */
xid_type_t ppal_name_to_type(const __u8 *name);

#endif /* HEADER_PPAL_MAP_H */
