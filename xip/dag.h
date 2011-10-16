#ifndef HEADER_DAG_H
#define HEADER_DAG_H

#include <stdio.h>
#include <net/xia.h>

/** xia_pton - Convert a string that represents an XIA addressesng into
 *	binary (network) form.
 * It doesn't not require the string @src to be terminated by '\0'.
 * If @ignore_ce is true, the chosen edges are not marked in @dst.
 * 	It's useful to obtain an address that will be used in a header.
 * @invalid_flag is set true if '!' begins the string;
 * 	otherwise it is set false.
 * RETURN
 * 	-1 if the string can't be converted.
 *	Number of parsed chars, not couting trailing '\0' if it exists.
 * NOTES
 *	Even if the function is successful, the address may
 *	still be invalid according to xia_test_addr.
 *	INT_MAX<limits.h> could be passed in srclen if src includes a '\0'.
 *
 * IMPORTANT
 *	init_ppal_map<ppal_map.h> must be called first before this function
 *	in order to recognize principal names!
 */
int xia_pton(const char *src, size_t srclen, struct xia_addr *dst,
		int ignore_ce, int *invalid_flag);

/** xia_ptoxid - works as xia_pton, but only parses a single XID. */
int xia_ptoxid(const char *src, size_t srclen, struct xia_xid *dst);

/** xia_ptoid - works as xia_ptoxid, but only parses a single ID.
 *  NOTE
 *	dst->xid_type is not modified.
 */
int xia_ptoid(const char *src, size_t srclen, struct xia_xid *dst);

#endif /* HEADER_DAG_H */
