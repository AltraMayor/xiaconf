#ifndef _XIA_SOCKET_H
#define _XIA_SOCKET_H

/* This file is intended to help application developers to integrate XIA
 * into their applications.
 *
 * As XIA become integrated, we expect that some of the definitions here
 * will migrate to kernel headers and C library.
 */

#include <net/xia.h>
#include <net/xia_dag.h>
#include <ppal_map.h>

#define AF_XIA		41	/* eXpressive Internet Architecture */
#define PF_XIA		AF_XIA

#define XDP_CORK	1

#endif /* _XIA_SOCKET_H */
