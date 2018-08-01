#ifndef _NEIGH_H
#define _NEIGH_H

#include <net/xia.h>
#include <stdbool.h>

extern void modify_neighbour(struct xia_xid *, bool);
extern void modify_route(const struct xia_xid *, const struct xia_xid *);

#endif /* _NEIGH_H */
