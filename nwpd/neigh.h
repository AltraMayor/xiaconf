#ifndef _NEIGH_H
#define _NEIGH_H

#include <net/xia.h>
#include <stdbool.h>
#include <linux/if_packet.h>

extern void modify_neighbour(struct xia_xid *, bool);
extern void modify_route(const struct xia_xid *, const struct xia_xid *);
extern void send_announce(int, struct sockaddr_ll *);

#endif /* _NEIGH_H */
