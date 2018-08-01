#ifndef _MONITOR_H
#define _MONITOR_H

#include <inttypes.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <net/xia.h>

#include "uthash.h"

#include "nwp.h"

struct host_clock {
        char *haddr; /* same pointer as addr->sll_addr */
        pthread_rwlock_t lock;
        struct sockaddr_ll *addr;
        struct xia_xid *xid;
        int32_t clock;
        bool waiting_for_ack;
        bool waiting_for_investigative_ack;
        timer_t timeout;
        UT_hash_handle hh;
};

extern void init_monitor();
extern void monitor_add_host(struct sockaddr_ll *, struct xia_xid *);
extern void send_monitor(int, struct sockaddr_ll *, uint8_t,  char *, char *);
extern void send_monitor_investigate(int, struct sockaddr_ll *, uint8_t, char *,
                                     char *, char *);
extern void process_monitor(struct sockaddr_ll *, struct nwp_monitor *);
extern void process_monitor_investigate(struct sockaddr_ll *,
                                        struct nwp_monitor_investigate *);
#endif
