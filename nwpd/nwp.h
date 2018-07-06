#ifndef _NWP_H
#define _NWP_H

#include <net/xia_fib.h>
#include <xia_socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#define ETH_P_NWP 0xC0DF

#define NWP_ANNOUNCEMENT 0x01

struct nwp_common_hdr {
        uint8_t version;
        uint8_t type;
};

struct nwp_announce {
        struct nwp_common_hdr common;
        uint8_t hid_count;
        uint8_t haddr_len;
        uint8_t *haddr;
        uint8_t *addr_begin;
};

#define NWP_ANNOUNCEMENT_GET_HID(ann, n) (ann)->addr_begin + ((n)*XIA_XID_MAX)

extern bool read_announce(char *, struct nwp_announce *, int);
extern void announce_set_ha(struct nwp_announce *, uint8_t *);
extern void announce_add_xid(struct nwp_announce *, uint8_t *);
extern int announce_size(struct nwp_announce *);
extern void announce_free(struct nwp_announce *);

#define NWP_NEIGHBOUR_LIST 0x02

struct nwp_neigh_list {
        struct nwp_common_hdr common;
        uint8_t hid_count;
        uint8_t haddr_len;

        struct nwp_neighbor **addrs;
};

struct nwp_neighbor {
        char xid[XIA_XID_MAX];
        uint8_t num;
        uint8_t **haddrs;
};

extern bool read_neighbor_list(char *, struct nwp_neigh_list *, int);
extern void neighbor_list_free(struct nwp_neigh_list *);

/* Monitoring packets */

#define NWP_MONITOR_PING 0x03
#define NWP_MONITOR_ACK 0x04

struct nwp_monitor {
        struct nwp_common_hdr common;
        uint8_t haddr_len;
        uint8_t reserved;

        int32_t sender_clock;

        /* Sender and Host Hardware Addresses*/
        uint8_t *haddr_src;
        uint8_t *haddr_dest;
};

extern bool read_monitor(char *, struct nwp_monitor *, int);
extern void monitor_free(struct nwp_monitor *);

#define NWP_MONITOR_PING_REQUEST 0x05
#define NWP_MONITOR_INVESTIGATE_PING 0x06

struct nwp_monitor_investigate {
        struct nwp_common_hdr common;
        uint8_t haddr_len;
        uint8_t reserved;

        int32_t sender_clock;

        uint8_t *haddr_src;
        uint8_t *haddr_dest;
        uint8_t *haddr_investigate; /* The host being investigated */
};

#endif	/* _NWP_H */
