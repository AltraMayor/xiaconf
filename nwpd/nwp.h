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
extern int announce_size(struct nwp_announce *packet);

#define NWP_NEIGHBOUR_LIST 0x02

struct nwp_neigh_list {
        struct nwp_common_hdr common;
        uint8_t hid_count;
        uint8_t haddr_len;

        uint8_t *addr_begin;
        /* With Ether addresses, the format will be
           ETH_XID_1 1 HA_1
           ETH_XID_2 1 HA_2
           ...
           ETH_XID_(hid_count) 1 HA_(hid_count)
        */
};

struct nwp_neighbor {
        char xid[XIA_XID_MAX];
        uint8_t num;
        uint8_t *ha_begin;
};

extern bool neigh_list_validate(struct nwp_neigh_list *, int);

/* Monitoring packets */

#define NWP_MONITOR_PING 0x03
#define NWP_MONITOR_ACK 0x04

struct nwp_monitor {
        struct nwp_common_hdr common;
        uint8_t haddr_len;
        uint8_t reserved;

        int32_t sender_clock;

        /* Sender and Host Hardware Addresses*/
        uint8_t addr_begin[0];
};

#define NWP_MONITOR_PING_REQUEST 0x05
#define NWP_MONITOR_INVESTIGATE_PING 0x06

struct nwp_monitor_investigate {
        struct nwp_common_hdr common;
        uint8_t haddr_len;
        uint8_t reserved;

        int32_t sender_clock;
        
        /* Sender, Host and Investigative Host Hardware Addresses*/
        uint8_t addr_begin[0];
};

#endif	/* _NWP_H */
