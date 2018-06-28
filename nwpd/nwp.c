#include "nwp.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

bool read_announce(char *buf, struct nwp_announce *packet, int msglen)
{
        size_t elem_len = sizeof(struct nwp_common_hdr)
                + sizeof(uint8_t)
                + sizeof(uint8_t);
        size_t data_len = packet->haddr_len + XIA_XID_MAX * packet->hid_count;
        if (elem_len + data_len > msglen)
                return false;

        memcpy(packet, buf, elem_len);

        buf = buf + elem_len;
        packet->haddr = malloc(packet->haddr_len);
        memcpy(packet->haddr, buf, packet->haddr_len);

        buf = buf + packet->haddr_len;
        packet->addr_begin = malloc(XIA_XID_MAX * packet->hid_count);
        memcpy(packet->addr_begin, buf, XIA_XID_MAX * packet->hid_count);
        return true;
}

void announce_set_ha(struct nwp_announce *packet, uint8_t *ha)
{
        assert(packet->haddr_len != 0);
        memmove(packet->haddr, ha, packet->haddr_len);
} 

void announce_add_xid(struct nwp_announce *packet, uint8_t *xid)
{
        memmove(packet->addr_begin + ((packet->hid_count++) * XIA_XID_MAX),
                xid, XIA_XID_MAX);
}

int announce_size(struct nwp_announce *packet)
{
        return sizeof(struct nwp_common_hdr) + 2*sizeof(uint8_t)
                + packet->haddr_len + packet->hid_count * XIA_XID_MAX;
}

bool neigh_list_validate(struct nwp_neigh_list *packet, int msglen)
{
        size_t size = sizeof(struct nwp_common_hdr)
                + sizeof(uint8_t)
                + sizeof(uint8_t);
        packet->addr_begin = (uint8_t *)packet + offsetof(struct nwp_neigh_list, addr_begin);
        int i;
        uint8_t *addr = packet->addr_begin + 1;

        for (i = 0; i < packet->hid_count; i++) {
                if (msglen < ((char *)addr - (char *)packet + 1))
                        return false;
                size += XIA_XID_MAX + sizeof(uint8_t);
                uint8_t num_ha = (uint8_t)*addr++;
                size += packet->haddr_len * num_ha;
                addr += packet->haddr_len * num_ha;
        }
        return size <= msglen;
}

void neigh_list_add_neigh(struct nwp_neigh_list *packet, char *xid,
                          uint8_t ha_num, char **ha)
{
        struct nwp_neighbor *neigh = (struct nwp_neighbor *)packet->addr_begin;
        uint8_t i;
        size_t ha_size = neigh->num * packet->haddr_len;

        for (i = 0; packet->hid_count; i++) {
                neigh += (XIA_XID_MAX + sizeof(uint8_t) + ha_size);
        }

        memmove(neigh->xid, xid, XIA_XID_MAX);
        neigh->num = ha_num;
        memmove(neigh->ha_begin, ha, ha_size);
}
