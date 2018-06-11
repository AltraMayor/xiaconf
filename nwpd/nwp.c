#include "nwp.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

bool announce_validate(struct nwp_announce *packet, int msglen)
{
        size_t elem_len = sizeof(struct nwp_common_hdr)
                + sizeof(uint8_t)
                + sizeof(uint8_t);
        if (msglen < elem_len)
                return false;

        packet->haddr = (uint8_t *)(packet +
                                      offsetof(struct nwp_announce, haddr));
        packet->addr_begin = (uint8_t **)(packet->haddr
                                            + packet->haddr_len);
        return ((elem_len + XIA_XID_MAX * packet->hid_count + packet->haddr_len)
                 <= msglen);
}

bool neigh_list_validate(struct nwp_neigh_list *packet, int msglen)
{
        size_t size = sizeof(struct nwp_common_hdr)
                + sizeof(uint8_t)
                + sizeof(uint8_t);
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
