#include <libmnl/libmnl.h>
#include <event2/thread.h>
#include <event2/event.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <time.h>
#include <linux/rtnetlink.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "nwp.h"
#include "rtnl.h"

struct mnl_socket *xia_nl_socket;
int subs;

struct sockaddr_ll broadcast_addr;
int broadcast_socket;

uint8_t if_hwaddr[ETH_ALEN];

struct ctxt {
        char *dev;
        int fd;
        socklen_t addr_len;
        struct sockaddr_ll addr;
        struct nwp_common_hdr common;
};

struct route {
        char dst_xid[XIA_XID_MAX];
        char gw_xid[XIA_XID_MAX];
};

struct routes {
        struct route **routes;
        int n;
};

struct ctxt *new_ctxt (char *dev) {
        struct ctxt *ctxt = malloc(sizeof(struct ctxt));
        ctxt->dev = dev;
        return ctxt;
}

void init_broadcast(int ifindex)
{
        int i;
        broadcast_addr.sll_family = AF_PACKET;
        broadcast_addr.sll_protocol = htons(ETH_P_NWP);
        broadcast_addr.sll_halen = ETH_ALEN;
        broadcast_addr.sll_ifindex = ifindex;
        for (i = 0; i < ETH_ALEN; i++) {
                broadcast_addr.sll_addr[i] = 0xFF;
        }

        broadcast_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_NWP));
        if (broadcast_socket == -1) {
                perror("socket");
                exit(1);
        }
}

void modify_neighbour (struct xia_xid *dst, bool add)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        struct rtmsg *rtm;
        nlh = mnl_nlmsg_put_header(buf);
        rtm = mnl_nlmsg_put_extra_header(nlh, sizeof (struct rtmsg));
        nlh->nlmsg_seq = time(NULL);
        if (add) {
                nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
                nlh->nlmsg_type = RTM_NEWROUTE;
                rtm->rtm_scope = RT_SCOPE_LINK;
        } else {
                nlh->nlmsg_flags = NLM_F_REQUEST;
                nlh->nlmsg_type = RTM_DELROUTE;
                rtm->rtm_scope = RT_SCOPE_NOWHERE;
        }

        rtm->rtm_family = AF_XIA;
        rtm->rtm_table = XRTABLE_MAIN_INDEX;
        rtm->rtm_protocol = RTPROT_BOOT;
        rtm->rtm_type = RTN_UNICAST;
        rtm->rtm_dst_len = sizeof(struct xia_xid);

        mnl_attr_put(nlh, RTA_DST, sizeof(struct xia_xid), dst);

        if (rtnl_talk(xia_nl_socket, nlh, nlh->nlmsg_len) == -1) 
                fprintf(stderr, "modify_neighbour: Couldn't modify neighbour entry\n");        
}

/* src should be an AD XID, dst an Ether XID */
void modify_route(struct xia_xid *src, struct xia_xid *dst)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof (struct rtmsg));

        nlh->nlmsg_seq = time(NULL);
        if (dst) {
                nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
                nlh->nlmsg_type = RTM_NEWROUTE;
                rtm->rtm_scope = RT_SCOPE_LINK;
        } else {
                nlh->nlmsg_flags = NLM_F_REQUEST;
                nlh->nlmsg_type = RTM_DELROUTE;
                rtm->rtm_scope = RT_SCOPE_NOWHERE;
        }

        rtm->rtm_family = AF_XIA;
        rtm->rtm_table = XRTABLE_MAIN_INDEX;
        rtm->rtm_protocol = RTPROT_BOOT;
        rtm->rtm_type = RTN_UNICAST;
        rtm->rtm_dst_len = sizeof(struct xia_xid);
        
        mnl_attr_put(nlh, RTA_DST, sizeof(struct xia_xid), dst);
        if (dst)
                mnl_attr_put(nlh, RTA_GATEWAY, sizeof(*dst), dst);

        
        if (mnl_socket_sendto(xia_nl_socket, nlh, nlh->nlmsg_len) < 0) {
                perror("mnl_socket_sendto");
        }
}

/* Based on xip/xipad.c:print_route */
void get_ad_ether_routes(struct nlmsghdr *n, void *arg)
{
        struct routes *routes = (struct route *)arg;
        if (mnl_nlmsg_ok(n, n->nlmsg_len)) {
                fprintf(stderr, "Received an invalid/truncated message\n");
                return;
        }
}

static int form_ether_xid(unsigned int oif, unsigned char *lladdr,
			  unsigned int tlen, char *id)
{
	int rc;

	rc = snprintf(id, tlen,
			"%08x%02x%02x%02x%02x%02x%02x%020x", oif,
			lladdr[0], lladdr[1], lladdr[2], lladdr[3], lladdr[4],
			lladdr[5], 0);
	if(rc <= 0 || rc >= tlen)
		return -1;
	return 0;
}

void announce()
{
        char nwp_write_buf[1500];
        struct xia_xid if_xid;
        char strid[XIA_MAX_STRID_SIZE];

        struct nwp_announce *ann = (struct nwp_announce *)&nwp_write_buf[0];
        ann->common.type = NWP_ANNOUNCEMENT;
        ann->common.version = 0x01;
        ann->haddr_len = ETH_ALEN;
        
        ann->haddr = (uint8_t *)(&ann->haddr_len + sizeof(uint8_t));
        ann->addr_begin = (uint8_t *)(ann->haddr + ann->haddr_len);

        if (form_ether_xid(broadcast_addr.sll_ifindex, if_hwaddr, sizeof(strid),
                           strid) == -1) {
                fprintf(stderr, "Cannot form ether XID\n");
                exit(1);
        }

        assert(!ppal_name_to_type("ad", &(if_xid.xid_type)));
        assert(xia_ptoid(strid, INT_MAX, &if_xid) > 0);
        announce_set_ha(ann, if_hwaddr);
        announce_add_xid(ann, if_xid.xid_id);

        int size = announce_size(ann);
        printf("announce size: %d\n", size);
        if (sendto(broadcast_socket, ann, size, 0,
                   (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)) == -1) {
                perror("sendto");
                exit(1);
        }
}

void *ether_receiver(void *ptr)
{
        struct ctxt *ctxt = (struct ctxt *)ptr;

        char *nwp_buf[1500];
        struct nwp_common_hdr *nwp_common = (struct nwp_common_hdr *)nwp_buf;

        char if_xid[XIA_MAX_STRID_SIZE];
        int if_index, sockopt, sock;

        if ((sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_NWP))) == -1) {
                perror("socket");
                exit(1);
        }

        {
                struct ifreq ifr;
                strncpy(ifr.ifr_name, ctxt->dev, IFNAMSIZ-1);
                ioctl(sock, SIOCGIFHWADDR, &ifr);
                memcpy(if_hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
                ioctl(sock, SIOCGIFINDEX, &ifr);
                if_index = ifr.ifr_ifindex;
                init_broadcast(if_index);
                ifr.ifr_flags |= IFF_PROMISC;
                if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
                        perror("SIOCSIFFLAGS");
                        exit(1);
                }
        }

        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) {
                perror("SO_REUSEADDR");
                close(sock);
                exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ctxt->dev, IFNAMSIZ-1) == -1) {
                perror("SO_BINDTODEVICE");
                close(sock);
                exit(1);
        }

        if (form_ether_xid(if_index, (unsigned char *)if_hwaddr, sizeof(if_xid), if_xid)) {
                fprintf(stderr, "Could not form ether XID\n");
                exit(1);
        }

        announce();
        ctxt->fd = sock;
        printf("Listening on ether-%s\n", if_xid);
        while(1) {
                printf("Reading\n");
                struct sockaddr_ll addr;
                socklen_t addr_len = sizeof(struct sockaddr_ll);
                int msglen;

                if ((msglen = recvfrom(ctxt->fd, nwp_buf, 1500, 0, (struct sockaddr *)&addr,
                             &addr_len)) == -1) {
                        perror("recvfrom");
                        exit(1);
                }
                msglen -= sizeof(struct ether_header);

                printf("Got NWP Packet type %d, size: %d bytes\n", nwp_common->type, msglen);
                switch (nwp_common->type) {
                case NWP_ANNOUNCEMENT:
                {
                        char if_ether_xid[XIA_MAX_STRID_SIZE];
                        struct nwp_announce *announce = (struct nwp_announce *)nwp_buf;
                        printf("Received an announcement packet\n");
                        if (!announce_validate(announce, msglen)) {
                                printf("invalid NWP announce packet, discarding\n");
                                continue;
                        }
                        printf("GOOD packet HID count: %d, Haddr len: %d\n",
                               announce->hid_count,
                               announce->haddr_len);

                        if (announce->hid_count != 1) {
                                printf("announce packet has more than one HID, discarding packet\n");
                                continue;
                        }

                        struct xia_xid xid;
                        printf("forming XID\n");
                        if (form_ether_xid(addr.sll_ifindex, addr.sll_addr,
                                           sizeof(if_ether_xid), if_ether_xid)) {
                                printf("Could not form ether XID for the address\n");
                                continue;
                        }
                        assert(!ppal_name_to_type("ether", &xid.xid_type));
                        printf("no issue here\n");
                        if (xia_ptoid(if_ether_xid, INT_MAX, &xid) == -1) {
                                printf("Invalid ether XID: %s", if_ether_xid);
                                continue;
                        }
                        printf("Adding neighbour ether-%s\n",if_ether_xid);
                        modify_neighbour(&xid, true);
                        break;
                }
                case NWP_NEIGHBOUR_LIST:
                {
                        struct nwp_neigh_list *neigh = (struct nwp_neigh_list *)nwp_buf;
                        neigh->addr_begin = (uint8_t *)neigh
                                + offsetof(struct nwp_neigh_list, addr_begin);
                        printf("Received a neighbour list packet\n");
                        if (!neigh_list_validate(neigh, msglen)) {
                                printf("invalid NWP neighbour list packet, discarding\n");
                                continue;
                        }
                        printf("GOOD packet HID count: %d, Haddr len: %d\n",
                               neigh->hid_count,
                               neigh->haddr_len);
                        break;
                }
                case NWP_MONITOR_PING:
                {
                        break;
                }
                case NWP_MONITOR_ACK:
                {
                        break;
                }
                case NWP_MONITOR_PING_REQUEST:
                {
                        break;
                }
                case NWP_MONITOR_INVESTIGATE_PING:
                {
                        break;
                }
                default:
                        printf("Unknown NWP packet type: %d\n", nwp_common->type);
                }
        }
}

int main(int argc, char **argv)
{
        xia_nl_socket = mnl_socket_open(NETLINK_ROUTE);
        mnl_socket_bind(xia_nl_socket, subs, getppid());
        setvbuf(stdout, NULL, _IOLBF, 0);
        printf("nwpd v0.1\n");
        if (argc < 2) {
                fprintf(stderr, "interface not specified, exiting\n");
                exit(1);
        }

        assert(!init_ppal_map(NULL));

        pthread_t receiver;

        struct ctxt *ctxt = new_ctxt(argv[1]);
        pthread_create(&receiver, NULL, ether_receiver, ctxt);
        pthread_join(receiver, NULL);

        mnl_socket_close(xia_nl_socket);
        return 0;
}
