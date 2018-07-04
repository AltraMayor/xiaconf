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
#include <net/xia.h>

#include "nwp.h"
#include "rtnl.h"

struct mnl_socket *xia_nl_socket;
int subs;

struct sockaddr_ll broadcast_addr;
int eth_socket;

uint8_t if_hwaddr[ETH_ALEN];

struct ctxt {
        char *dev;
        int fd;
        socklen_t addr_len;
        struct sockaddr_ll addr;
        struct nwp_common_hdr common;
};

struct route {
        uint8_t dst_xid[XIA_XID_MAX];
        uint8_t gw_xid[XIA_XID_MAX];
};

struct routes {
        struct route **routes;
        int n;
        int table;

        struct xia_xid *dst;
        struct xia_xid *gw;

        xid_type_t dst_type;
        xid_type_t gw_type;
};

struct ctxt *new_ctxt (char *dev) {
        struct ctxt *ctxt = malloc(sizeof(struct ctxt));
        ctxt->dev = dev;
        return ctxt;
}

void send_neigh_list(int socket, struct sockaddr_ll *addr, int haddr_len);

struct routes *create_filter(int table_index)
{
        struct routes *routes = calloc(1, sizeof(struct routes));
        if (!routes) {
                perror("malloc");
                exit(1);
        }
        routes->table = table_index;
        return routes;
}

void free_filter(struct routes *routes)
{
        int i;
        for (i = 0; i < routes->n; i++) {
                free(routes->routes[i]);
        }
        free(routes->routes);
        free(routes);
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

        eth_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_NWP));
        if (eth_socket == -1) {
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

        if (rtnl_talk(xia_nl_socket, nlh) == -1)
                fprintf(stderr, "modify_neighbour: Couldn't modify neighbour entry\n");
}

/* dst should be an AD XID, gw an Ether XID */
void modify_route(const struct xia_xid *dst, const struct xia_xid *gw)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        struct rtmsg *rtm = mnl_nlmsg_put_extra_header(nlh, sizeof (struct rtmsg));

        nlh->nlmsg_seq = time(NULL);
        if (gw) {
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
        if (gw)
                mnl_attr_put(nlh, RTA_GATEWAY, sizeof(*gw), gw);

        if (rtnl_talk(xia_nl_socket, nlh) == -1)
                fprintf(stderr, "modify_route: Couldn't modify route entry\n");
}

/* Based on xip/xipad.c:print_route */
void filter_callback(struct nlmsghdr *n, void *arg)
{
        int len = n->nlmsg_len;
        uint32_t table;
        struct routes *routes = (struct routes *)arg;
        const struct xia_xid *dst = NULL, *gw = NULL;
        struct rtattr *tb[RTA_MAX+1];
        struct rtmsg *r = mnl_nlmsg_get_payload(n);

        if (!mnl_nlmsg_ok(n, n->nlmsg_len)) {
                fprintf(stderr, "Received an invalid/truncated message\n");
                return;
        }

        /* mnl_nlmsg_fprintf(stdout, n, n->nlmsg_len, mnl_nlmsg_get_payload_len(n)); */

        if (n->nlmsg_type != RTM_NEWROUTE) {
                fprintf(stderr, "Not a route: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
                return;
        }
        if (n->nlmsg_type == RTM_DELROUTE)
                return;
        if (r->rtm_family != AF_XIA) {
                return;
        }

        len -= NLMSG_LENGTH(sizeof(*r));
        if (len < 0) {
                fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return;
        }
        if (r->rtm_dst_len != sizeof(struct xia_xid)) {
		fprintf(stderr, "BUG: wrong rtm_dst_len %d\n", r->rtm_dst_len);
		return;
	}

        parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
        table = rtnl_get_table(r, tb);
        if (table != routes->table) {
                return;
        }

        if (!tb[RTA_DST] ||
            RTA_PAYLOAD(tb[RTA_DST]) != sizeof(struct xia_xid) ||
            r->rtm_dst_len != sizeof(struct xia_xid)) {
                return;
        }

        dst = (const struct xia_xid *)RTA_DATA(tb[RTA_DST]);

        if (dst->xid_type != routes->dst_type)
                return;
        if (routes->dst && !are_sxids_equal(routes->dst, dst))
                return;
        if (n->nlmsg_type == RTM_DELROUTE)
                return;

        if (tb[RTA_GATEWAY]) {
                assert(RTA_PAYLOAD(tb[RTA_GATEWAY]) == sizeof(struct xia_xid));
                gw = (const struct xia_xid *)RTA_DATA(tb[RTA_GATEWAY]);
                if (gw->xid_type != routes->gw_type)
                        return;
                if (routes->gw && !are_sxids_equal(gw, routes->gw))
                        return;

        }

        assert(!r->rtm_src_len);
	assert(!(r->rtm_flags & RTM_F_CLONED));

        int index = routes->n++;
        if (index == 0)
                routes->routes = calloc(routes->n, sizeof(struct route *));
        else
                routes->routes = realloc(routes->routes, routes->n * sizeof(struct route *));

        routes->routes[index] = calloc(1, sizeof(struct route));
        if (!routes->routes) {
                perror("malloc");
                exit(1);
        }
        if (gw)
                memcpy(routes->routes[index]->gw_xid, gw->xid_id, XIA_XID_MAX);
        memcpy(routes->routes[index]->dst_xid, dst->xid_id, XIA_XID_MAX);
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

void send_announce(int socket, struct sockaddr_ll *addr)
{
        /*routes contains all local ADs*/
        struct routes *routes = create_filter(XRTABLE_LOCAL_INDEX);
        assert(!ppal_name_to_type("ad", &routes->dst_type));
        assert(!ppal_name_to_type("ether", &routes->gw_type));

        int i, size, member_size;
        char *buf, *cur_buf;

        char strid[XIA_MAX_STRID_SIZE];

        if (form_ether_xid(addr->sll_ifindex, if_hwaddr, sizeof(strid),
                           strid) == -1) {
                fprintf(stderr, "Cannot form ether XID\n");
                exit(1);
        }

        if (rtnl_send_wilddump_request(xia_nl_socket, AF_XIA, RTM_GETROUTE,
                                       filter_callback, routes) == -1) {
                perror("rtnl_send_wilddump_request");
                exit(1);
        }

        struct nwp_announce ann;
        ann.common.type = NWP_ANNOUNCEMENT;
        ann.common.version = 0x01;
        ann.hid_count = routes->n;
        ann.haddr_len = ETH_ALEN;

        size = announce_size(&ann);

        buf = cur_buf = calloc(size, sizeof(char));
        member_size = sizeof(struct nwp_common_hdr) + 2*sizeof(uint8_t);
        memcpy(cur_buf, &ann, member_size);
        cur_buf += member_size;
        memcpy(cur_buf, if_hwaddr, ann.haddr_len);
        cur_buf += ann.haddr_len;

        for (i = 0; i < routes->n; i++) {
                memcpy(cur_buf, routes->routes[i]->dst_xid, XIA_XID_MAX);
                cur_buf += XIA_XID_MAX;
        }

        if (sendto(socket, buf, size, 0, (struct sockaddr *)addr,
                   sizeof(*addr)) == -1) {
                perror("sendto");
                return;
        }
        free(buf);
        free_filter(routes);
}

void *announce_loop(void *_arg)
{
        while(1) {
                send_announce(eth_socket, &broadcast_addr);
                sleep(5);
        }
}

void process_announce(struct sockaddr_ll *addr, struct nwp_announce *announce)
{
        char if_ether_xid_str[XIA_MAX_STRID_SIZE];
        int i;

        if (announce->hid_count > 1) {
                fprintf(stderr, "packet has more than one HID, discarding\n");
                return;
        }
        if (announce->haddr_len != addr->sll_halen) {
                fprintf(stderr, "hardware address length is different in the packet and the sender's sockaddr_ll value, discarding\n");
                return;
        }
        if (memcmp(announce->haddr, if_hwaddr, announce->haddr_len) == 0) {
                fprintf(stderr, "packet has a duplicate hardware address, discarding\n");
                return;
        }

        struct xia_xid ether_xid;
        if (form_ether_xid(addr->sll_ifindex, addr->sll_addr,
                           sizeof(if_ether_xid_str), if_ether_xid_str)) {
                fprintf(stderr, "Could not form ether XID for the address\n");
                return;
        }
        assert(!ppal_name_to_type("ether", &ether_xid.xid_type));
        if (xia_ptoid(if_ether_xid_str, INT_MAX, &ether_xid) == -1) {
                fprintf(stderr, "Invalid ether XID: %s", if_ether_xid_str);
                return;
        }
        printf("Adding neighbour ether-%s\n",if_ether_xid_str);
        modify_neighbour(&ether_xid, true);

        for (i = 0; i < announce->hid_count; i++) {
                struct xia_xid ad_src;
                assert(!ppal_name_to_type("ad", &(ad_src.xid_type)));
                uint8_t *xid = NWP_ANNOUNCEMENT_GET_HID(announce, i);
                memcpy(ad_src.xid_id, xid, XIA_XID_MAX);

                printf("Adding route ");
                print_xia_xid(&ad_src);
                printf(" -> ");
                print_xia_xid(&ether_xid);
                printf("\n");
                modify_route(&ad_src, &ether_xid);
        }

        send_neigh_list(eth_socket, addr, announce->haddr_len);
}

void send_neigh_list(int socket, struct sockaddr_ll *addr, int haddr_len)
{
        struct nwp_neigh_list list;
        /* neighs contains all known neighbors */
        struct routes *neighs = create_filter(XRTABLE_MAIN_INDEX);
        assert(!ppal_name_to_type("ether", &neighs->dst_type));

        int i, member_size = sizeof(struct nwp_common_hdr) + 2 * sizeof(uint8_t),
                neigh_size = XIA_XID_MAX + sizeof(uint8_t) + haddr_len, size;
        char *buf, *cur_buf;

        if (rtnl_send_wilddump_request(xia_nl_socket, AF_XIA, RTM_GETROUTE,
                                       filter_callback, neighs) == -1) {
                perror("rtnl_send_wilddump_request");
                free(neighs);
                return;
        }

        size = member_size + neighs->n * neigh_size;
        buf = cur_buf = calloc(1, size);

        list.common.type = NWP_NEIGHBOUR_LIST;
        list.common.version = 0x01;
        list.hid_count = neighs->n;
        list.haddr_len = haddr_len;

        memcpy(cur_buf, &list, member_size);
        cur_buf += member_size;

        uint8_t num_xids = 1;
        for (i = 0; i < neighs->n; i++) {
                /* routes contains all ad->ether routes*/
                struct routes *routes = create_filter(XRTABLE_MAIN_INDEX);
                assert(!ppal_name_to_type("ad", &routes->dst_type));
                assert(!ppal_name_to_type("ether", &routes->gw_type));

                struct xia_xid eth_xid ;
                eth_xid.xid_type = routes->gw_type;
                memcpy(eth_xid.xid_id, neighs->routes[i]->dst_xid, XIA_XID_MAX);
                routes->gw = &eth_xid;
                if (rtnl_send_wilddump_request(xia_nl_socket, AF_XIA, RTM_GETROUTE,
                                       filter_callback, routes) == -1) {
                        perror("rtnl_send_wilddump_request");
                        free_filter(routes);
                        goto done;
                }
                if (routes->n > 0) {
                        memcpy(cur_buf, routes->routes[i]->dst_xid, XIA_XID_MAX);
                        cur_buf += XIA_XID_MAX;
                        memcpy(cur_buf, &num_xids, sizeof(uint8_t));
                        cur_buf += sizeof(uint8_t);
                        memcpy(cur_buf, &neighs->routes[i]->dst_xid[4], ETH_ALEN);
                        cur_buf += ETH_ALEN;
                }
                free_filter(routes);
        }

        if (sendto(socket, buf, size, 0, (struct sockaddr *)addr,
                   sizeof(*addr)) == -1) {
                perror("sendto");
        }


done:
        free(buf);
        free_filter(neighs);
        return;
}

void *ether_receiver(void *ptr)
{
        struct ctxt *ctxt = (struct ctxt *)ptr;

        char nwp_buf[1500];
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

        pthread_t announce_loop_thread;
        pthread_create(&announce_loop_thread, NULL, announce_loop, ctxt);
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
                        struct nwp_announce *announce = calloc(1, sizeof(struct nwp_announce));
                        if (!read_announce(nwp_buf, announce, msglen)) {
                                fprintf(stderr, "invalid NWP announce packet, discarding\n");
                                free(announce);
                                continue;
                        }

                        process_announce(&addr, announce);
                        free(announce->haddr);
                        free(announce->addr_begin);
                        free(announce);
                        break;
                }
                case NWP_NEIGHBOUR_LIST:
                {
                        struct nwp_neigh_list *neigh = malloc(msglen);
                        if (!read_neighbor_list(nwp_buf, neigh, msglen)) {
                                fprintf(stderr, "invalid NWP neighbour list packet, discarding\n");
                                free(neigh);
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
