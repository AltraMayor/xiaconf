#include <net/xia.h>
#include <net/xia_fib.h>
#include <xia_socket.h>
#include <time.h>

#include "rtnl.h"
#include "globals.h"
#include "log.h"
#include "neigh.h"

void modify_neighbour(struct xia_xid *dst, bool add)
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
                nwpd_logf(LOG_LEVEL_ERROR, "modify_neighbour: Couldn't modify neighbour entry\n");
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
                nwpd_logf(LOG_LEVEL_ERROR, "modify_route: Couldn't modify route entry\n");
}
