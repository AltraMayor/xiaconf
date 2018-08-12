#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include "rtnl.h"
#include "log.h"

int rtnl_talk(const struct mnl_socket *nl_socket, struct nlmsghdr *n)
{
        uint32_t seq = time(NULL);
        n->nlmsg_seq = seq;
        n->nlmsg_flags |= NLM_F_ACK;

        if (mnl_socket_sendto(nl_socket, n, n->nlmsg_len) < 0) {
                nwpd_perror("mnl_socket_sendto");
                return -1;
        }

        char recv_buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(recv_buf);
        int msglen = sizeof(recv_buf);

        if (mnl_socket_recvfrom(nl_socket, recv_buf, sizeof(recv_buf)) == -1) {
                nwpd_perror("mnl_socket_recvfrom");
                return -1;
        }

        if (!mnl_nlmsg_ok(nlh, msglen)) {
                nwpd_logf(LOG_LEVEL_ERROR, "rtnl_talk: Received malformed/truncated message");
                return -1;
        }

        while(1) {
                if (!mnl_nlmsg_ok(nlh, msglen)) {
                        return 0;
                }

                if (nlh->nlmsg_pid != 0 || nlh->nlmsg_seq != seq) {
                        nlh = mnl_nlmsg_next(nlh, &msglen);
                        continue;
                }
                if (nlh->nlmsg_type == NLMSG_ERROR) {
                        struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
                        errno = -err->error;
                        if (errno == 0)
                                return 0;
                        nwpd_perror("RTNETLINK");
                        return -1;
                }
                nlh = mnl_nlmsg_next(nlh, &msglen);
        }
}

int rtnl_send_wilddump_request(const struct mnl_socket *nl_socket,
                               const int family, const int type,
                               rtnl_filter_t callback, void *arg)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        int rtrn, msglen;
        uint32_t seq = time(NULL);

        {
                struct rtgenmsg *g = mnl_nlmsg_put_extra_header(nlh,
                                                                sizeof(struct rtgenmsg));

                g->rtgen_family = family;
                nlh->nlmsg_type = type;
                nlh->nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
                nlh->nlmsg_seq = seq;

                if ((rtrn = mnl_socket_sendto(nl_socket, nlh, nlh->nlmsg_len)) == -1)
                        return rtrn;
        }

        while(1)
        {
                nlh = mnl_nlmsg_put_header(buf);
                if ((rtrn = mnl_socket_recvfrom(nl_socket, buf, sizeof(buf))) == -1)
                        return rtrn;
                msglen = sizeof(buf);

                while (mnl_nlmsg_ok(nlh, msglen)) {
                        switch (nlh->nlmsg_type) {
                        case NLMSG_ERROR:
                        {
                                struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
                                errno = -err->error;
                                nwpd_perror("RTNETLINK");
                                return -1;
                        }
                        case NLMSG_DONE:
                                return 0;
                        default:
                                callback(nlh, arg);
                        }
                        nlh = mnl_nlmsg_next(nlh, &msglen);
                }
        }
        return 0;
}

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		nwpd_logf(LOG_LEVEL_ERROR, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

int rtnl_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;
	if (tb[RTA_TABLE])
		table = *(__u32*)RTA_DATA(tb[RTA_TABLE]);
	return table;
}
