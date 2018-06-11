#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <time.h>

typedef void (*rtnl_filter_t)(struct nlmsghdr *n, void *);

int rtnl_talk(const struct mnl_socket *nl_socket, struct nlmsghdr *n,
              const struct nlmsghdr *reply)
{
        if (reply == NULL)
                n->nlmsg_flags |= NLM_F_ACK;

        if (mnl_socket_sendto(nl_socket, n, n->nlmsg_len) < 0) {
                perror("mnl_socket_sendto");
                return -1;
        }
        char recv_buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(recv_buf);

        if (mnl_socket_recvfrom(nl_socket, recv_buf, sizeof(recv_buf)) == -1) {
                perror("mnl_socket_recvfrom");
                return -1;
        }

        while(1) {
                if (!mnl_nlmsg_ok(nlh, sizeof(recv_buf))) {
                        fprintf(stderr, "rtnl_talk: Received malformed/truncated message");
                        return -1;   
                }
                if (nlh->nlmsg_type == NLMSG_ERROR) {
                        struct nlmsgerr *err = NLMSG_DATA(nlh);
                        errno = -err->error;
                        if (errno == 0) 
                                return 0;
                        perror("RTNETLINK");
                        return -1;
                }
        }
}

int rtnl_send_wilddump_request(const struct mnl_socket *nl_socket,
                               const int family, const int type,
                               rtnl_filter_t callback, void *arg)
{
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        int rtrn;

        {
                struct rtgenmsg *g = mnl_nlmsg_put_extra_header(nlh,
                                                                sizeof(struct rtgenmsg));

                g->rtgen_family = family;
                nlh->nlmsg_type = type;
                nlh->nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
                nlh->nlmsg_seq = time(NULL);

                if ((rtrn = mnl_socket_sendto(nl_socket, nlh, nlh->nlmsg_len)))
                        return rtrn;
        }
        
        nlh = mnl_nlmsg_put_header(buf);
        if ((rtrn = mnl_socket_recvfrom(nl_socket, buf, sizeof(buf))))
                return rtrn;
        while (1) {
                if (!mnl_nlmsg_ok(nlh, sizeof(buf))) {
                        fprintf(stderr, "rtnl_talk: Received malformed/truncated message");
                        return -1;
                }
                if (nlh->nlmsg_type == NLMSG_ERROR) {
                        struct nlmsgerr *err = NLMSG_DATA(nlh);
                        errno = -err->error;
                        perror("RTNETLINK");
                        return -1;
                }
                callback(nlh, arg);
        }
}
