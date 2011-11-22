#ifndef __LIBNETLINK_H__
#define __LIBNETLINK_H__ 1

/* XXX The following include shouldn't be here, but <linux/socket.h> isn't
 * including it, what, in turn, breaks <linux/netlink.h> added below.
 */
#include <sys/socket.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>

struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
	__u32			seq;
	__u32			dump;
};

/*
 * Initialization and termination
 */

/* @subscriptions fills field nl_groups in struct sockaddr_nl of
 * the local address.
 *
 * RETURN
 *	Zero on success; a negative number otherwise.
 */
extern int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
		int protocol);

static inline int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}

extern void rtnl_close(struct rtnl_handle *rth);

/*
 * Sending
 */

extern int rtnl_send(struct rtnl_handle *rth, const char *buf, int);

/* Same as rtnl_send, but checks for immediate errors before returning. */
extern int rtnl_send_check(struct rtnl_handle *rth, const char *buf, int);

/*
 * Dumping
 */

extern int rtnl_wilddump_request(struct rtnl_handle *rth, int fam, int type);
extern int rtnl_dump_request(struct rtnl_handle *rth, int type, void *req,
			int len);

typedef int (*rtnl_filter_t)(const struct sockaddr_nl *,
			     struct nlmsghdr *n, void *);

struct rtnl_dump_filter_arg
{
	rtnl_filter_t filter;
	void *arg1;
	rtnl_filter_t junk;
	void *arg2;
};

/* rtnl_dump_filter_l handles multiple filters, @arg is an array. */
extern int rtnl_dump_filter_l(struct rtnl_handle *rth,
			      const struct rtnl_dump_filter_arg *arg);

/* Single filter. */
extern int rtnl_dump_filter(struct rtnl_handle *rth, rtnl_filter_t filter,
			    void *arg1,
			    rtnl_filter_t junk,
			    void *arg2);

/*
 * Attributes
 */

/* Add an attribute of 32 bits. */
extern int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data);

/* Add an attribute of length @alen. */
extern int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen);

/* Add raw @data. */
extern int addraw_l(struct nlmsghdr *n, int maxlen, const void *data, int len);

extern struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type);

extern int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
extern struct rtattr *addattr_nest_compat(struct nlmsghdr *n, int maxlen, int type, const void *data, int len);
extern int addattr_nest_compat_end(struct nlmsghdr *n, struct rtattr *nest);
extern int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data);
extern int rta_addattr_l(struct rtattr *rta, int maxlen, int type, const void *data, int alen);

extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
extern int parse_rtattr_byindex(struct rtattr *tb[], int max, struct rtattr *rta, int len);
extern int __parse_rtattr_nested_compat(struct rtattr *tb[], int max, struct rtattr *rta, int len);

#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))

#define parse_rtattr_nested_compat(tb, max, rta, data, len) \
({	data = RTA_PAYLOAD(rta) >= len ? RTA_DATA(rta) : NULL; \
	__parse_rtattr_nested_compat(tb, max, rta, len); })

/*
 * Miscellaneous
 */

/* Obtain table ID. */
int rtnl_get_table(struct rtmsg *r, struct rtattr **tb);

/* Send @n to @peer/@groups, and obtain the reply in @answer.
 * junk and jarg are called for replies that are not proper.
 */
extern int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, __u32 peer,
		     unsigned groups, struct nlmsghdr *answer,
		     rtnl_filter_t junk,
		     void *jarg);

/* Read up rtnl_handle. */
extern int rtnl_listen(struct rtnl_handle *, rtnl_filter_t handler,
		       void *jarg);

/* Similar to rtnl_listen, but the input is a file. */
extern int rtnl_from_file(FILE *, rtnl_filter_t handler,
		       void *jarg);

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef IFA_RTA
#define IFA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#endif
#ifndef IFA_PAYLOAD
#define IFA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
#endif

#ifndef IFLA_RTA
#define IFLA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#endif
#ifndef IFLA_PAYLOAD
#define IFLA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#endif

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif
#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

#ifndef NDTA_RTA
#define NDTA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndtmsg))))
#endif
#ifndef NDTA_PAYLOAD
#define NDTA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndtmsg))
#endif

#endif /* __LIBNETLINK_H__ */
