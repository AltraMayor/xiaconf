#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <net/xia_fib.h>
#include <xia_socket.h>

#include "xip_common.h"
#include "utils.h"
#include "libnetlink.h"
#include "xiart.h"

void xrt_get_ppalty_id(xid_type_t ppal_ty, help_func_t usage,
	struct xia_xid *dst, const char *s)
{
	dst->xid_type = ppal_ty;
	if (xia_ptoid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid ID '%s'\n", s);
		usage();
		exit(1);
	}
}

void xrt_get_ppal_id(const char *ppal, help_func_t usage, struct xia_xid *dst,
	const char *s)
{
	xid_type_t ty;
	assert(!ppal_name_to_type(ppal, &ty));
	xrt_get_ppalty_id(ty, usage, dst, s);
}

void xrt_get_xid(help_func_t usage, struct xia_xid *dst, const char *s)
{
	if (xia_ptoxid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid XID '%s'\n", s);
		usage();
		exit(1);
	}
}

/* Based on iproute2/ip/iproute.c:iproute_modify. */
int xrt_modify_route(const struct xia_xid *dst, const struct xia_xid *gw)
{
	int to_add = !!gw;
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

	if (to_add) {
		/* XXX Does one really needs all these flags? */
		req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
		req.n.nlmsg_type = RTM_NEWROUTE;
		req.r.rtm_scope = RT_SCOPE_LINK;
	} else {
		req.n.nlmsg_flags = NLM_F_REQUEST;
		req.n.nlmsg_type = RTM_DELROUTE;
		req.r.rtm_scope = RT_SCOPE_NOWHERE;
	}

	req.r.rtm_family = AF_XIA;
	req.r.rtm_table = XRTABLE_MAIN_INDEX;
	req.r.rtm_protocol = RTPROT_BOOT;
	req.r.rtm_type = RTN_UNICAST;

	req.r.rtm_dst_len = sizeof(*dst);
	addattr_l(&req.n, sizeof(req), RTA_DST, dst, sizeof(*dst));

	if (to_add)
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gw, sizeof(*gw));

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

static struct {
	__u32		tb;
	xid_type_t	xid_type;
} filter;

static inline void reset_filter(__u32 tb_id, xid_type_t ty)
{
	filter.tb = tb_id;
	filter.xid_type = ty;
}

/* Based on iproute2/ip/iproute.c:iproute_list_flush_or_save. */
static int dump(__u32 tbl_id, xid_type_t ty, rtnl_filter_t print)
{
	reset_filter(tbl_id, ty);

	if (rtnl_wilddump_request(&rth, AF_XIA, RTM_GETROUTE) < 0) {
		perror("XIA RT: Cannot send dump request");
		exit(1);
	}
	if (rtnl_dump_filter(&rth, print, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "XIA RT: Dump terminated\n");
		exit(1);
	}
	return 0;
}

/* Based on iproute2/ip/iproute.c:print_route. */
static int print_route(const struct sockaddr_nl *who, struct nlmsghdr *n,
	void *arg)
{
	FILE *fp = (FILE*)arg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX+1];
	const struct xia_xid *dst;
	__u32 table;

	UNUSED(who);

	if (n->nlmsg_type != RTM_NEWROUTE && n->nlmsg_type != RTM_DELROUTE) {
		fprintf(stderr, "Not a route: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}
	if (r->rtm_family != AF_XIA) {
		/* fprintf(stderr, "Wrong rtm_family %d\n", r->rtm_family); */
		return 0;
	}
	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}
	if (r->rtm_dst_len != sizeof(struct xia_xid)) {
		fprintf(stderr, "BUG: wrong rtm_dst_len %d\n", r->rtm_dst_len);
		return -1;
	}

	/* XXX Doesn't the kernel provide similar function? */
	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	table = rtnl_get_table(r, tb);

	/* Filter happens here. */
	if (filter.tb != table)
		return 0;
	if (!tb[RTA_DST] ||
		RTA_PAYLOAD(tb[RTA_DST]) != sizeof(struct xia_xid) ||
		r->rtm_dst_len != sizeof(struct xia_xid))
		return -1;
	dst = (const struct xia_xid *)RTA_DATA(tb[RTA_DST]);
	if (dst->xid_type != filter.xid_type)
		return 0;

	if (n->nlmsg_type == RTM_DELROUTE)
		fprintf(fp, "Deleted ");
	fprintf(fp, "to ");
	/* XXX It got to use fp! */
	print_xia_xid(dst);
	fprintf(fp, "\n");

	if (tb[RTA_GATEWAY]) {
		printf("gw ");
		assert(RTA_PAYLOAD(tb[RTA_GATEWAY]) == sizeof(struct xia_xid));
		print_xia_xid((const struct xia_xid *)
			RTA_DATA(tb[RTA_GATEWAY]));
	}

	assert(!r->rtm_src_len);
	assert(!(r->rtm_flags & RTM_F_CLONED));

	fprintf(fp, " flags [");
	if (r->rtm_flags & RTNH_F_DEAD)
		fprintf(fp, "dead ");
	if (r->rtm_flags & RTNH_F_ONLINK)
		fprintf(fp, "onlink ");
	if (r->rtm_flags & RTNH_F_PERVASIVE)
		fprintf(fp, "pervasive ");
	if (r->rtm_flags & RTM_F_NOTIFY)
		fprintf(fp, "notify ");
	fprintf(fp, "]");

	fprintf(fp, "\n\n");
	fflush(fp);
	return 0;
}

int xrt_list_rt_redirects(__u32 tbl_id, xid_type_t ppal_ty)
{
	return dump(tbl_id, ppal_ty, print_route);
}
