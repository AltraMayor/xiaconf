#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <net/xia.h>
#include <net/xia_fib.h>
#include <net/xia_dag.h>

#include "xip_common.h"
#include "utils.h"
#include "libnetlink.h"
#include "xia_socket.h"
#include "ppal_map.h"
#include "ll_map.h"

static int usage(void)
{
/* XXX Shouldn't  addroute/delroute support multiple gateways for
 * the same AD?
 */
	fprintf(stderr,
"Usage:	xip ad { addlocal | dellocal } ID\n"
"	xip ad addroute ID gw XID\n"
"	xip ad delroute ID\n"
"	xip ad show { locals | routes }\n"
"where	ID := HEXDIGIT{20}\n"
"	XID := PRINCIPAL '-' ID\n"
"	PRINCIPAL := '0x' NUMBER | STRING\n");
	return -1;
}

static void get_ad(const char *s, struct xia_xid *dst)
{
	if (xia_ptoid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid ID '%s'\n", s);
		usage();
		exit(1);
	}
	assert(!ppal_name_to_type("ad", &dst->xid_type));
}

static void get_xid(const char *s, struct xia_xid *dst)
{
	if (xia_ptoxid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid XID '%s'\n", s);
		usage();
		exit(1);
	}
}

static int modify_local(const struct xia_xid *dst, int to_add)
{
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
	} else {
		req.n.nlmsg_flags = NLM_F_REQUEST;
		req.n.nlmsg_type = RTM_DELROUTE;
	}

	req.r.rtm_family = AF_XIA;
	req.r.rtm_table = XRTABLE_LOCAL_INDEX;
	req.r.rtm_protocol = RTPROT_BOOT;
	req.r.rtm_type = RTN_LOCAL;
	req.r.rtm_scope = RT_SCOPE_HOST;

	req.r.rtm_dst_len = sizeof(*dst);
	addattr_l(&req.n, sizeof(req), RTA_DST, dst, sizeof(*dst));

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

static int do_local(int argc, char **argv, int to_add)
{
	struct xia_xid dst;

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	get_ad(argv[0], &dst);
	return modify_local(&dst, to_add);
}

static int do_addlocal(int argc, char **argv)
{
	return do_local(argc, argv, 1);
}

static int do_dellocal(int argc, char **argv)
{
	return do_local(argc, argv, 0);
}

/* Based on iproute2/ip/iproute.c:iproute_modify. */
static int modify_route(const struct xia_xid *dst, const struct xia_xid *gw)
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

static int do_addroute(int argc, char **argv)
{
	struct xia_xid dst, gw;

	if (argc != 3) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[1], "gw")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}
	get_ad(argv[0], &dst);
	get_xid(argv[2], &gw);

	return modify_route(&dst, &gw);
}

static int do_delroute(int argc, char **argv)
{
	struct xia_xid dst;

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	get_ad(argv[0], &dst);

	return modify_route(&dst, NULL);
}

static struct
{
	__u32		tb;
	xid_type_t	xid_type;
} filter;

static inline void reset_filter(void)
{
	memset(&filter, 0, sizeof(filter));
	assert(!ppal_name_to_type("ad", &filter.xid_type));
}

/* Based on iproute2/ip/iproute.c:print_route. */
int print_route(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
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

/* Based on iproute2/ip/iproute.c:iproute_list_flush_or_save. */
static int dump(int tbl_id)
{
	reset_filter();
	filter.tb = tbl_id;

	if (rtnl_wilddump_request(&rth, AF_XIA, RTM_GETROUTE) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}
	if (rtnl_dump_filter(&rth, print_route, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}
	return 0;
}

static int do_show(int argc, char **argv)
{
	int tbl_id;
	char *name;

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}

	name = argv[0];
	if (!matches(name, "locals"))
		tbl_id = XRTABLE_LOCAL_INDEX;
	else if (!matches(name, "routes"))
		tbl_id = XRTABLE_MAIN_INDEX;
	else {
		fprintf(stderr, "Unknow routing table '%s', it must be either 'locals', or 'routes'\n",
			name);
		return usage();
	}

	return dump(tbl_id);
}

static int do_help(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);
	usage();
	exit(1);
}

static const struct cmd cmds[] = {
	{ "addlocal",	do_addlocal	},
	{ "dellocal",	do_dellocal	},
	{ "addroute",	do_addroute	},
	{ "delroute",	do_delroute	},
	{ "show",	do_show		},
	{ "help",	do_help		},
	{ 0,		0 }
};

int do_ad(int argc, char **argv)
{
	assert(!init_ppal_map());
	assert(!ll_init_map(&rth));
	return do_cmd(cmds, "Command", "xip ad help", argc, argv);
}
