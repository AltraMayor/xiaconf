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
	fprintf(stderr,
"Usage: xip ad addroute ID tbl { local | main } gw XID dev STRING\n"
"       xip ad delroute ID tbl { local | main }\n"
"	xip ad dump tbl { local | main }\n"
"where	ID := HEXDIGIT{20}\n"
"       XID := PRINCIPAL-ID\n"
"	PRINCIPAL := NUMBER | STRING\n");
	return -1;
}

static int get_tbl_id(const char *name)
{
	if (!matches(name, "local"))
		return XRTABLE_LOCAL_INDEX;
	if (!matches(name, "main"))
		return XRTABLE_MAIN_INDEX;
	fprintf(stderr, "Unknow routing table '%s', "
		"it must be either 'local', or 'main'\n", name);
	return usage();
}

static void get_ad(const char *s, struct xia_xid *dst)
{
	if (xia_ptoid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid ID '%s'\n", s);
		usage();
		exit(1);
	}
	/* XXX Get rid of magic numbers! */
	dst->xid_type = __cpu_to_be32(0x10);
}

static void get_xid(const char *s, struct xia_xid *dst)
{
	if (xia_ptoxid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid XID '%s'\n", s);
		usage();
		exit(1);
	}
}

/* Based on iproute2/ip/iproute.c:iproute_modify. */
static int addroute(const struct xia_xid *dst, int tbl_id,
	const struct xia_xid *gw, unsigned oif)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	/* XXX Does one really needs all these flags? */
	req.n.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWROUTE;
	req.r.rtm_family = AF_XIA;
	req.r.rtm_table = tbl_id;

	if (tbl_id == XRTABLE_LOCAL_INDEX) {
		req.r.rtm_type = RTN_LOCAL;
		req.r.rtm_scope = RT_SCOPE_HOST;
	} else {
		req.r.rtm_type = RTN_UNICAST;
		req.r.rtm_scope = RT_SCOPE_LINK;
	}

	req.r.rtm_dst_len = sizeof(struct xia_xid);
	addattr_l(&req.n, sizeof(req), RTA_DST, dst, sizeof(struct xia_xid));
	addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gw, sizeof(struct xia_xid));
	addattr32(&req.n, sizeof(req), RTA_OIF, oif);

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

/* Based on iproute2/ip/iproute.c:iproute_modify. */
static int delroute(const struct xia_xid *dst, int tbl_id)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
		char   			buf[1024];
	} req;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELROUTE;
	req.r.rtm_family = AF_XIA;
	req.r.rtm_table = tbl_id;
	req.r.rtm_protocol = RTPROT_BOOT;

	if (tbl_id == XRTABLE_LOCAL_INDEX) {
		req.r.rtm_type = RTN_LOCAL;
		req.r.rtm_scope = RT_SCOPE_HOST;
	} else {
		req.r.rtm_type = RTN_UNICAST;
		req.r.rtm_scope = RT_SCOPE_NOWHERE;
	}

	req.r.rtm_dst_len = sizeof(struct xia_xid);
	addattr_l(&req.n, sizeof(req), RTA_DST, dst, sizeof(struct xia_xid));

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

static struct
{
	__u32 tb;
} filter;

static inline void reset_filter(void)
{
	memset(&filter, 0, sizeof(filter));
}

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;
	if (tb[RTA_TABLE])
		table = *(__u32*) RTA_DATA(tb[RTA_TABLE]);
	return table;
}

/* Based on iproute2/ip/iproute.c:print_route. */
int print_route(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE*)arg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX+1];
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

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	table = rtm_get_table(r, tb);

	/* Filter happens here. */
	if (filter.tb != table)
		return 0;

	if (n->nlmsg_type == RTM_DELROUTE)
		fprintf(fp, "Deleted ");

	if (tb[RTA_DST]) {
		printf("to ");
		assert(RTA_PAYLOAD(tb[RTA_DST]) == sizeof(struct xia_addr));
		print_xia_addr((const struct xia_addr *)
			RTA_DATA(tb[RTA_DST]));
	} else if (r->rtm_dst_len) {
		fprintf(fp, "to 0/%d ", r->rtm_dst_len);
	} else {
		fprintf(fp, "default ");
	}

	if (tb[RTA_GATEWAY]) {
		printf("gw ");
		assert(RTA_PAYLOAD(tb[RTA_GATEWAY]) == sizeof(struct xia_addr));
		print_xia_addr((const struct xia_addr *)
			RTA_DATA(tb[RTA_GATEWAY]));
	}

	if (tb[RTA_OIF]) {
		unsigned oif = *(int *)RTA_DATA(tb[RTA_OIF]);
		fprintf(fp, "dev %s ", ll_index_to_name(oif));
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

	fprintf(fp, "\n");
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

static int do_addroute(int argc, char **argv)
{
	int tbl_id;
	const char *dev;
	unsigned oif;
	struct xia_xid dst, gw;

	if (argc != 7) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[1], "tbl") ||
	    strcmp(argv[3], "gw")  ||
	    strcmp(argv[5], "dev")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}
	get_ad(argv[0], &dst);
	tbl_id = get_tbl_id(argv[2]);
	get_xid(argv[4], &gw);

	dev = argv[6];
	oif = ll_name_to_index(dev);
	if (!oif) {
		fprintf(stderr, "Cannot find device '%s'\n", dev);
		return -1;
	}

	return addroute(&dst, tbl_id, &gw, oif);
}

static int do_delroute(int argc, char **argv)
{
	int tbl_id;
	struct xia_xid dst;

	if (argc != 3) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[1], "tbl")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}
	get_ad(argv[0], &dst);
	tbl_id = get_tbl_id(argv[2]);

	return delroute(&dst, tbl_id);
}

static int do_dump(int argc, char **argv)
{
	int tbl_id;

	if (argc != 2) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[0], "tbl")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}
	tbl_id = get_tbl_id(argv[1]);

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
	{ "addroute",	do_addroute	},
	{ "delroute",	do_delroute	},
	{ "dump",	do_dump		},
	{ "help",	do_help		},
	{ 0,		0 }
};

int do_ad(int argc, char **argv)
{
	if (argc < 1) {
		/* TODO */
		fprintf(stderr, "TODO: Implement a default action!\n");
		return 0;
	}

	assert(!init_ppal_map());
	assert(!ll_init_map(&rth));
	return do_cmd(cmds, "Command", "xip ad help", argc, argv);
}
