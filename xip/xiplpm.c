#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <net/xia_fib.h>
#include <xia_socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm-generic/errno-base.h>

#include "xip_common.h"
#include "utils.h"
#include "libnetlink.h"
#include "xiart.h"

static int usage(void)
{
	fprintf(stderr,
"Usage:	xip lpm { addlocal | dellocal } ID PREFIX_LEN\n"
"	xip lpm addroute ID PREFIX_LEN gw XID\n"
"	xip lpm delroute ID PREFIX_LEN\n"
"	xip lpm show { locals | routes }\n"
"where	ID := '0x' HEXDIGIT{20} | IPV4ADDR\n"
"	IPV4ADDR := 0-255 \".\" 0-255 \".\" 0-255 \".\" 0-255\n"
"	XID := PRINCIPAL '-' HEXDIGIT{20}\n"
"	PRINCIPAL := '0x' NUMBER | STRING\n");
	return -1;
}

static long get_prefix_len(const char *prefix_len_str)
{
	char *end;
	long prefix_len;
	errno = 0;

	prefix_len = strtol(prefix_len_str, &end, 0);
	if (prefix_len_str == end || !*prefix_len_str || *end) {
		/* No string or not only digits in string. */
		fprintf(stderr, "\"%s\" is not an integer\n", prefix_len_str);
		return -1;
	}
	if (errno == ERANGE &&
		(prefix_len == LONG_MAX || prefix_len == LONG_MIN)) {
		/* Overflow in prefix length. */
		perror("strtol");
		return -1;
	}
	if (prefix_len < 0 || prefix_len > XIA_XID_MAX * 8) {
		/* Prefix length outside valid bounds for application. */
		fprintf(stderr, "Prefix length must be in range 0 - %d\n",
			XIA_XID_MAX * 8);
		return -1;
	}
	return prefix_len;
}

static int convert_id_to_hex(char *id, char *hexbuf)
{
	int rc;
	if (strlen(id) < 3) {
		fprintf(stderr, "ID is too short\n");
		return -1;
	}

	if (id[0] == '0' && id[1] == 'x') {
		/* Skip past '0x'. */
		id = id + 2;

		if (strlen(id) == XIA_MAX_STRID_SIZE - 1) {
			/* No padding necessary. */
			memmove(hexbuf, id, XIA_MAX_STRID_SIZE);
		} else {
			/* Pad to 20 bytes. */
			rc = snprintf(hexbuf, XIA_MAX_STRID_SIZE, "%s%0*x",
				id, (int)(XIA_MAX_STRID_SIZE - strlen(id) - 1),
				0);
			if (rc >= XIA_MAX_STRID_SIZE) {
				fprintf(stderr, "snprintf: ID is too long\n");
				return -1;
			}
		}
	} else {
		/* Need to convert an IP address to hex characters. */
		struct in_addr ip_addr;

		/* Convert IP address string to decimal number. */
		rc = inet_pton(AF_INET, id, &ip_addr);
		if (rc <= 0) {
			if (rc == 0) {
				fprintf(stderr, "invalid IPv4 address\n");
				return -1;
			} else {
				perror("inet_pton: cannot use IPv4 address");
				return -1;
			}
		}

		/* Pad to 20 bytes. */
		rc = snprintf(hexbuf, XIA_MAX_STRID_SIZE, "%08x%032x",
			__be32_to_cpu(ip_addr.s_addr), 0);
		if (rc >= XIA_MAX_STRID_SIZE) {
			fprintf(stderr, "snprintf failed\n");
			return -1;
		}
	}

	return 0;
}

static int modify_local(const struct xia_xid *dst, __u8 prefix_len, int to_add)
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
	addattr_l(&req.n, sizeof(req), RTA_PROTOINFO, &prefix_len,
		sizeof(prefix_len));

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

static int do_local(int argc, char **argv, int to_add)
{
	char id_in_hex[XIA_MAX_STRID_SIZE];
	struct xia_xid dst;
	int prefix_len;

	if (argc != 2) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}

	if (convert_id_to_hex(argv[0], id_in_hex) < 0)
		return usage();

	prefix_len = get_prefix_len(argv[1]);
	if (prefix_len < 0)
		return usage();

	xrt_get_ppal_id("lpm", usage, &dst, id_in_hex);
	return modify_local(&dst, (__u8)prefix_len, to_add);
}

static int do_addlocal(int argc, char **argv)
{
	return do_local(argc, argv, 1);
}

static int do_dellocal(int argc, char **argv)
{
	return do_local(argc, argv, 0);
}

static int modify_route(const struct xia_xid *dst, __u8 prefix_len,
			const struct xia_xid *gw)
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
	addattr_l(&req.n, sizeof(req), RTA_PROTOINFO, (__u8 *)&prefix_len,
		sizeof((__u8)prefix_len));

	if (to_add)
		addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gw, sizeof(*gw));

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

static int do_addroute(int argc, char **argv)
{
	char id_in_hex[XIA_MAX_STRID_SIZE];
	struct xia_xid dst, gw;
	int prefix_len;

	if (argc != 4) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[2], "gw")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}

	if (convert_id_to_hex(argv[0], id_in_hex) < 0)
		return usage();

	prefix_len = get_prefix_len(argv[1]);
	if (prefix_len < 0)
		return usage();

	xrt_get_ppal_id("lpm", usage, &dst, id_in_hex);
	xrt_get_xid(usage, &gw, argv[3]);

	return modify_route(&dst, prefix_len, &gw);
}

static int do_delroute(int argc, char **argv)
{
	char id_in_hex[XIA_MAX_STRID_SIZE];
	struct xia_xid dst;
	int prefix_len;

	if (argc != 2) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}

	if (convert_id_to_hex(argv[0], id_in_hex) < 0)
		return usage();

	prefix_len = get_prefix_len(argv[1]);
	if (prefix_len < 0)
		return usage();

	xrt_get_ppal_id("lpm", usage, &dst, id_in_hex);

	return modify_route(&dst, prefix_len, NULL);
}

static struct
{
	__u32		tb;
	xid_type_t	xid_type;
} filter;

static inline void reset_filter(void)
{
	memset(&filter, 0, sizeof(filter));
	assert(!ppal_name_to_type("lpm", &filter.xid_type));
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
	fprintf(fp, "/%d", *(__u8 *)RTA_DATA(tb[RTA_PROTOINFO]));
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
	const char *name;

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}

	name = argv[0];
	if (!matches(name, "locals")) {
		return dump(XRTABLE_LOCAL_INDEX);
	} else if (!matches(name, "routes")) {
		return dump(XRTABLE_MAIN_INDEX);
	} else {
		fprintf(stderr, "Unknown routing table '%s', it must be either 'locals', or 'routes'\n",
			name);
		return usage();
	}
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
	{ 0,		0		}
};

int do_lpm(int argc, char **argv)
{
	return do_cmd(cmds, "Command", "xip lpm help", argc, argv);
}
