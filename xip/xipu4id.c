#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <net/xia_fib.h>
#include <xia_socket.h>
#include <asm-generic/errno-base.h>

#include "xip_common.h"
#include "utils.h"
#include "libnetlink.h"
#include "xiart.h"

#define MIN_IPV4_PORT 0
#define MAX_IPV4_PORT 65535

static int usage(void)
{
	fprintf(stderr,
"Usage:	xip u4id add UDP_ID\n"
"	xip u4id del UDP_ID\n"
"	xip u4id show\n"
"where	UDP_ID := HEXDIGIT{20} | IPV4ADDR PORT\n"
"	IPV4ADDR := 0-255 \".\" 0-255 \".\" 0-255 \".\" 0-255\n"
"	PORT := 0-65535 | \"0x\" 0000-FFFF\n");
	return -1;
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
	char static_xid[XIA_MAX_STRID_SIZE];
	char *str_xid;

	if (argc == 2) {
		/* Need to convert an IP address and port to an XID. */
		struct in_addr ip_addr;
		long ip_port;
		int rc;

		/* Convert IP address string to decimal number. */
		rc = inet_pton(AF_INET, argv[0], &ip_addr);
		if (rc <= 0) {
			if (rc == 0) {
				fprintf(stderr, "Invalid IPv4 address\n");
				return usage();
			} else {
				perror("inet_pton: cannot use IPv4 address");
				exit(1);
			}
		}

		/* Convert port string to decimal number. */
		ip_port = strtol(argv[1], NULL, 0);
		if (ip_port == LONG_MIN || ip_port == LONG_MAX) {
			perror("strtol: overflow converting port number");
			return usage();
		}
		if (ip_port < MIN_IPV4_PORT || ip_port > MAX_IPV4_PORT) {
			fprintf(stderr, "Port must be in range %d - %d\n",
				MIN_IPV4_PORT, MAX_IPV4_PORT);
			return usage();
		}

		/* Convert the IP address and port decimal
		 * strings to hex strings and add 28 zeros
		 * for the 14 zeroed bytes of the U4ID XID.
		 */
		rc = snprintf(static_xid, XIA_MAX_STRID_SIZE, "%08x%04x%028x",
			__be32_to_cpu(ip_addr.s_addr), (in_port_t)ip_port, 0);
		if (rc >= XIA_MAX_STRID_SIZE) {
			fprintf(stderr, "do_local: snprintf failed");
			return -ENOSPC;
		}
		str_xid = static_xid;
	} else if (argc == 1) {
		/* User has given an XID. */
		str_xid = argv[0];
	} else {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	xrt_get_ppal_id("u4id", usage, &dst, str_xid);
	return modify_local(&dst, to_add);
}

static int do_add(int argc, char **argv)
{
	return do_local(argc, argv, 1);
}

static int do_del(int argc, char **argv)
{
	return do_local(argc, argv, 0);
}

static struct
{
	__u32		tb;
	xid_type_t	xid_type;
} filter;

static inline void reset_filter(void)
{
	memset(&filter, 0, sizeof(filter));
	assert(!ppal_name_to_type("u4id", &filter.xid_type));
}

static int print_route(const struct sockaddr_nl *who, struct nlmsghdr *n,
	void *arg)
{
	FILE *fp = (FILE*)arg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX+1];
	const struct xia_xid *dst;
	__u32 table;
	char ip_addr_str[INET_ADDRSTRLEN];
	__be32 *pxid;
	in_addr_t ip_addr;
	in_port_t ip_port;

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
	/* XXX It got to use @fp! */
	print_xia_xid(dst);
	fprintf(fp, "\n");

	/* Print IP address and port representation. */
	pxid = (__be32 *)dst->xid_id;
	ip_addr = *pxid++;
	ip_port = __be16_to_cpu(*(__be16 *)pxid);
	if (inet_ntop(AF_INET, &ip_addr, ip_addr_str, INET_ADDRSTRLEN))
		fprintf(fp, " using IP socket: %s:%d\n",ip_addr_str, ip_port);

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
static int dump(void)
{
	reset_filter();
	filter.tb = XRTABLE_LOCAL_INDEX;

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
	UNUSED(argv);
	if (argc != 0) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	return dump();
}

static int do_help(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);
	usage();
	exit(1);
}

static const struct cmd cmds[] = {
	{ "add",	do_add		},
	{ "del",	do_del		},
	{ "show",	do_show		},
	{ "help",	do_help		},
	{ 0,		0		}
};

int do_u4id(int argc, char **argv)
{
	return do_cmd(cmds, "Command", "xip u4id help", argc, argv);
}
