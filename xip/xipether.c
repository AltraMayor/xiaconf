#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <fcntl.h>
#include <asm/byteorder.h>
#include <asm-generic/errno-base.h>
#include <net/xia_fib.h>
#include <xia_socket.h>
#include <sys/socket.h>
#include <net/xia_ether.h>

#include "xip_common.h"
#include "utils.h"
#include "ll_map.h"
#include "libnetlink.h"
#include "xiart.h"

#define IFINDEX_STR_SIZE 8
#define XIA_LLADDR_LEN 12
#define APPEND_ZEROES 20

static int usage(void)
{
	fprintf(stderr,
"Usage:	xip ether { addinterface | delinterface } dev DEV\n"
"       xip ether { addneigh | delneigh } lladdr LLADDR dev DEV\n"
"       xip ether show { interfaces | neighs }\n"
"where	LLADDR := HEXDIGIT{1,2} (':' HEXDIGIT{1,2})*\n"
"	DEV := STRING NUMBER\n");
	return -1;
}

static void form_ether_xid(unsigned oif, unsigned char *lladdr, unsigned tlen, const char *id)
{
	char bytes[4];
	unsigned append = APPEND_ZEROES;
	bytes[0] = (oif >> 24) & 0xFF;
	bytes[1] = (oif >> 16) & 0xFF;
	bytes[2] = (oif >> 8) & 0xFF;
	bytes[3] = oif & 0xFF;
	snprintf(id, (tlen+1), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%0*x",(unsigned char)bytes[0],
				(unsigned char)bytes[1],(unsigned char)bytes[2],
				(unsigned char)bytes[3],lladdr[0],lladdr[1],
				lladdr[2], lladdr[3],lladdr[4], lladdr[5], append);
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
	const char *dev;
	char strid[XIA_XID_MAX];
	unsigned char lladdr[MAX_ADDR_LEN];
	unsigned oif,addrlen;

	if (argc != 2) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}

	if (strcmp(argv[0], "dev")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}

	dev = argv[1];
	oif = ll_name_to_index(dev);
	if (!oif) {
		fprintf(stderr, "Cannot find device '%s'\n", dev);
		return -1;
	}
	addrlen = ll_index_to_addr(oif, lladdr, sizeof(lladdr));
	if (!addrlen) {
		/* should add a check to see if addrlen also equal to 12?*/
		fprintf(stderr, "Cannot find device address '%s'\n", dev);
		return -1;
	}
	form_ether_xid(oif, lladdr, XIA_XID_MAX*2, strid);

	xrt_get_ppal_id("ether", usage, &dst, strid);
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

static int modify_neigh(struct xia_xid *dst, unsigned char *lladdr,
	int lladdr_len, unsigned oif, int to_add)
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
	addattr_l(&req.n, sizeof(req), RTA_LLADDR, lladdr, lladdr_len);
	addattr32(&req.n, sizeof(req), RTA_OIF, oif);

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

static int do_Xneigh_common(int argc, char **argv, int to_add)
{
	struct xia_xid dst;
	char *str_lladdr;
	char strid[XIA_XID_MAX];
	unsigned char lladdr[MAX_ADDR_LEN];
	int lladdr_len;
	const char *dev;
	unsigned oif;

	if (argc != 4) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[2], "dev") || strcmp(argv[0], "lladdr")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}

	str_lladdr = argv[1];
	lladdr_len = lladdr_pton(str_lladdr, lladdr, sizeof(lladdr));
	if (lladdr_len < 0) {
		fprintf(stderr, "Invalid link layer address: '%s'\n",
			str_lladdr);
		return lladdr_len;
	}

	dev = argv[3];
	oif = ll_name_to_index(dev);
	if (!oif) {
		fprintf(stderr, "Cannot find device '%s'\n", dev);
		return -1;
	}
	form_ether_xid(oif, lladdr, XIA_XID_MAX*2, strid);

	xrt_get_ppal_id("ether", usage, &dst, strid);
	return modify_neigh(&dst, lladdr, lladdr_len, oif, to_add);
}

static int do_addneigh(int argc, char **argv)
{
	return do_Xneigh_common(argc, argv, 1);
}

static int do_delneigh(int argc, char **argv)
{
	return do_Xneigh_common(argc, argv, 0);
}

static struct
{
	xid_type_t	xid_type;
} filter;

static inline void reset_filter(void)
{
	memset(&filter, 0, sizeof(filter));
	assert(!ppal_name_to_type("ether", &filter.xid_type));
}

static int print_interface(const struct sockaddr_nl *who, struct nlmsghdr *n,
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
	if (table != XRTABLE_LOCAL_INDEX)
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

	assert(!r->rtm_src_len);
	assert(!(r->rtm_flags & RTM_F_CLONED));

	fprintf(fp, "flags [");
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

/* XXX This function should be componentized in a library, little variances
 * are repeating themselves. See the same function in xipad.c.
 */
static int print_neigh(const struct sockaddr_nl *who, struct nlmsghdr *n,
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
	if (table != XRTABLE_MAIN_INDEX)
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

	if (tb[RTA_MULTIPATH]) {
		struct rtnl_xia_ether_addrs *rtha =
			RTA_DATA(tb[RTA_MULTIPATH]);
		int len = RTA_PAYLOAD(tb[RTA_MULTIPATH]);
		char ha[MAX_ADDR_LEN];

		if (RTHA_OK(rtha, len)) {
			/* We only have a header, nothing else. */
			assert(rtha->attr_len == sizeof(*rtha));

			assert(!lladdr_ntop(rtha->interface_addr, rtha->interface_addr_len,
				ha, sizeof(ha)));
			fprintf(fp, "lladdr: %s\tdev: %s\n", ha,
				ll_index_to_name(rtha->interface_index));
		}
	}

	assert(!r->rtm_src_len);
	/* XXX It should go to be printed out in flags. */
	assert(!(r->rtm_flags & RTM_F_CLONED));

	/* XXX This should become a function, and removed mixed flags, that is,
	 * it doesn't make sense to have RTNH_F_* and RTM_F_* together.
	 */
	fprintf(fp, "flags [");
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

static int showinfo(rtnl_filter_t filter)
{
	reset_filter();

	if (rtnl_wilddump_request(&rth, AF_XIA, RTM_GETROUTE) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}
	if (rtnl_dump_filter(&rth, filter, stdout, NULL, NULL) < 0) {
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
	if (!matches(name, "interfaces")) {
		return showinfo(print_interface);
	}
	else if (!matches(name, "neighs")) {
		return showinfo(print_neigh);
	}
	else {
		fprintf(stderr, "Unknown routing table '%s', it must be either 'interface', or 'neighs'\n",
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
	{ "addinterface",	do_addlocal	},
	{ "delinterface",	do_dellocal	},
	{ "addneigh",	do_addneigh	},
	{ "delneigh",	do_delneigh	},
	{ "show",	do_show },
	{ "help",	do_help	},
	{ 0,		0		}
};

int do_ether(int argc, char **argv)
{
	assert(!ll_init_map(&rth));
	return do_cmd(cmds, "Command", "xip ether help", argc, argv);
}
