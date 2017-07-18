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

#include "xip_common.h"
#include "utils.h"
#include "ll_map.h"
#include "libnetlink.h"
#include "xiart.h"

#define IFINDEX_STR_SIZE 8
#define XIA_LLADDR_LEN 12

static int usage(void)
{
	fprintf(stderr,
"Usage:	xip ether { addinterface | delinterface } dev IF_NAME\n"
"       xip ether { addneigh | delneigh } ID dev IF_NAME\n"
"		xip ether show { interfaces | neighs }\n"
"where	ID := HEXDIGIT{20}\n"
"	DEV := STRING NUMBER\n");
	return -1;
}

static void form_ether_xid(unsigned oif, unsigned char *lladdr, unsigned tlen, const char *id)
{
	memset(id, 0, sizeof(*id));
	snprintf(id, tlen+1, "%08x%s", oif, lladdr);
	id[sizeof(*id)]='\0';
	id[tlen] = '0';
}

static void get_neigh_addr_from_id(const char *id, unsigned char *lladdr, unsigned *alen)
{
	*alen = XIA_LLADDR_LEN * sizeof(char);
	strncpy(lladdr, id + (IFINDEX_STR_SIZE * sizeof(char)), (*alen));
	lladdr[alen] = '\0';
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
	form_ether_xid(oif, lladdr, (IFINDEX_STR_SIZE + addrlen), strid);

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
	unsigned char lladdr[MAX_ADDR_LEN];
	int lladdr_len;
	const char *dev;
	unsigned oif;

	if (argc != 3) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[1], "dev")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}
	xrt_get_ppal_id("ether", usage, &dst, argv[0]);

	dev = argv[2];
	oif = ll_name_to_index(dev);
	if (!oif) {
		fprintf(stderr, "Cannot find device '%s'\n", dev);
		return -1;
	}
	get_neigh_addr_from_id(argv[0],lladdr,lladdr_len);

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
	{ "show",	do_show		},
	{ "help",	do_help		},
	{ 0,		0		}
};

int do_ether(int argc, char **argv)
{
	assert(!ll_init_map(&rth));
	return do_cmd(cmds, "Command", "xip ether help", argc, argv);
}
