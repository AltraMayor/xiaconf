#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <net/xia_fib.h>
#include <net/xia_route.h>
#include <xia_socket.h>

#include "xip_common.h"
#include "utils.h"
#include "libnetlink.h"

static int usage(void)
{
	fprintf(stderr,
"Usage:	xip dst show\n"
"	xip dst flush\n");
	return -1;
}

#define SIZE_OF_DEST	(sizeof(struct xia_xid[XIA_OUTDEGREE_MAX]))

static const char *action_to_str(__u8 action)
{
	switch (action) {
	case XDA_DIG:		return "XDA_DIG";
	case XDA_ERROR:		return "XDA_ERROR";
	case XDA_DROP:		return "XDA_DROP";
	case XDA_METHOD:	return "XDA_METHOD";
	case XDA_METHOD_AND_SELECT_EDGE: return "XDA_METHOD_AND_SELECT_EDGE";
	default: assert(0);
	}
}

static const char *chosen_edge_to_str(__s8 chosen_edge)
{
	switch (chosen_edge) {
	case -1: return "none";
	case  0: return "0";
	case  1: return "1";
	case  2: return "2";
	case  3: return "3";
	default: assert(0);
	}
}

static int print_cache(const struct sockaddr_nl *who, struct nlmsghdr *n,
	void *arg)
{
	FILE *fp = (FILE*)arg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX+1];
	const struct xia_xid *dst;
	const struct xip_dst_cachinfo *ci;
	int i;

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
	if (r->rtm_dst_len != SIZE_OF_DEST) {
		fprintf(stderr, "BUG: wrong rtm_dst_len %d\n", r->rtm_dst_len);
		return -1;
	}

	/* XXX Doesn't the kernel provide similar function? */
	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

	if (!tb[RTA_DST] || RTA_PAYLOAD(tb[RTA_DST]) != SIZE_OF_DEST)
		return -1;
	dst = (const struct xia_xid *)RTA_DATA(tb[RTA_DST]);

	/* Print edges (key). */
	fprintf(fp, "%sto\n", n->nlmsg_type == RTM_DELROUTE ? "Deleted " : "");
	for (i = 0; i < XIA_OUTDEGREE_MAX; i++) {
		fprintf(fp, "%i: ", i);
		/* XXX It got to use @fp! */
		print_xia_xid(dst);
		fprintf(fp, "\n");
		dst++;
	}

	/* Print information about DST entry. */
	if (!tb[RTA_PROTOINFO] || RTA_PAYLOAD(tb[RTA_PROTOINFO]) !=
		sizeof(struct xip_dst_cachinfo))
		return -1;
	ci = (const struct xip_dst_cachinfo *)RTA_DATA(tb[RTA_PROTOINFO]);
	fprintf(fp, "%s, key_hash=0x%x, chosen_edge=%s\n",
		ci->input ? "input" : "output", ci->key_hash,
		chosen_edge_to_str(ci->chosen_edge));
	fprintf(fp, "passthrough/sink_action=%s/%s\n",
		action_to_str(ci->passthrough_action),
		action_to_str(ci->sink_action));

	assert(!r->rtm_src_len);
	assert(r->rtm_flags & RTM_F_CLONED);

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

static int rtnl_rtcache_request(struct rtnl_handle *rth, int family)
{
	struct {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
	} req;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETROUTE;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.rtm.rtm_family = family;
	req.rtm.rtm_flags |= RTM_F_CLONED;

	return send(rth->fd, (void *)&req, sizeof(req), 0);
}

static int do_show(int argc, char **argv)
{
	UNUSED(argv);
	if (argc != 0) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}

	if (rtnl_rtcache_request(&rth, AF_XIA) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}
	if (rtnl_dump_filter(&rth, print_cache, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

static int do_flush(int argc, char **argv)
{
	struct {
		struct nlmsghdr 	n;
		struct rtmsg 		r;
	} req;

	UNUSED(argv);
	if (argc != 0) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELROUTE;

	req.r.rtm_family = AF_XIA;
	req.r.rtm_flags |= RTM_F_CLONED;
	req.r.rtm_table = XRTABLE_LOCAL_INDEX;
	req.r.rtm_protocol = RTPROT_BOOT;
	req.r.rtm_type = RTN_LOCAL;
	req.r.rtm_scope = RT_SCOPE_HOST;
	req.r.rtm_dst_len = 0;

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		exit(2);
	return 0;
}

static int do_help(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);
	usage();
	exit(1);
}

static const struct cmd cmds[] = {
	{ "show",	do_show		},
	{ "flush",	do_flush	},
	{ "help",	do_help		},
	{ 0,		0		}
};

int do_dst(int argc, char **argv)
{
	return do_cmd(cmds, "Command", "xip dst help", argc, argv);
}
