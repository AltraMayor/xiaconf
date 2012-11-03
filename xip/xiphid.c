#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <asm/byteorder.h>
#include <asm-generic/errno-base.h>
#include <net/xia.h>
#include <net/xia_dag.h>
#include <net/xia_fib.h>

/* XXX <sys/socket.h> is included before <net/xia_hid.h> because it adds
 * <linux/netdevice.h>, which, in turn, adds <linux/if.h>, and struct ifreq
 * in <linux/if.h> is meant to use userland struct sockaddr.
 * This is not pretty, but one has to be careful to solve this, because
 * current applications may break.
 * Notice that struct ifreq isn't even used in this file.
 */
#include <sys/socket.h>
#include <net/xia_hid.h>

#include "xip_common.h"
#include "xia_socket.h"
#include "libnetlink.h"
#include "ppk.h"
#include "utils.h"
#include "ppal_map.h"
#include "ll_map.h"

#ifndef HID_PRV_PATH
#define HID_PRV_PATH "/etc/xia/hid/prv/"
#endif

static int usage(void)
{
	fprintf(stderr,
"Usage: xip hid { new | getpub } PRVFILENAME\n"
"       xip hid { addaddr | deladdr } PRVFILENAME\n"
"       xip hid showaddrs\n"
"       xip hid { addneigh | delneigh } ID lladdr LLADDR dev DEV\n"
"       xip hid showneighs\n"
"where	ID := HEXDIGIT{20}\n"
"       XID := PRINCIPAL '-' ID\n"
"	PRINCIPAL := '0x' NUMBER | STRING\n"
"	LLADDR := HEXDIGIT{1,2} (':' HEXDIGIT{1,2})*\n"
"	DEV := STRING NUMBER\n");
	return -1;
}

/* get_ffn - obtains Final FileName.
 *
 * @ffn must be at least PATH_MAX (available in <limits.h>).
 *
 * If @filename includes a '/', it assumes to be a filename with full path,
 * otherwise it assumes it is to be stored in the default configuration path.
 */
static void get_ffn(char *ffn, const char *filename)
{
	if (strchr(filename, '/')) {
		strncpy(ffn, filename, PATH_MAX);
		ffn[PATH_MAX - 1] = '\0';
	} else {
		int left = PATH_MAX - strlen(HID_PRV_PATH) - 1;
		strcpy(ffn, HID_PRV_PATH);
		strncat(ffn, filename, left);
	}
}

static int xid_from_key(struct xia_xid *xid, char *ppal, PPK_KEY *pkey)
{
	int hashlen;
	int rc;

	/* Set XID type. */
	rc = ppal_name_to_type(ppal, &xid->xid_type);
	if (rc)
		return rc;

	/* Set ID. */
	hashlen = XIA_XID_MAX;
	rc = hash_of_key(pkey, xid->xid_id, &hashlen);
	if (rc)
		return rc;
	assert(hashlen == XIA_XID_MAX);

	return 0;
}

/* write_new_hid_file - generates a new HID and save to @filename.
 *
 *	In fact, all that is genereaged is a private key.
 *
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
static int write_new_hid_file(const char *filename)
{
	FILE *f;
	PPK_KEY *pkey;
	int rc;

	rc = -1;
	f = fopen(filename, "w");
	if (!f)
		goto out;

	rc = -ENOMEM;
	pkey = gen_keys();
	if (!pkey)
		goto close_f;

	rc = write_prvpem(pkey, f);
	if (rc)
		goto pkey;

	rc = 0;

pkey:
	ppk_free_key(pkey);
close_f:
	fclose(f);
out:
	return rc;
}

static int do_newhid(int argc, char **argv)
{
	char ffn[PATH_MAX];

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	
	get_ffn(ffn, argv[0]);
	if (write_new_hid_file(ffn)) {
		perror("Couldn't create new HID file");
		return -1;
	}

	return 0;
}

/* read_prv_key_from_file - load @filename into @ppkey.
 * (*ppkey) must not be allocated; it'll be allocated if no error is found.
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
static int read_prv_key_from_file(const char *filename, PPK_KEY **ppkey)
{
#define HID_FILE_BUFFER_SIZE (8*1024)

	FILE *f;
	char buf[HID_FILE_BUFFER_SIZE];
	int len;

	/* Read private key. */
	f = fopen(filename, "r");
	if (!f)
		return -1;
	len = fread(buf, 1, HID_FILE_BUFFER_SIZE, f);
	assert(len < HID_FILE_BUFFER_SIZE);
	fclose(f);

	*ppkey = pkey_of_prvpem(buf, len);
	return *ppkey ? 0 : -1;
}

/* write_pub_hid_file - reads @infilename, a file with the private key, and
 * writes @outf a file with the HID, and its public key.
 *
 * RETURN
 *	returns zero on success; otherwise a negative number.
 */
static int write_pub_hid_file(const char *infilename, FILE *outf)
{
	PPK_KEY *pkey;
	struct xia_xid xid;
	char buf[XIA_MAX_STRXID_SIZE];
	int rc;
	
	rc = read_prv_key_from_file(infilename, &pkey);
	if (rc)
		goto out;

	/* Print XID. */
	rc = xid_from_key(&xid, "hid", pkey);
	if (rc)
		goto pkey;
	rc = xia_xidtop(&xid, buf, sizeof(buf));
	if (rc < 0)
		goto pkey;
	fprintf(outf, "%s\n\n", buf);

	/* Print public key. */
	rc = write_pubpem(pkey, outf);
	if (rc)
		goto pkey;

	rc = 0;
pkey:
	ppk_free_key(pkey);
out:
	return rc;
}

static int do_getpub(int argc, char **argv)
{
	char ffn[PATH_MAX];

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	
	get_ffn(ffn, argv[0]);
	if (write_pub_hid_file(ffn, stdout)) {
		fprintf(stderr, "Couldn't create public HID file\n");
		return -1;
	}

	return 0;
}

static int modify_addr(struct xia_xid *dst, int to_add)
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

static int do_Xaddr_common(int argc, char **argv, int to_add)
{
	struct xia_xid xid;
	char ffn[PATH_MAX];
	PPK_KEY *pkey;

	if (argc != 1) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	
	get_ffn(ffn, argv[0]);
	if (read_prv_key_from_file(ffn, &pkey)) {
		fprintf(stderr, "Couldn't read private HID file\n");
		return -1;
	}

	assert(!xid_from_key(&xid, "hid", pkey));
	ppk_free_key(pkey);

	return modify_addr(&xid, to_add);
}

static int do_addaddr(int argc, char **argv)
{
	return do_Xaddr_common(argc, argv, 1);
}

static int do_deladdr(int argc, char **argv)
{
	return do_Xaddr_common(argc, argv, 0);
}

static struct
{
	xid_type_t	xid_type;
} filter;

static inline void reset_filter(void)
{
	memset(&filter, 0, sizeof(filter));
	assert(!ppal_name_to_type("hid", &filter.xid_type));
}

/* XXX This function should be componentized in a library, little variances
 * are repeating themselves. See the same function in xipad.c.
 */
static int print_addr(const struct sockaddr_nl *who, struct nlmsghdr *n,
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

/* XXX This should become a function in a library, there're very
 * little variance of this repeated code instances
 */
static int showaddrs(void)
{
	reset_filter();

	if (rtnl_wilddump_request(&rth, AF_XIA, RTM_GETROUTE) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}
	if (rtnl_dump_filter(&rth, print_addr, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

static int do_showaddrs(int argc, char **argv)
{
	UNUSED(argv);
	if (argc != 0) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	return showaddrs();
}

/* XXX This function, and xipad.c:get_ad should be reshaped, and
 * go to a library.
 */
static void get_hid(const char *s, struct xia_xid *dst)
{
	if (xia_ptoid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid ID '%s'\n", s);
		usage();
		exit(1);
	}
	assert(!ppal_name_to_type("hid", &dst->xid_type));
}

static int modify_neigh(struct xia_xid *dst, char *lladdr, int lladdr_len,
	unsigned oif, int to_add)
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
	char lladdr[MAX_ADDR_LEN];
	int lladdr_len;
	const char *dev;
	unsigned oif;

	if (argc != 5) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	if (strcmp(argv[1], "lladdr") ||
	    strcmp(argv[3], "dev")) {
		fprintf(stderr, "Wrong parameters\n");
		return usage();
	}
	get_hid(argv[0], &dst);

	str_lladdr = argv[2];
	lladdr_len = lladdr_pton(str_lladdr, lladdr, sizeof(lladdr));
	if (lladdr_len < 0) {
		fprintf(stderr, "Invalid link layer address: '%s'\n",
			str_lladdr);
		return lladdr_len;
	}

	dev = argv[4];
	oif = ll_name_to_index(dev);
	if (!oif) {
		fprintf(stderr, "Cannot find device '%s'\n", dev);
		return -1;
	}

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
		struct rtnl_xia_hid_hdw_addrs *rtha =
			RTA_DATA(tb[RTA_MULTIPATH]);
		int len = RTA_PAYLOAD(tb[RTA_MULTIPATH]);
		char ha[MAX_ADDR_LEN];

		while (RTHA_OK(rtha, len)) {
			/* We only have a header, nothing else. */
			assert(rtha->hha_len == sizeof(*rtha));

			assert(!lladdr_ntop(rtha->hha_ha, rtha->hha_addr_len,
				ha, sizeof(ha)));
			fprintf(fp, "lladdr: %s\tdev: %s\n", ha,
				ll_index_to_name(rtha->hha_ifindex));

			len -= NLMSG_ALIGN(rtha->hha_len);
			rtha = RTHA_NEXT(rtha);
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

/* XXX This should become a function in a library, there're very
 * little variance of this repeated code instances
 */
static int showneighs(void)
{
	reset_filter();

	if (rtnl_wilddump_request(&rth, AF_XIA, RTM_GETROUTE) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}
	if (rtnl_dump_filter(&rth, print_neigh, stdout, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	return 0;
}

static int do_showneighs(int argc, char **argv)
{
	UNUSED(argv);
	if (argc != 0) {
		fprintf(stderr, "Wrong number of parameters\n");
		return usage();
	}
	return showneighs();
}

static int do_help(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);
	usage();
	exit(1);
}

static const struct cmd cmds[] = {
	{ "new",	do_newhid	},
	{ "getpub",	do_getpub	},
	{ "addaddr",	do_addaddr	},
	{ "deladdr",	do_deladdr	},
	{ "showaddrs",	do_showaddrs	},
	{ "addneigh",	do_addneigh	},
	{ "delneigh",	do_delneigh	},
	{ "showneighs",	do_showneighs	},
	{ "help",	do_help		},
	{ 0,		0		}
};

int do_hid(int argc, char **argv)
{
	assert(!init_ppal_map());
	assert(!ll_init_map(&rth));
	return do_cmd(cmds, "Command", "xip hid help", argc, argv);
}
