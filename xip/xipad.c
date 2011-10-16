#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <net/xia_fib.h>

#include "xip_common.h"
#include "utils.h"
#include "dag.h"

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

static int get_ad(const char *s, struct xia_xid *dst)
{
	if (xia_ptoid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid ID '%s'\n", s);
		return usage();
	}
	/* XXX Get rid of magic numbers! */
	dst->xid_type = __cpu_to_be32(0x10);
}

static int get_xid(const char *s, struct xia_xid *dst)
{
	if (xia_ptoxid(s, INT_MAX, dst) < 0) {
		fprintf(stderr, "Invalid XID '%s'\n", s);
		return usage();
	}
}

static int do_addroute(int argc, char **argv)
{
	int tbl_id;
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
	oif = ll_name_to_index(argv[6]);

	/* TODO Implement me! */
	printf("tbl %i dev %i xid %s\n", tbl_id, oif, argv[4]);
	return -1;
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

	/* TODO Implement me! */
	printf("tbl %i id %s\n", tbl_id, argv[0]);
	return -1;
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

	/* TODO Implement me! */
	printf("tbl %i\n", tbl_id);
	return -1;
}

static int do_help(int argc, char **argv)
{
	usage();
	exit(-1);
}

static const struct cmd cmds[] = {
	{ "addroute",	do_addroute	},
	{ "delroute",	do_delroute	},
	{ "dump",	do_dump		},
	{ "help",	do_help		},
	{ 0 }
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
