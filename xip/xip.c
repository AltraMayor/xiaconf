#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ppal_map.h>

#include "xip_common.h"
#include "SNAPSHOT.h"
#include "libnetlink.h"
#include "utils.h"

struct rtnl_handle rth = { .fd = -1 };

static int usage(void)
{
	fprintf(stderr,
"Usage: xip [ OPTIONS ] OBJECT { COMMAND | help }\n"
"       xip [ -force ] -batch filename\n"
"where  OBJECT := { ad | dst | hid | serval | u4id | xdp | zf }\n"
"       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] |\n"
"                    -o[neline] | -t[imestamp] | -b[atch] [filename] }\n");
	return -1;
}

static int do_help(int argc, char **argv)
{
	UNUSED(argc);
	UNUSED(argv);
	usage();
	exit(1);
}

static const struct cmd cmds[] = {
	{ "ad", 	do_ad		},
	{ "dst",	do_dst		},
	{ "hid", 	do_hid		},
	{ "serval",	do_serval	},
	{ "u4id",	do_u4id		},
	{ "xdp",	do_xdp		},
	{ "zf",		do_zf		},

	{ "help",       do_help		},
	{ 0,		0		}
};

static inline int my_do_cmd(int argc, char **argv)
{
	return do_cmd(cmds, "Object", "xip help", argc, argv);
}

static char *batch_file = NULL;

static int batch(const char *name)
{
	char *line = NULL;
	size_t len = 0;
	int ret = 0;

	if (name && strcmp(name, "-") != 0) {
		if (freopen(name, "r", stdin) == NULL) {
			fprintf(stderr,
				"Cannot open file \"%s\" for reading: %s\n",
				name, strerror(errno));
			return -1;
		}
	}

	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		return -1;
	}

	cmdlineno = 0;
	while (getcmdline(&line, &len, stdin) != -1) {
		char *largv[100];
		int largc;

		largc = makeargs(line, largv, 100);
		if (largc == 0)
			continue;	/* blank line */

		if (my_do_cmd(largc, largv)) {
			fprintf(stderr, "Command failed %s:%d\n",
				name, cmdlineno);
			ret = 1;
			if (!force)
				break;
		}
	}
	if (line)
		free(line);

	rtnl_close(&rth);
	return ret;
}

int main(int argc, char **argv)
{
	const char *ppal_map_file = NULL;

	/* Take care of options. */
	while (argc > 1) {
		char *opt = argv[1];
		if (strcmp(opt, "--") == 0) {
			argc--; argv++;
			break;
		}
		if (opt[0] != '-')
			break;
		if (opt[1] == '-')
			opt++;
		if (matches(opt, "-stats") == 0 ||
			   matches(opt, "-statistics") == 0) {
			++show_stats;
		} else if (matches(opt, "-details") == 0) {
			++show_details;
		} else if (matches(opt, "-oneline") == 0) {
			++oneline;
		} else if (matches(opt, "-timestamp") == 0) {
			++timestamp;
		} else if (matches(opt, "-Version") == 0) {
			printf("xip utility, xiaconf-ss%s\n", SNAPSHOT);
			exit(0);
		} else if (matches(opt, "-force") == 0) {
			++force;
		} else if (matches(opt, "-batch") == 0) {
			argc--;
			argv++;
			if (argc <= 1)
				return usage();
			batch_file = argv[1];
		} else if (matches(opt, "-help") == 0) {
			return usage();
		} else if (matches(opt, "-ppal-map") == 0) {
			argc--;
			argv++;
			if (argc <= 1)
				return usage();
			ppal_map_file = argv[1];
		} else {
			fprintf(stderr, "Option \"%s\" is unknown, "
				"try \"xip -help\".\n", opt);
			exit(1);
		}
		argc--;	argv++;
	}

	_SL_ = oneline ? "\\" : "\n" ;

	assert(!init_ppal_map(ppal_map_file));

	if (batch_file)
		return batch(batch_file);

	if (argc > 1) {
		int rc;
		if (rtnl_open(&rth, 0) < 0)
			exit(1);
		rc = my_do_cmd(argc-1, argv+1);
		rtnl_close(&rth);
		return rc;
	}

	return usage();
}
