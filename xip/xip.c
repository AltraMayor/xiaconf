#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* XXX Does one need any of them?
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
*/

#include "SNAPSHOT.h"
#include "libnetlink.h"
#include "utils.h"

int show_stats = 0;
int show_details = 0;
int oneline = 0;
int timestamp = 0;
char *_SL_ = NULL;
int force = 0;

static char *batch_file = NULL;

struct rtnl_handle rth = { .fd = -1 };

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr,
"Usage: xip [ OPTIONS ] OBJECT { COMMAND | help }\n"
"       xip [ -force ] -batch filename\n"
"where  OBJECT := { hid }\n"
"       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] |\n"
"                    -o[neline] | -t[imestamp] | -b[atch] [filename] }\n");
	exit(-1);
}

static int do_help(int argc, char **argv)
{
	usage();
}

static const struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
} cmds[] = {
	/*{ "hid", 	do_hid },*/
	{ "help",       do_help },
	{ 0 }
};

static int do_cmd(const char *argv0, int argc, char **argv)
{
	const struct cmd *c;

	for (c = cmds; c->cmd; c++) {
		if (matches(argv0, c->cmd) == 0)
			return c->func(argc-1, argv+1);
	}

	fprintf(stderr, "Object \"%s\" is unknown, try \"xip help\".\n", argv0);
	return -1;
}

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

		if (do_cmd(largv[0], largc, largv)) {
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
				usage();
			batch_file = argv[1];
		} else if (matches(opt, "-help") == 0) {
			usage();
		} else {
			fprintf(stderr, "Option \"%s\" is unknown, "
				"try \"xip -help\".\n", opt);
			exit(-1);
		}
		argc--;	argv++;
	}

	_SL_ = oneline ? "\\" : "\n" ;

	if (batch_file)
		return batch(batch_file);

	if (argc > 1) {
		int rc;
		if (rtnl_open(&rth, 0) < 0)
			exit(1);
		rc = do_cmd(argv[1], argc-1, argv+1);
		rtnl_close(&rth);
		return rc;
	}

	usage();
}
