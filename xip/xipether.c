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
	{ "addneigh",	do_addroute	},
	{ "delneigh",	do_delroute	},
	{ "show",	do_show		},
	{ "help",	do_help		},
	{ 0,		0		}
};

int do_ether(int argc, char **argv)
{
	return do_cmd(cmds, "Command", "xip ether help", argc, argv);
}
