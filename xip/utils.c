#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "utils.h"

int show_stats = 0;
int show_details = 0;
int oneline = 0;
int timestamp = 0;
char *_SL_ = NULL;
int force = 0;

int matches(const char *cmd, const char *pattern)
{
	size_t len = strlen(cmd);
	if (len > strlen(pattern))
		return -1;
	return memcmp(pattern, cmd, len);
}

int do_cmd(const struct cmd *cmds, const char *entity, const char *help,
	int argc, char **argv)
{
	const char *argv0;
	const struct cmd *c;

	assert(argc >= 1);
	argv0 = argv[0];

	for (c = cmds; c->cmd; c++) {
		if (matches(argv0, c->cmd) == 0)
			return c->func(argc-1, argv+1);
	}

	fprintf(stderr, "%s \"%s\" is unknown, try \"%s\".\n",
		entity, argv0, help);
	return -1;
}

/* XXX Does one really need this global variable? */
int cmdlineno;

ssize_t getcmdline(char **linep, size_t *lenp, FILE *in)
{
	ssize_t cc;
	char *cp;

	if ((cc = getline(linep, lenp, in)) < 0)
		return cc;	/* eof or error */
	++cmdlineno;

	cp = strchr(*linep, '#');
	if (cp)
		*cp = '\0';

	while ((cp = strstr(*linep, "\\\n")) != NULL) {
		char *line1 = NULL;
		size_t len1 = 0;
		ssize_t cc1;

		if ((cc1 = getline(&line1, &len1, in)) < 0) {
			fprintf(stderr, "Missing continuation line\n");
			return cc1;
		}

		++cmdlineno;
		*cp = 0;

		cp = strchr(line1, '#');
		if (cp)
			*cp = '\0';

		*lenp = strlen(*linep) + strlen(line1) + 1;
		*linep = realloc(*linep, *lenp);
		if (!*linep) {
			fprintf(stderr, "Out of memory\n");
			*lenp = 0;
			return -1;
		}
		cc += cc1 - 2;
		strcat(*linep, line1);
		free(line1);
	}
	return cc;
}

int makeargs(char *line, char *argv[], int maxargs)
{
	static const char ws[] = " \t\r\n";
	char *cp;
	int argc = 0;

	for (cp = strtok(line, ws); cp; cp = strtok(NULL, ws)) {
		if (argc >= (maxargs - 1)) {
			fprintf(stderr, "Too many arguments to command\n");
			exit(1);
		}
		argv[argc++] = cp;
	}
	argv[argc] = NULL;

	return argc;
}
