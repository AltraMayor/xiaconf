#include <stdio.h>
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

int lladdr_ntop(unsigned char *lladdr, int alen, char *buf, int blen)
{
	int i;
	char *sep = "";
	char *p = buf;

	for (i = 0; i < alen; i++) {
		int count = snprintf(p, blen, "%s%02x", sep, lladdr[i]);
		if (count < 0 || count >= blen)
			return -1;
		p += count;
		blen -= count;
		sep = ":";
	}
	return 0;
}

static inline int hexd_to_val(int ch)
{
	if ('0' <= ch && ch <= '9')
		return ch - '0' + 0;
	if ('A' <= ch && ch <= 'F')
		return ch - 'A' + 10;
	if ('a' <= ch && ch <= 'f')
		return ch - 'a' + 10;
	return -1;
}

int lladdr_pton(char *str, char *lladdr, int alen)
{
	char *p = str;	/* String cursor.				*/
	int v;		/* Temporary value.				*/
	int octet;	/* The octet being unconvered.			*/
	int digit = 0;	/* State of the machine.			*/
	int count = 0;	/* Number of octets pushed into @lladdr.	*/

	while (*p && alen > 0) {
		switch (digit) {
		case 0:
			/* We expect a hexdigit. */
			v = hexd_to_val(*p);
			if (v < 0)
				return -1;
			octet = v;
			digit++;
			break;
		case 1:
			/* We expect a hexdigit or ':'. */
			if (*p == ':') {
				*(lladdr++) = octet;
				alen--;
				count++;
			} else {
				v = hexd_to_val(*p);
				if (v < 0)
					return -1;
				octet = (octet << 4) + v;
			}
			digit++;
			break;
		case 2:
			/* We expect a ':'. */
			if (*p == ':') {
				*(lladdr++) = octet;
				alen--;
				count++;
			} else
				return -1;
			digit = 0;
			break;
		default:
			return -1;
		}
		p++;
	}

	/* The tests read as follows:
	 *	1. String isn't fully parsed.
	 *	2. There's a more octet to add, but @lladdr is full.
	 *	3. No octet was found.
	 */
	if (*p || (digit && alen <= 0) || (count == 0))
		return -1;

	if (digit) {
		assert(alen > 0);
		*lladdr = octet;
		count++;
	}

	return count;
}
