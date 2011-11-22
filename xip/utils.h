#ifndef HEADER_UTILS_H
#define HEADER_UTILS_H

#include <stdio.h>

/* Global variables. */
extern int show_stats;
extern int show_details;
extern int oneline;
extern int timestamp;
extern char *_SL_;
extern int force;

struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
};

int matches(const char *arg, const char *pattern);
int do_cmd(const struct cmd *cmds, const char *entity, const char *help,
	int argc, char **argv);

extern int cmdlineno;

/* Like glibc getline but handle continuation lines and comments. */
ssize_t getcmdline(char **line, size_t *len, FILE *in);
/* split command line into argument vector. */
int makeargs(char *line, char *argv[], int maxargs);

#define UNUSED(x) (void)x

/** lladdr_ntop - convert @lladdr, a link layer address of size @alen, into
 *		a human-readable, NULL-terminated string in @buf,
 *		whose maximum size is @blen.
 * RETURN
 *	Return zero if success; otherwise a negative number.
 */
int lladdr_ntop(unsigned char *lladdr, int alen, char *buf, int blen);

/** lladdr_pton - convert @str, a NULL-terminated string, into
 *		its corresponding link layer address and stores it in @lladdr.
 *		@alen is the size of @lladdr.
 * RETURN
 *	Return the length of @lladdr if success; otherwise a negative number.
 */
int lladdr_pton(char *str, char *lladdr, int alen);

#endif /* HEADER_UTILS_H */
