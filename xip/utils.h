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

#endif /* HEADER_UTILS_H */
