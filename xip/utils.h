#ifndef HEADER_UTILS_H
#define HEADER_UTILS_H

#include <stdio.h>

extern int show_stats;
extern int show_details;
extern int oneline;
extern int timestamp;
extern char *_SL_;
extern int force;

int matches(const char *arg, const char *pattern);

extern int cmdlineno;

/* Like glibc getline but handle continuation lines and comments. */
extern ssize_t getcmdline(char **line, size_t *len, FILE *in);
/* split command line into argument vector. */
extern int makeargs(char *line, char *argv[], int maxargs);

#endif /* HEADER_UTILS_H */
