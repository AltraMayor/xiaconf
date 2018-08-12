#ifndef _LOG_H
#define _LOG_H

#include <net/xia.h>

#define LOG_LEVEL_DEBUG   0
#define LOG_LEVEL_INFO    1
#define LOG_LEVEL_WARNING 2
#define LOG_LEVEL_ERROR   3
#define LOG_LEVEL_FATAL   4

extern void nwpd_logf(int, const char *, ...);
extern void nwpd_perror(const char *);
extern char *xid_str(const struct xia_xid *);

#endif /* _LOG_H */
