#include <net/xia.h>
#include <net/xia_dag.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "log.h"
#include "globals.h"

void nwpd_logf(const int level, const char *fmt, ...)
{
        if (level < nwpd_config.log_level)
                return;
        char *level_str;

        switch (level) {
        case LOG_LEVEL_DEBUG:
                level_str = "debug";
                break;
        case LOG_LEVEL_INFO:
                level_str = "info";
                break;
        case LOG_LEVEL_WARNING:
                level_str = "warning";
                break;
        case LOG_LEVEL_ERROR:
                level_str = "error";
                break;
        case LOG_LEVEL_FATAL:
                level_str = "fatal";
                break;
        default:
                level_str = "unknown";
                break;
        }

        time_t t = time(NULL);

        fprintf(stderr, "[%s] [%s]: ", strtok(ctime(&t), "\n"), level_str);
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
}

void nwpd_perror(const char *str)
{
        nwpd_logf(LOG_LEVEL_ERROR, strerror(errno));
}

char *xid_str(const struct xia_xid *xid)
{
        static char buf[XIA_MAX_STRXID_SIZE];
        xia_xidtop(xid, buf, XIA_MAX_STRXID_SIZE);
        return buf;

}
