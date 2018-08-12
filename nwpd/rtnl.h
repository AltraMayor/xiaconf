#ifndef _RTNL_H
#define _RTNL_H

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

typedef void (*rtnl_filter_t)(struct nlmsghdr *n, void *);

extern int rtnl_talk(const struct mnl_socket *, struct nlmsghdr *);
extern int parse_rtattr(struct rtattr **, int, struct rtattr *, int);
extern int rtnl_get_table(struct rtmsg *, struct rtattr **);
extern int rtnl_send_wilddump_request(const struct mnl_socket *, const int,
                                      const int, rtnl_filter_t, void *);
#endif /* RTNL_H */
