#ifndef _RTNL_H
#define _RTNL_H

#include <libmnl/libmnl.h>

extern int rtnl_talk(const struct mnl_socket *nl_socket, const void *buf, const size_t siz);

#endif /* RTNL_H */
