#ifndef HEADER_XIP_COMMON
#define HEADER_XIP_COMMON

/* From xip.c */
extern struct rtnl_handle rth;

/* From xiphid.c */
int do_hid(int argc, char **argv);
/* From xipad.c */
int do_ad(int argc, char **argv);

#endif /* HEADER_XIP_COMMON */
