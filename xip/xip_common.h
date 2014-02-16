#ifndef HEADER_XIP_COMMON
#define HEADER_XIP_COMMON

/* From xip.c */
extern struct rtnl_handle rth;

/* From xipad.c */
int do_ad(int argc, char **argv);
/* From xiphid.c */
int do_hid(int argc, char **argv);
/* From xipserval.c */
int do_serval(int argc, char **argv);
/* From xipu4id.c */
int do_u4id(int argc, char **argv);
/* From xipxdp.c */
int do_xdp(int argc, char **argv);
/* From xipdst.c */
int do_dst(int argc, char **argv);

#endif /* HEADER_XIP_COMMON */
