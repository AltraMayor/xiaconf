#ifndef _NET_XIA_HID_H
#define _NET_XIA_HID_H

struct rtnl_xia_hid_hdw_addrs {
	__u16		hha_len;
	__u8		hha_addr_len;
	__u8		hha_ha[MAX_ADDR_LEN];
	int		hha_ifindex;
};

#endif /* _NET_XIA_HID_H */
