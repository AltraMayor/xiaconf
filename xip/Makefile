CC = gcc
CFLAGS = -Wall -MMD $(ADD_CFLAGS)

PPK_OBJ = ppk.o test_ppk.o

PPAL_OBJ = dag.o test_ppal_map.o
PPAL_OBJ_PROD = ppal_map.o
PPAL_OBJ_TEST = test_flags_ppal_map.o

XIPHID_OBJ_PROD = xiphid.o
XIPHID_OBJ_TEST = test_flags_xiphid.o

XIP_OBJ = $(XIP_OBJ_BASE) $(XIP_OBJ_EXTRA) $(XIP_OBJ_INCLUDE)
XIP_OBJ_BASE = libnetlink.o
XIP_OBJ_EXTRA = ppk.o utils.o ll_map.o xip.o
XIP_OBJ_INCLUDE = dag.o xipad.o xipad.o xipdst.o xipxdp.o
XIP_OBJ_PROD = $(PPAL_OBJ_PROD) $(XIPHID_OBJ_PROD)
XIP_OBJ_TEST = $(PPAL_OBJ_TEST) $(XIPHID_OBJ_TEST)

$(sort $(PPK_OBJ) $(XIP_OBJ_EXTRA)) : ADD_CFLAGS = -Wextra
$(sort $(PPAL_OBJ) $(XIP_OBJ_INCLUDE) $(XIP_OBJ_PROD)) : ADD_CFLAGS = \
-Wextra -I ../kernel-include
$(XIPHID_OBJ_TEST) : ADD_CFLAGS = -Wextra -c -I ../kernel-include \
-DHID_PATH=\"../etc-test/xia/hid/\"
$(PPAL_OBJ_TEST) : ADD_CFLAGS = -Wextra -I ../kernel-include \
-DPRINCIPAL_FILENAME=\"../etc-test/xia/principals\"


all : xip test_flags_xip test_flags_test_ppal_map test_ppk



xip : $(XIP_OBJ) $(XIP_OBJ_PROD)
	$(CC) -o $@ $^ -lcrypto

test_flags_xip : $(XIP_OBJ) $(XIP_OBJ_TEST)
	$(CC) -o $@ $^ -lcrypto

test_ppal_map : $(PPAL_OBJ) $(PPAL_OBJ_PROD)
	$(CC) -o $@ $^ -lcrypto

test_flags_test_ppal_map : $(PPAL_OBJ) $(PPAL_OBJ_TEST)
	$(CC) -o $@ $^ -lcrypto

test_ppk : $(PPK_OBJ)
	$(CC) -o $@ $^ -lcrypto



test_flags_ppal_map.o : ppal_map.c
	$(CC) $(CFLAGS) -c $< -o $@

test_flags_xiphid.o : xiphid.c
	$(CC) $(CFLAGS) -c $< -o $@

-include *.d



PHONY : clean
clean :
	rm -f *.o *.pem *.d xip test_xip test_ppk test_ppal_map \
	test_flags_test_ppal_map test_flags_xip
