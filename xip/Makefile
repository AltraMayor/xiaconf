CC = gcc
CFLAGS = -Wall -MMD $(ADD_CFLAGS)

PPK_OBJ = ppk.o test_ppk.o

XIPHID_OBJ_PROD = xiphid.o
XIPHID_OBJ_TEST = test_flags_xiphid.o

XIP_OBJ = $(XIP_OBJ_BASE) $(XIP_OBJ_EXTRA) $(XIP_OBJ_INCLUDE)
XIP_OBJ_BASE = libnetlink.o
XIP_OBJ_EXTRA = ppk.o utils.o ll_map.o xip.o
XIP_OBJ_INCLUDE = xipad.o xipad.o xipdst.o xipxdp.o
XIP_OBJ_PROD = $(XIPHID_OBJ_PROD)
XIP_OBJ_TEST = $(XIPHID_OBJ_TEST)

$(sort $(PPK_OBJ) $(XIP_OBJ_EXTRA)) : ADD_CFLAGS = -Wextra
$(sort $(XIP_OBJ_INCLUDE) $(XIP_OBJ_PROD)) : ADD_CFLAGS = \
-Wextra -I ../kernel-include -I ../include
$(XIPHID_OBJ_TEST) : ADD_CFLAGS = -Wextra -c -I ../kernel-include \
-I ../include -DHID_PATH=\"../etc-test/xia/hid/\"

TARGETS = xip test_flags_xip test_ppk

all : $(TARGETS)

xip : $(XIP_OBJ) $(XIP_OBJ_PROD)
	$(CC) -o $@ $^ -lcrypto -L ../libxia -lxia

test_flags_xip : $(XIP_OBJ) $(XIP_OBJ_TEST)
	$(CC) -o $@ $^ -lcrypto -L ../libxia -lxia

test_ppk : $(PPK_OBJ)
	$(CC) -o $@ $^ -lcrypto

test_flags_xiphid.o : xiphid.c
	$(CC) $(CFLAGS) -c $< -o $@

-include *.d


PHONY : clean
clean :
	rm -f *.o *.pem *.d $(TARGETS)
