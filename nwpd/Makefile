CC=gcc
CFLAGS= -Wall -O2 -MMD -I ../kernel-include -I ../include -DUSE_DEBUG  -fdiagnostics-color $(ADD_CFLAGS)
LDFLAGS = -g -L ../libxia -lmnl -levent -pthread -levent_pthreads -lxia

NWPD_OBJ = nwpd.o nwp.o rtnl.o

TARGETS = nwpd

all : $(TARGETS)

nwpd : $(NWPD_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
clean :
	rm -f *.o *.d $(TARGETS)
