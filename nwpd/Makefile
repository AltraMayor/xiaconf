CC=gcc
CFLAGS= -Wall -O0 -gdwarf-4 -g3 -MMD -I ../kernel-include -I ../include -DUSE_DEBUG  -fdiagnostics-color $(ADD_CFLAGS)
LDFLAGS = -g -L ../libxia -lmnl -pthread -lxia $(ADD_LDFLAGS)

NWPD_OBJ = nwpd.o nwp.o rtnl.o

TARGETS = nwpd

all : $(TARGETS)

nwpd : $(NWPD_OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
clean :
	rm -f *.o *.d $(TARGETS)
