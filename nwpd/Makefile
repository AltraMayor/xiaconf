CC=gcc
CFLAGS= -Wall -O0 -gdwarf-4 -g3 -MMD -I ../kernel-include -I ../include -DUSE_DEBUG  -fdiagnostics-color $(ADD_CFLAGS)
LDFLAGS = -g -L ../libxia -lmnl -pthread -lxia -lrt $(ADD_LDFLAGS)

NWPD_OBJ = nwpd.o nwp.o rtnl.o monitor.o timer.o config.o log.o neigh.o

TARGETS = nwpd

all : $(TARGETS)

nwpd : $(NWPD_OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
clean :
	rm -f *.o *.d $(TARGETS)
