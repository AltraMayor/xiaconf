CC = gcc
CFLAGS = -Wall -Wextra -g -MMD -I ../kernel-include -I ../include
LDFLAGS = -g -L ../libxia -lxia

PPAL_OBJ = test_ppal_map.o

TARGETS = test_ppal_map

all : $(TARGETS)

test_ppal_map : $(PPAL_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

-include *.d

PHONY : clean
clean :
	rm -f *.o *.d $(TARGETS)
