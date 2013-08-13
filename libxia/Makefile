CC = gcc
CFLAGS = -Wall -Wextra -g -MMD -fPIC -I ../kernel-include -I ../include
LDFLAGS = -g

LIBXIA_BASENAME = libxia.so
LIBXIA_SONAME = $(LIBXIA_BASENAME).0
LIBXIA_LIBNAME = $(LIBXIA_SONAME).0
LIBXIA_OBJ = dag.o ppal_map.o

all : $(LIBXIA_BASENAME)

$(LIBXIA_LIBNAME) : $(LIBXIA_OBJ)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,$(LIBXIA_SONAME) -o $@ $^ -lc

# Create a pointer from the soname to the library.
$(LIBXIA_SONAME) : $(LIBXIA_LIBNAME)
	ln -sf $< $@

# Create a pointer for the linker.
$(LIBXIA_BASENAME) : $(LIBXIA_SONAME)
	ln -sf $< $@

-include *.d

PHONY : clean
clean :
	rm -f *.o *.d $(LIBXIA_BASENAME)*
