#
# Copyright (C) 2014, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pie -fPIE -Wl,-z,relro,-z,now
#CFLAGS +=-Wextra -Wall -pedantic -pie -fPIE -Wl,-z,relro,-z,now

# Change as necessary
PREFIX := /usr/local
# library target directory (either lib or lib64)
LIBDIR := lib

NAME := kcapi
LIBMAJOR=$(shell cat kcapi-kernel-if.c | grep define | grep MAJVERSION | awk '{print $$3}')
LIBMINOR=$(shell cat kcapi-kernel-if.c | grep define | grep MINVERSION | awk '{print $$3}')
LIBPATCH=$(shell cat kcapi-kernel-if.c | grep define | grep PATCHLEVEL | awk '{print $$3}')
LIBVERSION := $(LIBMAJOR).$(LIBMINOR).$(LIBPATCH)
C_SRCS := $(wildcard *.c)
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

INCLUDE_DIRS :=
LIBRARY_DIRS :=
LIBRARIES :=

CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

.PHONY: all scan install clean distclean

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -shared -Wl,-soname,lib$(NAME).so.$(LIBMAJOR) -o lib$(NAME).so.$(LIBVERSION) $(OBJS) $(LDFLAGS)

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) -shared -Wl,-soname,lib$(NAME).so.$(LIBMAJOR) -o lib$(NAME).so.$(LIBVERSION) $(OBJS) $(LDFLAGS)

install: $(NAME)
	install -m 0755 -s lib$(NAME).so.$(LIBVERSION) $(PREFIX)/$(LIBDIR)/
	$(RM) $(PREFIX)/$(LIBDIR)/lib$(NAME).so.$(LIBMAJOR)
	ln -s lib$(NAME).so.$(LIBVERSION) $(PREFIX)/$(LIBDIR)/lib$(NAME).so.$(LIBMAJOR)
	install -m 0644 kcapi.h $(PREFIX)/include

clean:
	@- $(RM) $(OBJS)
	@- $(RM) lib$(NAME).so.$(LIBVERSION)

distclean: clean
