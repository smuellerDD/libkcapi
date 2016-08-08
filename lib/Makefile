#
# Copyright (C) 2014, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS +=-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden
LDFLAGS +=-Wl,-z,relro,-z,now

# Change as necessary
PREFIX := /usr/local
# library target directory (either lib or lib64)
LIBDIR := lib

NAME := kcapi
LIBMAJOR=$(shell grep '^\#define[ \t]*MAJVERSION' kcapi.h | awk '{print $$3}')
LIBMINOR=$(shell grep '^\#define[ \t]*MINVERSION' kcapi.h | awk '{print $$3}')
LIBPATCH=$(shell grep '^\#define[ \t]*PATCHLEVEL' kcapi.h | awk '{print $$3}')

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

.PHONY: all scan install clean distclean man maninstall pdf ps html

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) -shared -Wl,-soname,lib$(NAME).so.$(LIBMAJOR) -o lib$(NAME).so.$(LIBVERSION) $(OBJS) $(LDFLAGS)

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) -shared -Wl,-soname,lib$(NAME).so.$(LIBMAJOR) -o lib$(NAME).so.$(LIBVERSION) $(OBJS) $(LDFLAGS)

install:
	install -m 0755 -s lib$(NAME).so.$(LIBVERSION) $(PREFIX)/$(LIBDIR)/
	$(RM) $(PREFIX)/$(LIBDIR)/lib$(NAME).so.$(LIBMAJOR)
	ln -s lib$(NAME).so.$(LIBVERSION) $(PREFIX)/$(LIBDIR)/lib$(NAME).so.$(LIBMAJOR)
	install -m 0644 kcapi.h $(PREFIX)/include

man:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh man

maninstall:
	install -m 0644 doc/man/* $(PREFIX)/share/man/man3

html:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh html

pdf:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh pdf

ps:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh ps

clean:
	@- $(RM) $(OBJS)
	@- $(RM) lib$(NAME).so.$(LIBVERSION)
	@- doc/gendocs.sh clean

distclean: clean
