#
# Copyright (C) 2014 - 2016, Stephan Mueller <smueller@chronox.de>
#

CC		:= gcc
CFLAGS		+= -Wextra -Wall -pedantic -fPIC -O2 -std=gnu99
#Hardening
CFLAGS		+= -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4 -fvisibility=hidden
LDFLAGS		+= -Wl,-z,relro,-z,now -Wl,--version-script,version.lds

NAME		:= kcapi

DESTDIR		:=
ETCDIR		:= /etc
BINDIR		:= /bin
SBINDIR		:= /sbin
SHAREDIR	:= /usr/share/keyutils
MANDIR		:= /usr/share/man
MAN1		:= $(MANDIR)/man1
MAN3		:= $(MANDIR)/man3
MAN5		:= $(MANDIR)/man5
MAN7		:= $(MANDIR)/man7
MAN8		:= $(MANDIR)/man8
INCLUDEDIR	:= /usr/include
LN		:= ln
LNS		:= $(LN) -sf

###############################################################################
#
# Define compilation options
#
###############################################################################
INCLUDE_DIRS	:=
LIBRARY_DIRS	:=
LIBRARIES	:=

CFLAGS		+= $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS		+= $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS		+= $(foreach library,$(LIBRARIES),-l$(library))

###############################################################################
#
# Get version name and cross check
#
###############################################################################
LIBMAJOR   := $(shell grep '^\#define.*MAJVERSION' internal.h | awk '{print $$3}')
LIBMINOR   := $(shell grep '^\#define.*MINVERSION' internal.h | awk '{print $$3}')
LIBPATCH   := $(shell grep '^\#define.*PATCHLEVEL' internal.h | awk '{print $$3}')
LIBVERSION := $(LIBMAJOR).$(LIBMINOR).$(LIBPATCH)

# Determine the current library version from the version script
ldversion  := $(filter LIBKCAPI_%,$(shell grep ^LIBKCAPI_ version.lds))
ldversion  := $(lastword $(ldversion))
ldversion  := $(lastword $(ldversion))
APIVERSION := $(subst LIBKCAPI_,,$(ldversion))
ifneq ($(APIVERSION),$(LIBVERSION))
error:
	$(info ERROR VERSION NUMBERS in kcapi.h and version.lds)
	@echo version.lds=$(APIVERSION)
	@echo kcapi-kernel-if.c=$(LIBVERSION)
endif

###############################################################################
#
# Guess at the appropriate lib directory and word size
#
###############################################################################
ifeq ($(origin LIBDIR),undefined)
LIBDIR		:= $(shell ldd /usr/bin/make | grep '\(/libc\.\)' | sed -e 's!.*\(/.*\)/libc[.].*!\1!')
endif
ifeq ($(origin USRLIBDIR),undefined)
USRLIBDIR	:= $(patsubst /lib/%,/usr/lib/%,$(LIBDIR))
endif
BUILDFOR	:= $(shell file /usr/bin/make | sed -e 's!.*ELF \(32\|64\)-bit.*!\1!')-bit

ifeq ($(origin CFLAGS),undefined)
ifeq ($(BUILDFOR),32-bit)
CFLAGS		+= -m32
LIBDIR		:= /lib
USRLIBDIR	:= /usr/lib
else
ifeq ($(BUILDFOR),64-bit)
CFLAGS		+= -m64
LIBDIR		:= /lib64
USRLIBDIR	:= /usr/lib64
endif
endif
endif

###############################################################################
#
# Names
#
###############################################################################
SONAME		:= lib$(NAME).so.$(LIBMAJOR)
LIBNAME		:= lib$(NAME).so.$(LIBVERSION)

###############################################################################
#
# Define files to be compiled
#
###############################################################################
C_SRCS := $(wildcard *.c)
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

.PHONY: all scan install clean cppcheck distclean man maninstall pdf ps html

all: $(NAME)

###############################################################################
#
# Build the library
#
##############################################################################

$(NAME): $(OBJS)
	$(CC) -shared -Wl,-soname,$(SONAME) -o $(LIBNAME) $(OBJS) $(LDFLAGS)

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) -shared -Wl,-soname,$(SONAME) -o $(LIBNAME) $(OBJS) $(LDFLAGS)

cppcheck:
	cppcheck --enable=performance --enable=warning --enable=portability *.h *.c

install:
	install -m 0755 -s $(LIBNAME) $(DESTDIR)$(LIBDIR)/
	$(RM) $(LIBDIR)/$(SONAME)
	$(LNS) $(DESTDIR)$(LIBDIR)/$(LIBNAME) $(DESTDIR)$(LIBDIR)/$(SONAME)
	install -m 0644 kcapi.h $(DESTDIR)$(INCLUDEDIR)

###############################################################################
#
# Build the documentation
#
###############################################################################

man:
	LIBVERSION=$(LIBVERSION) doc/gendocs.sh man

maninstall: man
	install -m 0644 doc/man/* $(MAN3)/

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

###############################################################################
#
# Build debugging
#
###############################################################################
show_vars:
	@echo LIBVERSION=$(LIBVERSION)
	@echo APIVERSION=$(APIVERSION)
	@echo LIBDIR=$(LIBDIR)
	@echo USRLIBDIR=$(USRLIBDIR)
	@echo BUILDFOR=$(BUILDFOR)
	@echo SONAME=$(SONAME)
	@echo LIBNAME=$(LIBNAME)
	@echo LDFLAGS=$(LDFLAGS)
	@echo CFLAGS=$(CFLAGS)
