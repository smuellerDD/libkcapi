#
# Copyright (C) 2015, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -fPIC -O2
#Hardening
CFLAGS +=-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4
LDFLAGS +=-Wl,-z,relro,-z,now

NAME := kcapi-hasher
C_SRCS := $(wildcard *.c) $(wildcard ../lib/*.c)
C_OBJS := ${C_SRCS:.c=.o}
C_ASM := ${C_SRCS:.c=.s}
OBJS := $(C_OBJS)
ASM := $(C_ASM)

INCLUDE_DIRS := ../lib
LIBRARY_DIRS :=
LIBRARIES :=

CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

BINDIR := $(DESTDIR)/usr/local/bin

.PHONY: all scan asm clean distclean install

all: $(NAME)

cleanlinks:
	@- $(RM) sha1sum sha224sum sha256sum sha384sum sha512sum md5sum fipscheck fipshmac sha1hmac sha224hmac sha256hmac sha384hmac sha512hmac

$(NAME): cleanlinks $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)
	@- ln $(NAME) sha1sum
	@- ln $(NAME) sha224sum
	@- ln $(NAME) sha256sum
	@- ln $(NAME) sha384sum
	@- ln $(NAME) sha512sum
	@- ln $(NAME) md5sum
	@- ln $(NAME) fipscheck
	@- ln $(NAME) fipshmac
	@- ln $(NAME) sha1hmac
	@- ln $(NAME) sha224hmac
	@- ln $(NAME) sha256hmac
	@- ln $(NAME) sha384hmac
	@- ln $(NAME) sha512hmac

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

asm:
	$(foreach b, $(C_SRCS), $(CC) $(CFLAGS) -S -fverbose-asm -o ${b:.c=.s} $(b);)

clean:
	@- $(RM) $(NAME) sha1sum sha224sum sha256sum sha384sum sha512sum md5sum fipscheck fipshmac sha1hmac sha224hmac sha256hmac sha384hmac sha512hmac
	@- $(RM) $(ASM)
	@- $(RM) $(OBJS)

distclean: clean

install:
	install -m 0755 $(NAME) -D -t $(BINDIR)/
	install -m 0755 sha1sum -D -t $(BINDIR)/
	./fipshmac $(BINDIR)/sha1sum
	install -m 0755 sha224sum -D -t $(BINDIR)/
	./fipshmac $(BINDIR)/sha224sum
	install -m 0755 sha256sum -D -t $(BINDIR)/
	./fipshmac $(BINDIR)/sha256sum
	install -m 0755 sha384sum -D -t $(BINDIR)/
	./fipshmac $(BINDIR)/sha384sum
	install -m 0755 sha512sum -D -t $(BINDIR)/
	./fipshmac $(BINDIR)/sha512sum
	install -m 0755 fipscheck -D -t $(BINDIR)/
	./fipshmac $(BINDIR)/fipscheck
	install -m 0755 fipshmac -D -t $(BINDIR)/
	./fipshmac $(BINDIR)/fipshmac
	install -m 0755 sha1hmac -D -t $(BINDIR)/
	./sha512hmac sha1hmac > $(BINDIR)/.sha1hmac.hmac
	install -m 0755 sha224hmac -D -t $(BINDIR)/
	./sha512hmac sha224hmac > $(BINDIR)/.sha224hmac.hmac
	install -m 0755 sha256hmac -D -t $(BINDIR)/
	./sha512hmac sha256hmac > $(BINDIR)/.sha256hmac.hmac
	install -m 0755 sha384hmac -D -t $(BINDIR)/
	./sha512hmac sha384hmac > $(BINDIR)/.sha384hmac.hmac
	install -m 0755 sha512hmac -D -t $(BINDIR)/
	./sha512hmac sha512hmac > $(BINDIR)/.sha512hmac.hmac
