#
# Copyright (C) 2015, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -pie -fPIE -Wl,-z,relro,-z,now

NAME := kcapi-hasher
C_SRCS := $(wildcard *.c) $(wildcard ../lib/*.c)
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

INCLUDE_DIRS := ../lib
LIBRARY_DIRS :=
LIBRARIES :=

CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(LIBRARIES),-l$(library))

.PHONY: all clean distclean

all: $(NAME)

cleanlinks:
	@- $(RM) sha1sum sha224sum sha256sum sha384sum sha512sum md5sum fipscheck fipshmac sha1hmac sha224hmac sha256hmac sha384hmac sha512hmac

$(NAME): cleanlinks $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)
	@- ln -s $(NAME) sha1sum
	@- ln -s $(NAME) sha224sum
	@- ln -s $(NAME) sha256sum
	@- ln -s $(NAME) sha384sum
	@- ln -s $(NAME) sha512sum
	@- ln -s $(NAME) md5sum
	@- ln -s $(NAME) fipscheck
	@- ln -s $(NAME) fipshmac
	@- ln -s $(NAME) sha1hmac
	@- ln -s $(NAME) sha224hmac
	@- ln -s $(NAME) sha256hmac
	@- ln -s $(NAME) sha384hmac
	@- ln -s $(NAME) sha512hmac

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

clean:
	@- $(RM) $(NAME) sha1sum sha224sum sha256sum sha384sum sha512sum md5sum fipscheck fipshmac sha1hmac sha224hmac sha256hmac sha384hmac sha512hmac
	@- $(RM) $(OBJS)

distclean: clean
