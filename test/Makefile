#
# Copyright (C) 2014, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -Wno-overlength-strings -pie -fPIE -O2 -g
#Hardening
CFLAGS +=-D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4
LDFLAGS +=-Wl,-z,relro,-z,now

NAME := kcapi
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

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

scan:	$(OBJS)
	scan-build --use-analyzer=/usr/bin/clang $(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

clean:
	@- $(RM) $(NAME)
	@- $(RM) $(OBJS)

distclean: clean
