#
# Copyright (C) 2014, Stephan Mueller <smueller@chronox.de>
#

CC=gcc
CFLAGS +=-Wextra -Wall -pedantic -pie -fPIE -Wl,-z,relro,-z,now

NAME := kcapi
C_SRCS := $(wildcard *.c) $(wildcard ../*.c)
C_OBJS := ${C_SRCS:.c=.o}
OBJS := $(C_OBJS)

INCLUDE_DIRS := ../
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
