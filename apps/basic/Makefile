#!/usr/bin/env make
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Akira Moroo

PROGS = libsvchook_basic.so

CC ?= gcc
CLANG_FORMAT ?= clang-format

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -fPIC

LDFLAGS += -shared

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

.PHONY: all
all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

fmt:
	$(CLANG_FORMAT) -i $(C_SRCS)
