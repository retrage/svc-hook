#!/usr/bin/env make
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Akira Moroo

PROGS = libsvchook.so

CLANG_FORMAT ?= clang-format

SYSCALL_RECORD ?= 0

CLEANFILES = $(PROGS) *.o *.d

CFLAGS = -O3
CFLAGS += -pipe
CFLAGS += -g
CFLAGS += -Werror
CFLAGS += -Wall
CFLAGS += -Wunused-function
CFLAGS += -Wextra
CFLAGS += -fPIC
CFLAGS += -DSUPPLEMENTAL__SYSCALL_RECORD=$(SYSCALL_RECORD)

LIBDL ?= -ldl
LDFLAGS += -shared
LDFLAGS += -rdynamic
LDFLAGS += $(LIBDL)

C_SRCS = main.c
HEADERS = scan_code.h scan_code_freebsd.h scan_code_linux.h
OBJS = $(C_SRCS:.c=.o)

all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

fmt:
	$(CLANG_FORMAT) -i $(C_SRCS) $(HEADERS)

.PHONY: all clean fmt
