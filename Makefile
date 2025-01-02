#!/usr/bin/env make
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Akira Moroo

PROGS = libsvchook.so

CLANG_FORMAT ?= clang-format

CLEANFILES = $(PROGS) *.o *.d

CFLAGS = -O3
CFLAGS += -pipe
CFLAGS += -g
CFLAGS += -Werror
CFLAGS += -Wall
CFLAGS += -Wunused-function
CFLAGS += -Wextra
CFLAGS += -fPIC

ifeq ($(FULL_CONTEXT), 1)
CFLAGS += -DFULL_CONTEXT
endif

LDFLAGS += -shared
LDFLAGS += -rdynamic
LDFLAGS += -ldl

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

fmt:
	$(CLANG_FORMAT) -i $(C_SRCS)

.PHONY: all clean fmt
