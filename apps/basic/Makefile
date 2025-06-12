# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 Akira Moroo

CC ?= clang
PROGS = libsvchook_basic.so

CLANG_FORMAT ?= clang-format
NO_MAN=

CLEANFILES = $(PROGS) *.o *.d

CFLAGS = -O3
CFLAGS += -pipe
CFLAGS += -Werror
CFLAGS += -Wall
CFLAGS += -Wunused-function
CFLAGS += -Wextra
CFLAGS += -fPIC

LDFLAGS += -shared

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $? $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

fmt:
	$(CLANG_FORMAT) -i $(C_SRCS)

.PHONY: all clean fmt
