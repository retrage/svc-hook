PROGS = libsvchook.so

CC ?= gcc
CLANG_FORMAT ?= clang-format

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -g
CFLAGS += -DMINIMAL_CONTEXT
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -fPIC

LDFLAGS += -shared -rdynamic -ldl

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
