PROGS = libsvchook.so

CC ?= gcc
CLANG_FORMAT ?= clang-format

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -g -rdynamic
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -DREDUCED_CONTEXT_SAVE
CFLAGS += -Wextra
CFLAGS += -shared -fPIC

LDFLAGS += -ldl

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
