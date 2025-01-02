PROGS = libsvchook.so

CLANG_FORMAT ?= clang-format

CLEANFILES = $(PROGS) *.o *.d

CFLAGS = -O3
CFLAGS += -pipe
CFLAGS += -g
CFLAGS += -DMINIMAL_CONTEXT
CFLAGS += -Werror
CFLAGS += -Wall
CFLAGS += -Wunused-function
CFLAGS += -Wextra
CFLAGS += -fPIC

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
