PROGS = libsvchook.so

CLANG_FORMAT ?= clang-format

CLEANFILES = $(PROGS) *.o *.d

NO_MAN=
CFLAGS = -O3 -pipe
CFLAGS += -g
CFLAGS += -DMINIMAL_CONTEXT
CFLAGS += -DSUPPLEMENTAL__SYSCALL_RECORD
CFLAGS += -Wunused-function
CFLAGS += -Wextra
CFLAGS += -fPIC

LDFLAGS += -shared

C_SRCS = main.c
OBJS = $(C_SRCS:.c=.o)

all: $(PROGS)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)

fmt:
	$(CLANG_FORMAT) -i $(C_SRCS)

.PHONY: all clean fmt
