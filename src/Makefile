CC=gcc
# https://github.com/libuv/libuv/issues/891
CFLAGS=-c -Wall -O0 -g -DLOG_VERBOSE -std=c99 -D_GNU_SOURCE
LDFLAGS=-luv -lcrypto -lssl

SRCS_FOR_LOCAL=alloc.c local.c socks5.c util.c encrypt.c cli.c
OBJS_FOR_LOCAL=$(SRCS_FOR_LOCAL:.c=.o)
EXECUTABLE_LOCAL=lightning

SRCS_FOR_REMOTE=alloc.c remote.c socks5.c util.c encrypt.c cli.c
OBJS_FOR_REMOTE=$(SRCS_FOR_REMOTE:.c=.o)
EXECUTABLE_REMOTE=lightning_remote

$(info $(OBJS_FOR_REMOTE))

all: $(EXECUTABLE_LOCAL) $(EXECUTABLE_REMOTE)

$(EXECUTABLE_LOCAL): $(OBJS_FOR_LOCAL)
	$(CC) $(LDFLAGS) $(OBJS_FOR_LOCAL) -o $@

$(EXECUTABLE_REMOTE): $(OBJS_FOR_REMOTE)
	$(CC) $(LDFLAGS) $(OBJS_FOR_REMOTE) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean: 
	rm -f $(OBJS_FOR_LOCAL) $(EXECUTABLE_LOCAL) $(OBJS_FOR_REMOTE) $(EXECUTABLE_REMOTE)
