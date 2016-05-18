CC=gcc
CFLAGS=-c -Wall -O0 -g -DLOG_VERBOSE
LDFLAGS=-luv -lcrypto -lssl

SRCS=alloc.c local.c socks5.c util.c encrypt.c
OBJS=$(SRCS:.c=.o)
EXECUTABLE=ligtning

all: $(SRCS) $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean: 
	rm -f $(OBJS) $(EXECUTABLE)
