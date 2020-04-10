CC=gcc
LD=ld
RM=rm

ROOT_DIRECTORY=$(HOME)/devel/rpi/edge-libevent
BIN=test_http_client test_http_server
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/include
LDFLAGS=-L$(ROOT_DIRECTORY)/lib -lssl -lcrypto

all: test_http_client test_http_server

test_http_client: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

test_http_server: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

%.o: %.c
	$(CC) -c $< $(CFLAGS)
	@echo "CC <= $<"

clean:
	$(RM) $(BIN) $(OBJS)
