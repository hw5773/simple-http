CC=gcc
LD=ld
RM=rm
DEBUG ?= 0

ROOT_DIRECTORY=$(HOME)/devel/rpi/edge-libevent
BIN=test_http_client test_http_server
SRCS=simple_http.c simple_network.c
OBJS=$(SRCS:.c=.o)
CLIENT_SRC=test_http_client.c
CLIENT_OBJ=$(CLIENT_SRC:.c=.o)
SERVER_SRC=test_http_server.c
SERVER_OBJ=$(SERVER_SRC:.c=.o)

CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/include

ifeq ($(DEBUG), 1)
	CFLAGS+= -DDEBUG
endif

LDFLAGS=-L$(ROOT_DIRECTORY)/lib -lssl -lcrypto

all: test_http_client test_http_server

test_http_client: $(CLIENT_OBJ) $(OBJS)
	$(CC) -o $@ $(CLIENT_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

test_http_server: $(SERVER_OBJ) $(OBJS)
	$(CC) -o $@ $(SERVER_OBJ) $(OBJS) $(LDFLAGS)
	@echo "LINK => $@"

%.o: %.c
	$(CC) -c $< $(CFLAGS)
	@echo "CC <= $<"

clean:
	$(RM) $(BIN) $(OBJS) $(CLIENT_OBJ) $(SERVER_OBJ)
