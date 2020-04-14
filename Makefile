CC=gcc
AR=ar
LD=ld
RM=rm
DEBUG ?= 0

ROOT_DIRECTORY=$(HOME)/devel/rpi/edge-libevent
BIN=test_http_client test_http_server
LIB=libsimple_http.a

SRCS=simple_http.c simple_https.c simple_network.c buf.c http_status.c simple_http_callbacks.c
OBJS=$(SRCS:.c=.o)
CLIENT_SRC=test_http_client.c
CLIENT_OBJ=$(CLIENT_SRC:.c=.o)
SERVER_SRC=test_http_server.c
SERVER_OBJ=$(SERVER_SRC:.c=.o)

CFLAGS=-Wall -I. -I$(ROOT_DIRECTORY)/include
ARFLAGS=rscv

ifeq ($(DEBUG), 1)
	CFLAGS+= -DDEBUG
endif

LDFLAGS=-L$(ROOT_DIRECTORY)/lib -lssl -lcrypto

all: test_http_client test_http_server lib

lib: $(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

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
	$(RM) $(BIN) $(OBJS) $(CLIENT_OBJ) $(SERVER_OBJ) $(LIB)
