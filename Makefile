ARCH ?= X86_64

ifeq ($(ARCH), AARCH64)
	CROSS_COMPILE := /home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-
endif

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
LD=$(CROSS_COMPILE)ld
RM=$(CROSS_COMPILE)rm
DEBUG ?= 0
SHARED ?= 0

ROOT_DIRECTORY=$(HOME)/devel/rpi/edge-libevent
BIN=test_http_client test_http_server
LIB=libsimple_http.a
SHLIB=libsimple_http.so
VERSION=1.0.1

SRCS=simple_http.c simple_https.c simple_network.c http_status.c simple_http_callbacks.c buf.c
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

ifeq ($(SHARED), 1)
	CFLAGS += -fPIC
endif

ifeq ($(ARCH), X86_64)
	LDFLAGS=-L$(ROOT_DIRECTORY)/lib -lssl -lcrypto -L. -lbuf
else
	LDFLAGS=-L$(ROOT_DIRECTORY)/platform/tz/lib -lssl -lcrypto -L. -lbuf
endif 

all: test_http_client test_http_server lib

lib: $(OBJS)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)

shared: $(OBJS)
	$(CC) -shared -Wl,-soname,$(SHLIB) -o $(SHLIB).$(VERSION) $(OBJS)

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
