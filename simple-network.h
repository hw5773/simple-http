#ifndef __SIMPLE_NETWORK_H__
#define __SIMPLE_NETWORK_H__

#include <resolv.h>
#include <sys/socket.h>
#include <netdb.h>

int open_connection(uint8_t *domain, uint16_t port, int nonblock);
int open_listener(uint16_t port, int nonblock);

#endif /* __SIMPLE_SOCKET_H__ */
