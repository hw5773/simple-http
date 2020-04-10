#include "simple_network.h"
#include "debug.h"
#include <resolv.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

unsigned long get_current_timestamp(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return ((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
}

int send_tcp_message(int fd, uint8_t *buf, int len)
{
  fstart("fd: %d, buf: %p, len: %d", fd, buf, len);

  int sent, offset;
  unsigned long base, curr;

  offset = 0;
  base = get_current_timestamp();
  while (offset < len)
  {
    sent = write(fd, buf + offset, len - offset);
    if (sent >= 0)
      offset += sent;

    curr = get_current_timestamp();

    if (curr - base >= TIME_OUT) goto err;
  }

  ffinish();
  return offset;

err:
  ferr();
  return -1;
}

int recv_tcp_message(int fd, uint8_t *buf, int max)
{
  fstart("fd: %d, buf: %p, max: %d", fd, buf, max);

  int rcvd, offset;
  unsigned long base, curr;

  offset = 0;
  base = get_current_timestamp();
  
  do {
    rcvd = read(fd, buf + offset, max - offset);
    if (rcvd >= 0)
      offset += rcvd;
    curr = get_current_timestamp();
  } while (rcvd < 0 || (curr - base <= TIME_OUT));

  if (rcvd == 0) goto err;

  ffinish();
  return offset;

err:
  ferr();
  return -1;
}

int send_tls_message(SSL *ssl, uint8_t *buf, int len)
{
  fstart("ssl: %p, buf: %p, len: %d", ssl, buf, len);

  int sent, offset;
  unsigned long base, curr;

  offset = 0;
  base = get_current_timestamp();
  while (offset < len)
  {
    sent = SSL_write(ssl, buf + offset, len - offset);
    if (sent >= 0)
      offset += sent;

    curr = get_current_timestamp();

    if (curr - base >= TIME_OUT) goto err;
  }

  ffinish();
  return offset;

err:
  ferr();
  return -1;
}

int recv_tls_message(SSL *ssl, uint8_t *buf, int max)
{
  fstart("ssl: %p, buf: %p, max: %d", ssl, buf, max);

  int rcvd, offset;
  unsigned long base, curr;

  offset = 0;
  base = get_current_timestamp();
  
  do {
    rcvd = SSL_read(ssl, buf + offset, max - offset);
    if (rcvd >= 0)
      offset += rcvd;
    curr = get_current_timestamp();
  } while (rcvd < 0 || (curr - base <= 10));

  ffinish();
  return offset;
}

int open_connection(const char *domain, uint16_t port, int nonblock)
{
  fstart("domain: %s, port: %u, nonblock: %d", domain, port, nonblock);
  int sock;
  struct hostent *host;
  struct sockaddr_in addr;

  sock = -1;

  if (!(host = gethostbyname(domain)))
  {
    emsg("gethostbyname() error");
    goto err;
  }

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0)
  {
    emsg("client socket error");
    goto err;
  }

  memset(&addr, 0x0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);

  if (nonblock)
    fcntl(sock, F_SETFL, O_NONBLOCK);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    emsg("connect() error");
    goto err;
  }

  ffinish();
  return sock;

err:
  if (sock > 0)
    close(sock);

  ferr();
  return -1;
}

int open_listener(uint16_t port, int nonblock)
{
  fstart("port: %u", port);
  int sock;
  struct sockaddr_in addr;

  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) goto err;

  memset(&addr, 0x0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (nonblock)
    fcntl(sock, F_SETFL, O_NONBLOCK);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
  {
    emsg("bind() error");
    goto err;
  }

  if (listen(sock, 10))
  {
    emsg("listen() error");
    goto err;
  }

  ffinish();
  return sock;

err:
  if (sock > 0)
    close(sock);

  ferr();
  return -1;
}
