#include "simple-network.h"
#include <string.h>
#include <fcntl.h>

int open_connection(uint8_t *domain, uint16_t port, int nonblock)
{
  fstart("domain: %s, port: %u, nonblock: %d", domain, port, nonblock);
  int sock;

  ffinish();
  return sock;
}

int open_listener(uint16_t port)
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
  return FAILURE;
}
