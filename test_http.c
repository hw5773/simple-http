#include <openssl/ssl.h>

#include "debug.h"
#include "simple-http.h"
#include "simple-network.h"

#define BUF_SIZE 16384

int main(int argc, char *argv[])
{
  http_t *req;
  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;
  int sock, port, reqlen, resplen;
  uint8_t req[BUF_SIZE] = {0, };
  uint8_t resp[BUF_SIZE] = {0, };
  const uint8_t *domain;
  int port;
  
  domain = "www.google.com";
  port = 443;

  req = init_http_message(HTTP_TYPE_REQUEST, HTTP_VERSION_1_1, HTTP_METHOD_GET,
      domain, strlen(domain), NULL, 0);

  add_

  method = (SSL_METHOD *)TLS_client_method();
  ctx = SSL_CTX_new(method);
  ssl = SSL_new(ctx);

  sock = open_connection(domain, port, 0);
  SSL_set_fd(sock);

  

  return 0;
}
