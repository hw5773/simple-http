#include <openssl/ssl.h>

#include "debug.h"
#include "simple_http.h"
#include "simple_network.h"

#define BUF_SIZE  16384

int main(int argc, char *argv[])
{
  http_t *req, *resp;
  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;

  int sock, port, reqhlen, reqdlen, resplen, ret, dlen;
  uint8_t reqhdr[BUF_SIZE] = {0, };
  uint8_t reqdata[BUF_SIZE] = {0, };
  uint8_t respbuf[BUF_SIZE] = {0, };
  uint8_t *data;
  char *key, *value;
  const char *domain = "www.google.com";
  const char *content = "index.html";
  port = 443;

  req = init_http_message(HTTP_TYPE_REQUEST);
  if (!req) goto err;

  http_set_version(req, HTTP_VERSION_1_1);
  http_set_method(req, HTTP_METHOD_GET);
  http_set_domain(req, domain, (int) strlen(domain));
  http_set_content(req, content, (int) strlen(content));
  http_set_default_attributes(req);

  key = "Accept-Encoding";
  value = "gzip, deflate";
  add_header_attribute(req, key, (int) strlen(key), value, (int) strlen(value));

  print_header(req);

  key = "Accept-Language";
  del_header_attribute(req, key, (int) strlen(key));

  print_header(req);

  method = (SSL_METHOD *)TLS_client_method();
  ctx = SSL_CTX_new(method);
  ssl = SSL_new(ctx);

  sock = open_connection(domain, port, 0);
  SSL_set_fd(ssl, sock);

  if (SSL_connect(ssl) == -1)
  {
    emsg("SSL_connect() error");
    goto err;
  }

  ret = http_serialize(req, reqhdr, &reqhlen, reqdata, &reqdlen);
  if (ret < 0) goto err;

  ret = send_tls_message(ssl, reqhdr, reqhlen);
  if (ret != reqhlen) goto err;

  if (reqdlen > 0)
    ret = send_tls_message(ssl, reqdata, reqdlen);
  if (ret != reqdlen) goto err;

  resplen = recv_tls_message(ssl, respbuf, BUF_SIZE);

  resp = init_http_message(HTTP_TYPE_RESPONSE);
  if (!resp) goto err;
  ret = http_deserialize(respbuf, resplen, resp);
  if (ret < 0) goto err;

  print_header(resp);
  data = http_get_data(resp, &dlen);
  
  imsg("Received data (%d bytes):\n%s", dlen, data);

  if (ssl)
    SSL_free(ssl);
  ssl = NULL;

  if (ctx)
    SSL_CTX_free(ctx);
  ctx = NULL;

  return 0;

err:
  if (ssl)
    SSL_free(ssl);

  if (ctx)
    SSL_CTX_free(ctx);

  return 1;
}
