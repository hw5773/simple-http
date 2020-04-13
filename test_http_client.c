#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

#include "debug.h"
#include "simple_https.h"

int process_error(SSL *ssl, int ret);

int main(int argc, char *argv[])
{
  http_t *req, *resp;
  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;

  int sock, err, port, ret;
  char *key, *value;
  const char *domain = "www.cloudflare.com";
  const uint8_t http1_1[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  FILE *fp;
  port = 443;
  err = 0;

  fp = fopen("index.html", "w");
  SSL_load_error_strings();
  init_http_module();

  req = init_http_message(HTTP_TYPE_REQUEST);
  if (!req) goto err;

  http_set_version(req, HTTP_VERSION_1_1);
  http_set_method(req, HTTP_METHOD_GET);
  http_set_domain(req, domain, (int) strlen(domain));
  http_set_default_attributes(req);

  key = "Accept-Encoding";
  value = "gzip, deflate";
  add_header_attribute(req, key, (int) strlen(key), value, (int) strlen(value));

  print_header(req);

  del_header_attribute(req, key, (int) strlen(key));

  print_header(req);

  method = (SSL_METHOD *)TLS_client_method();
  ctx = SSL_CTX_new(method);
  SSL_CTX_set_alpn_protos(ctx, http1_1, sizeof(http1_1));
  ssl = SSL_new(ctx);

  sock = open_connection(domain, port, 1);
  if (sock < 0)
    abort();
  SSL_set_fd(ssl, sock);
  SSL_set_connect_state(ssl);

  while (!err)
  {
    ret = SSL_do_handshake(ssl);
    err = process_error(ssl, ret);

    if (err < 0)
      abort();
  }
  dmsg("TLS session is established with %s", SSL_get_cipher(ssl));

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = send_https_message(ssl, req);

  if (ret != HTTP_SUCCESS) goto err;

  resp = init_http_message(HTTP_TYPE_RESPONSE);
  if (!resp) goto err;

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = recv_https_message(ssl, resp, fp);
  if (ret != HTTP_SUCCESS) goto err;

  print_header(resp);

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

int process_error(SSL *ssl, int ret)
{
  int err;
  err = SSL_get_error(ssl, ret);

  switch (err)
  {
    case SSL_ERROR_NONE:
      dmsg("SSL_ERROR_NONE");
      ret = 1;
      break;

    case SSL_ERROR_ZERO_RETURN:
      dmsg("SSL_ERROR_ZERO_RETURN");
      ret = -1;
      break;

    case SSL_ERROR_WANT_X509_LOOKUP:
      dmsg("SSL_ERROR_WANT_X509_LOOKUP");
      ret = 0;
      break;

    case SSL_ERROR_SYSCALL:
      dmsg("SSL_ERROR_SYSCALL");
      dmsg("errno: %d", errno);
      ERR_print_errors_fp(stderr);
      ret = -1;
      break;

    case SSL_ERROR_SSL:
      dmsg("SSL_ERROR_SSL");
      ERR_print_errors_fp(stderr);
      ret = -1;
      break;

    default:
      ret = 0;
  }

  return ret;
}
