#include <openssl/ssl.h>
#include <errno.h>

#include "debug.h"
#include "simple_http.h"
#include "simple_network.h"

#define BUF_SIZE  16384

int process_error(SSL *ssl, int ret);

int main(int argc, char *argv[])
{
  http_t *req, *resp;
  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;

  int sock, err, port, reqhlen, reqdlen, resplen, ret, dlen;
  uint8_t reqhdr[BUF_SIZE] = {0, };
  uint8_t reqdata[BUF_SIZE] = {0, };
  uint8_t respbuf[BUF_SIZE] = {0, };
  uint8_t *data;
  char *key, *value;
  const char *domain = "www.google.com";
  port = 443;

  SSL_load_error_strings();

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

  key = "Accept-Language";
  del_header_attribute(req, key, (int) strlen(key));

  print_header(req);

  method = (SSL_METHOD *)TLS_client_method();
  ctx = SSL_CTX_new(method);
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
  dmsg("TLS session is established");

  ret = http_serialize(req, reqbuf, BUF_SIZE, &reqlen);
  if (ret < 0) goto err;

  ret = send_tls_message(ssl, reqhdr, reqhlen);
  if (ret != reqhlen) 
  {
    emsg("ret != reqhlen: ret: %d, reqhlen: %d", ret, reqhlen);
    goto err;
  }

  if (reqdlen > 0)
  {
    ret = send_tls_message(ssl, reqdata, reqdlen);
    if (ret != reqdlen)
    {
      emsg("ret != reqdlen: ret: %d, reqdlen: %d", ret, reqdlen);
      goto err;
    }
  }

  resplen = recv_tls_message(ssl, respbuf, BUF_SIZE);

  resp = init_http_message(HTTP_TYPE_RESPONSE);
  if (!resp) goto err;
  ret = http_deserialize(respbuf, resplen, resp);
  if (ret < 0) goto err;

  print_header(resp);
  data = http_get_data(resp, &dlen);
  
  //imsg("Received data (%d bytes):\n%s", dlen, data);
  fprintf(stdout, "%s", data);
  memset(respbuf, 0x0, BUF_SIZE);

  while (resplen > 0)
  {
    resplen = recv_tls_message(ssl, respbuf, BUF_SIZE);
    fprintf(stdout, "%s", respbuf);
    memset(respbuf, 0x0, BUF_SIZE);
  }

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
