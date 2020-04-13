#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <unistd.h>

#include "debug.h"
#include "simple_https.h"
#include "simple_http_callbacks.h"

int process_index(http_t *req, http_t *resp);
int process_json(http_t *req, http_t *resp);
int process_file(http_t *req, http_t *resp);

int main(int argc, char *argv[])
{
  http_cbs_t *cbs;
  http_t *req, *resp;

  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;
  EC_KEY *ecdh;

  int server, client, err, port, ret;
  const uint8_t http1_1[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);

  port = 5555;
  err = 0;

  SSL_load_error_strings();
  init_http_module();

  method = (SSL_METHOD *)TLS_server_method();
  ctx = SSL_CTX_new(method);
  SSL_CTX_set_alpn_protos(ctx, http1_1, sizeof(http1_1));

  if (SSL_CTX_use_certificate_file(ctx, "cert.der", SSL_FILETYPE_ASN1) <= 0)
  {
    emsg("SSL_CTX_use_certificate_file() error");
    goto err;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "priv.der", SSL_FILETYPE_ASN1) <= 0)
  {
    emsg("SSL_CTX_use_PrivateKey_file() error");
    goto err;
  }

  if (!SSL_CTX_check_private_key(ctx))
  {
    emsg("SSL_CTX_check_private_key() error");
    goto err;
  }

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ecdh)
  {
    emsg("Set ECDH error");
    goto err;
  }

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
  {
    emsg("SSL_CTX_set_tmp_ecdh() error");
    goto err;
  }

  cbs = init_http_callbacks();
  if (!cbs) goto err;

  ret = register_callback(cbs, HTTP_METHOD_GET, "/", 1, process_index);
  if (ret != HTTP_SUCCESS) goto err;

  ret = register_callback(cbs, HTTP_METHOD_GET, "/json", 5, process_json);
  if (ret != HTTP_SUCCESS) goto err;

  ret = register_callback(cbs, HTTP_METHOD_GET, "/file", 5, process_file);

  print_callbacks(cbs);

  server = open_listener(port, 1);
  if (server < 0)
    abort();

  while(1)
  {
    if((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      dmsg("New connection is accepted");
      break;
    }
  }

  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, client);
  SSL_set_accept_state(ssl);

  req = init_http_message(HTTP_TYPE_REQUEST);
  if (!req) goto err;

  resp = init_http_message(HTTP_TYPE_RESPONSE);
  if (!resp) goto err;
  http_set_default_attributes(resp);

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
    ret = recv_https_message(ssl, req, NULL);
  if (ret != HTTP_SUCCESS) goto err;
  print_header(req);

  process_request(cbs, req, resp);

  print_header(resp);
  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = send_https_message(ssl, resp);
  if (ret != HTTP_SUCCESS) goto err;

  SSL_shutdown(ssl);
  close(client);
  close(server);

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

int process_index(http_t *req, http_t *resp)
{
  fstart("req: %p, resp: %p", req, resp);
  assert(req != NULL);
  assert(resp != NULL);

  dmsg("process_index()!");

  resource_t *resource;
  uint8_t *buf;

  resource = http_init_resource(resp);
  buf = (uint8_t *)malloc(7);
  memcpy(buf, "Hello!\n", 7);

  resource->type = HTTP_RESOURCE_MEM;
  resource->ptr = (void *)buf;
  resource->size = 7;

  ffinish();
  return HTTP_SUCCESS;
}

int process_json(http_t *req, http_t *resp)
{
  fstart("req: %p, resp: %p", req, resp);
  assert(req != NULL);
  assert(resp != NULL);

  dmsg("process_json()!");

  ffinish();
  return HTTP_SUCCESS;
}

int process_file(http_t *req, http_t *resp)
{
  fstart("req: %p, resp: %p", req, resp);
  assert(req != NULL);
  assert(resp != NULL);

  ffinish();
  return HTTP_SUCCESS;
}
