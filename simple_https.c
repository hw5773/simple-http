#include "simple_https.h"
#include <errno.h>
#include <openssl/err.h>

int send_https_message(SSL *ssl, http_t *http)
{
  fstart("ssl: %p, http: %p", ssl, http);

  int ret, sent, len;
  uint8_t buf[BUF_SIZE];

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
  {
    ret = http_serialize(http, buf, BUF_SIZE, &len);
    dmsg("HTTP request (%d bytes):\n%s", len, buf);
    sent = SSL_write(ssl, buf, len);
    if (sent > 0)
      http_update_resource(http, sent);
  }

  if (ret == HTTP_FAILURE) goto err;

  ffinish();
  return ret;

err:
  ferr();
  return HTTP_FAILURE;
}

int recv_https_message(SSL *ssl, http_t *http, FILE *fp)
{
  fstart("ssl: %p, http: %p, fp: %p", ssl, http, fp);

  int ret, recv;
  uint8_t buf[BUF_SIZE];
  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
  {
    recv = SSL_read(ssl, buf, BUF_SIZE);
    if (recv > 0)
    {
      ret = http_deserialize(buf, recv, http, fp);
      if (ret == HTTP_FAILURE) goto err;
    }
    memset(buf, 0x0, BUF_SIZE);
    if (http->resource)
      dmsg("offset: %d, size: %d", http->resource->offset, http->resource->size);
  }

  ffinish();
  return ret;

err:
  ferr();
  return HTTP_FAILURE;
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
