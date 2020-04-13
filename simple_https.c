#include "simple_https.h"

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
  dmsg("http->header: %d", http->header);
  while (ret == HTTP_NOT_FINISHED)
  {
    recv = SSL_read(ssl, buf, BUF_SIZE);
    if (recv > 0)
    {
      dmsg("Received: %d bytes", recv);
      ret = http_deserialize(buf, recv, http, fp);
      if (ret == HTTP_FAILURE) goto err;
      if (http->resource)
      {
        dmsg("http->chunked: %d / http->resource->offset: %d / http->resource->size: %d", http->chunked, http->resource->offset, http->resource->size);
      }
    }
    memset(buf, 0x0, BUF_SIZE);
  }

  ffinish();
  return ret;

err:
  ferr();
  return HTTP_FAILURE;
}
