#include "simple_http.h"
#include <ctype.h>

static int char_to_int(uint8_t *str, uint32_t slen);

/**
 * @brief Make the HTTP request
 * @param domain the name of the target domain
 * @param dlen the length of the domain name
 * @param content the name of the target content
 * @param clen the length of the content
 * @param msg the buffer of the HTTP request
 * @param mlen the length of the message
 * @return SUCCESS/FAILURE
 */
int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, 
    uint32_t clen, uint8_t *msg, uint32_t *mlen)
{
  const uint8_t *get = "GET /";
  const uint8_t *http = " HTTP/1.1";
  const uint8_t *host = "Host: ";
  const uint8_t *header =
    "User-Agent: Wget/1.17.1 (linux-gnu)\r\n"
    "Accept: */*\r\n"
    "Accept-Encoding: identity\r\n\r\n";
  uint32_t hlen;
  uint8_t *p;

  fstart();
  dassert(domain != NULL);
  dassert(dlen > 0);
  dassert(clen >= 0);
  dassert(msg != NULL);
  dassert(mlen != NULL);

  hlen = strlen(header);
  assert(hlen > 0);
  p = msg;
  memcpy(p, get, 5);
  p += 5;

  if (clen > 0)
  {
    memcpy(p, content, clen);
    p += clen;
  }
  memcpy(p, http, 9);
  p += 9;
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;
  memcpy(p, host, 6);
  p += 6;
  memcpy(p, domain, dlen);
  p += dlen;
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;

  memcpy(p, header, hlen);
  p += hlen;
  *(p++) = 0;

  *mlen = p - msg;

  ffinish();
  return SUCCESS;
}

/**
 * @brief Parse the HTTP request
 * @param msg the HTTP request message
 * @param mlen the length of the HTTP request
 * @param r the structure of the request information
 * @return SUCCESS/FAILURE
 */
int http_parse_request(uint8_t *msg, uint32_t mlen, request_t **req)
{
  (void) mlen;
  int l;
  uint8_t *cptr, *nptr, *p, *q;
  request_t *info;

#ifdef DEBUG 
  uint8_t buf[BUF_LEN] = {0, };
#endif /* DEBUG */

  (*r) = (request_t *)malloc(sizeof(request_t));
  info = (*r);
  cptr = msg;

  //printf("%s> before parse request while\n", __func__);
  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;

#ifdef DEBUG
    memcpy(buf, cptr, l);
    buf[l+1] = 0;
    dmsg("Token (%d bytes): %s", l, buf);
#endif /* DEBUG */

    p = cptr;
    
    while (*p == ' ')
      p++;

    if ((l > 0) && (strncmp((const char *)p, "GET", 3) == 0))
    {
      p += 3;

      while (*p != '/')
        p++;

      q = p;

      while (*q != ' ')
        q++;

      if (q - p == 1)
        init_memcpy_buf_mem(&(req->content), INDEX_FILE, INDEX_FILE_LEN);
      else if (q - p > 1)
      {
        init_memcpy_buf_mem(&(req->content), p+1, q - p - 1);
      }
      else
      {
        emsg("Error in parsing the content name");
        goto err;
      }
    }

    if ((l > 0) && (strncmp((const char *)p, "Host:", 5) == 0))
    {
      p += 5;

      while (*p == ' ')
        p++;

      if (nptr - p > 0)
        init_memcpy_buf_mem(&(info->domain), p, nptr - p);
      else
      {
        emsg("Error in parsing the domain name");
        goto err;
      }
    }

    cptr = nptr + DELIMITER_LEN;

#ifdef DEBUG
    memset(buf, 0x0, BUF_LEN);
#endif /* DEBUG */
  }

  dmsg("Domain name in parser (%d bytes): %s", info->domain->len, info->domain->data);
  dmsg("Content name in parser (%d bytes): %s", info->content->len, info->content->data);

  ffinish();
  return SUCCESS;

err:
  ferr();
  return FAILURE;
}

/**
 * @brief Sent the HTTP response
 * @param io the I/O structure
 * @param sctx the TLS context
 * @return SUCCESS/FAILURE
 */
TEE_Result http_send_response(struct io_status_st *io, struct tls_context_record_st *sctx)
{
  EDGE_MSG("Start: HTTP send response");
  int sent;
  SSL *ssl;

  ssl = sctx->ssl;
  EDGE_LOG("ssl: %p, io->buf->data: %p, io->buf->len: %d", ssl, io->buf->data, io->buf->len);

  if (io->buf->len > 0)
  {
    sent = SSL_write(ssl, io->buf->data, io->buf->len);
    BYTE("http_send_response> io->buf->len: %d, sent: %d", io->buf->len, sent);
  }
  else
  {
    EDGE_MSG("Error in sending the HTTP response");
    abort();
  }
  EDGE_MSG("Finished: HTTP send response");
  return TEE_SUCCESS;
}

/**
 * @brief Parse the HTTP response
 * @param io the I/O structure
 * @param msg the received message
 * @param mlen the length of the message
 * @param buf the buffer
 * @return SUCCESS/FAILURE
 */
TEE_Result http_parse_response(struct io_status_st *io, uint8_t *msg, uint32_t mlen)
{
  EDGE_LOG("Start: http_parse_response: io: %p, msg: %p, mlen: %d", io, msg, mlen);
  uint32_t i, j, l;
  uint32_t hdrlen;
  uint8_t *cptr, *nptr, *p;
  cptr = msg;
  hdrlen = 0;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;
    hdrlen += (l + 2);
    if (l == 0)
      break;

    p = cptr;

    for (i=0; i<l; i++)
    {
      if (p[i] == ' ')
        break;
    }

    if ((l > 0) && (strncmp((const char *)p, "Content-Length:", i) == 0))
    {
      for (j=i+1; j<l; j++)
      {
        if (p[j] == ' ')
          break;
      }
      io->size = char_to_int(p + i + 1, j - i);
    }

    cptr = nptr + DELIMITER_LEN;
  }

  if (io->hdrlen == 0)
  {
    io->hdrlen = hdrlen;
    io->size += io->hdrlen;
  }
  
  EDGE_LOG("Finished: http_parse_response: io->size: %d", io->size);
  return TEE_SUCCESS;
}

/**
 * @brief Make the domain tables
 * @param buf the buffer
 * @param offset the offset in the buffer
 * @param mngr the file manager
 * @return SUCCESS/FAILURE
 */
TEE_Result make_domain_tables(struct buf_st *buf, uint32_t offset, struct file_manager_st *mngr)
{
  EDGE_LOG("Start: make_domain_tables: buf: %p, offset: %d, mngr: %p", buf, offset, mngr);
  uint32_t nlen;
  uint8_t *cptr, *nptr;
  struct buf_st *name;
  uint16_t clen;
  struct domain_table_st *dom;
  cptr = buf->data + offset;

  while ((nptr = strstr(cptr, DOMAIN_DELIMITER)))
  {
    EDGE_LOG(">>>>>>>>>>>> nptr: %p, cptr: %p <<<<<<<<<<<<", nptr, cptr);
    nlen = nptr - cptr;
    if (nlen <= 0)
      break;
    name = init_memcpy_buf_mem(&name, cptr, nlen);
    EDGE_LOG("Domain Table Generated (%d bytes): %s", name->len, name->data);

    dom = mngr->ops->get(mngr, name);
    if (!dom)
      dom = mngr->ops->create(mngr, name, NULL);

    cptr = nptr + DOMAIN_DELIMITER_LEN;
    EDGE_MSG("=================== Set Origin's Certificate =================");
    PTR_TO_VAR_2BYTES(cptr, clen);
    EDGE_LOG("  Length of Origin's Cert: %d", clen);
    dom->vops->set_certificate(dom, cptr, clen);
    cptr += clen;
    cptr += DOMAIN_DELIMITER_LEN;
  }
  EDGE_MSG("Finished: make_domain_tables");
  return TEE_SUCCESS;
}

/**
 * @brief Process the HTTP data
 * @param io the I/O structure
 * @param sctx the TLS context
 * @param mngr the file manager
 * @param cctx the command context
 * @return SUCCESS/FAILURE
 */
TEE_Result http_process_data(struct io_status_st *io, struct tls_context_record_st *sctx, 
    struct file_manager_st *mngr, struct cmd_st *cctx)
{
  EDGE_LOG("Start: http_process_data: io: %p, sctx: %p, mngr: %p, cctx: %p", 
      io, sctx, mngr, cctx);
  TEE_Result res;
  res = TEE_SUCCESS;

  if (cctx->flags == TA_EDGE_CACHE_CMD_GET_DOMAIN)
    res = make_domain_tables(io->buf, io->hdrlen, mngr);

  EDGE_MSG("Finished: http_process_data");
  return res;
}

/**
 * @brief Translate the character into the integer
 * @param str the string to be changed into the integer
 * @param slen the length of the string
 * @return the translated integer
 */
static int char_to_int(uint8_t *str, uint32_t slen)
{
  int i;
  int ret = 0;
  uint8_t ch;

  for (i=0; i<slen; i++)
  {
    ch = str[i];
    if (ch == ' ')
      break;

    switch(ch)
    {
      case '0':
        ret *= 10;
        continue;
      case '1':
        ret = ret * 10 + 1;
        continue;
      case '2':
        ret = ret * 10 + 2;
        continue;
      case '3':
        ret = ret * 10 + 3;
        continue;
      case '4':
        ret = ret * 10 + 4;
        continue;
      case '5':
        ret = ret * 10 + 5;
        continue;
      case '6':
        ret = ret * 10 + 6;
        continue;
      case '7':
        ret = ret * 10 + 7;
        continue;
      case '8':
        ret = ret * 10 + 8;
        continue;
      case '9':
        ret = ret * 10 + 9;
        continue;
    }
  }

  EDGE_LOG("Content-Length: %d", ret);
  return ret;
}
