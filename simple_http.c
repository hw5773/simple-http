#include "simple_http.h"
#include <ctype.h>

static int char_to_int(const char *str, uint32_t slen);

attribute_t *init_attribute(char *key, int klen, char *value, int vlen)
{
  fstart("key: %p, klen: %d, value: %p, vlen: %d", key, klen, value, vlen);
  assert(key != NULL);
  assert(klen > 0);
  assert(value != NULL);
  assert(vlen > 0);

  attribute_t *ret;
  ret = (attribute_t *)malloc(sizeof(attribute_t));
  if (!ret) goto err;

  ret->key = (char *)malloc(klen + 1);
  if (!ret->key) goto err;
  memset(ret->key, 0x0, klen + 1);
  memcpy(ret->key, key, klen);
  ret->klen = klen;

  ret->value = (char *)malloc(vlen + 1);
  if (!ret->value) goto err;
  memset(ret->value, 0x0, vlen + 1);
  memcpy(ret->value, value, vlen);
  ret->vlen = vlen;

  ffinish();
  return ret;

err:
  if (ret)
  {
    if (ret->key)
      free(ret->key);

    if (ret->value)
      free(ret->value);

    free(ret);
  }
  ferr();
  return NULL;
}

void free_attribute(attribute_t *attr)
{
  fstart("attr: %p", attr);
  assert(attr != NULL);

  if (attr)
  {
    if (attr->key)
      free(attr->key);
    attr->klen = 0;

    if (attr->value)
      free(attr->value);
    attr->vlen = 0;

    free(attr);
  }
}

http_t *init_http_message(int type)
{
  fstart("type: %d", type);
  assert(type >= 0);

  http_t *ret;
  ret = (http_t *)malloc(sizeof(http_t));
  if (!ret) goto err;
  memset(ret, 0x0, sizeof(http_t));

  ret->type = type;

  ffinish();
  return ret;

err:
  if (ret)
    free(ret);
  ferr();
  return NULL;
}

void free_http_message(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  attribute_t *curr, *next;
  curr = http->hdr;
  next = curr->next;

  if (curr)
  {
    do {
      del_header_attribute(http, curr->key, curr->klen);
      curr = next;
      next = curr->next;
    } while (next);
  }

  free(http);
  ffinish();
}

void http_set_version(http_t *http, int version)
{
  fstart("http: %p, version: %d", http, version);
  assert(http != NULL);
  assert(version >= 0);

  http->version = version;

  ffinish();
}

void http_set_method(http_t *http, int method)
{
  fstart("http: %p, method: %d", http, method);
  assert(http != NULL);
  assert(method >= 0);

  http->method = method;

  ffinish();
}

void http_set_domain(http_t *http, const char *domain, int dlen)
{
  fstart("http: %p, domain: %s, dlen: %d", http, domain, dlen);
  assert(http != NULL);
  assert(domain != NULL);
  assert(dlen > 0);

  http->host = (char *)domain;
  http->hlen = dlen;

  ffinish();
}

void http_set_content(http_t *http, const char *content, int clen)
{
  fstart("http: %p, content: %s, clen: %d", http, content, clen);
  assert(http != NULL);
  assert(content != NULL);
  assert(clen > 0);

  http->content = (char *)content;
  http->clen = clen;

  ffinish();
}

void http_set_default_attributes(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  const char *user_agent_key = "User-Agent";
  const char *user_agent_value = "curl/7.47.0";

  const char *accept_key = "Accept";
  const char *accept_value = "*/*";

  const char *accept_encoding_key = "Accept-Encoding";
  const char *accept_encoding_value = "identity";

  add_header_attribute(http, (char *) user_agent_key, (int) strlen(user_agent_key), 
      (char *) user_agent_value, (int) strlen(user_agent_value));

  add_header_attribute(http, (char *) accept_key, (int) strlen(accept_key),
      (char *) accept_value, (int) strlen(accept_value));

  add_header_attribute(http, (char *) accept_encoding_key, (int) strlen(accept_encoding_key),
      (char *) accept_encoding_value, (int) strlen(accept_encoding_value));

  ffinish();
}

attribute_t *find_header_attribute(http_t *http, char *key, int klen)
{
  fstart("http: %p", http);
  assert(http != NULL);

  attribute_t *curr, *ret;
  ret = NULL;

  curr = http->hdr;

  if (curr)
  {
    do {
      if (curr->klen == klen && !strncmp(curr->key, key, klen))
      {
        ret = curr;
        break;
      }
      curr = curr->next;
    } while (curr);
  }

  ffinish();
  return ret;
}

int add_header_attribute(http_t *http, char *key, int klen, char *value, int vlen)
{
  fstart("http: %p, key: %p, klen: %d, value: %p, vlen: %d", http, key, klen, value, vlen);
  assert(http != NULL);
  assert(key != NULL);
  assert(klen > 0);
  assert(value != NULL);
  assert(vlen > 0);

  attribute_t *attr;
  attr = find_header_attribute(http, key, klen);

  if (!attr)
  {
    attr = init_attribute(key, klen, value, vlen);
    attr->next = http->hdr;
    http->hdr = attr;
  }
  else
  {
    if (attr->value)
      free(attr->value);

    attr->value = (char *)malloc(vlen);
    memcpy(attr->value, value, vlen);
    attr->vlen = vlen;
  }
  http->num_of_attr += 1;

  ffinish();
  return 1;
}

void del_header_attribute(http_t *http, char *key, int klen)
{
  fstart("http: %p, key: %p, klen: %d", http, key, klen);
  assert(http != NULL);
  assert(key != NULL);
  assert(klen > 0);

  attribute_t *hdr, *curr, *next;
  hdr = curr = http->hdr;

  if (http->num_of_attr > 0)
  {
    if (hdr && hdr->klen == klen && !strncmp(hdr->key, key, klen))
    {
      http->hdr = hdr->next;
      free_attribute(hdr);
      http->num_of_attr -= 1;
    }
    else
    {
      next = curr->next;
      while (next)
      {
        if (next->klen == klen && !strncmp(next->key, key, klen))
        {
          curr->next = next->next;
          free_attribute(next);
          http->num_of_attr -= 1;
          break;
        }
        curr = next;
        next = curr->next;
      }
    }
  }

  assert(http->num_of_attr >= 0);
  ffinish();
}

void print_header(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  attribute_t *ptr;
  
  if (http->type == HTTP_TYPE_REQUEST)
    printf("Type: HTTP Request\n");
  else if (http->type == HTTP_TYPE_RESPONSE)
    printf("Type: HTTP Response\n");
  else
    printf("Type: Error\n");

  if (http->version == HTTP_VERSION_NONE)
    printf("HTTP Version: None\n");
  else if (http->version == HTTP_VERSION_1_0)
    printf("HTTP Version: HTTP/1\n");
  else if (http->version == HTTP_VERSION_1_1)
    printf("HTTP Version: HTTP/1.1\n");
  else if (http->version == HTTP_VERSION_2)
    printf("HTTP Version: HTTP/2\n");
  else
    printf("HTTP Version: Error\n");

  if (http->method == HTTP_METHOD_NONE)
    printf("HTTP Method: None\n");
  else if (http->method == HTTP_METHOD_GET)
    printf("HTTP Method: GET\n");
  else if (http->method == HTTP_METHOD_POST)
    printf("HTTP Method: POST\n");
  else if (http->method == HTTP_METHOD_PUT)
    printf("HTTP Method: PUT\n");
  else if (http->method == HTTP_METHOD_DELETE)
    printf("HTTP Method: DELETE\n");
  else
    printf("HTTP Method: Error\n");

  ptr = http->hdr;
  while (ptr)
  {
    printf("%s: %s\n", ptr->key, ptr->value);
    ptr = ptr->next;
  }

  ffinish();
}

uint8_t *http_get_data(http_t *http, int *dlen)
{
  fstart("http: %p, dlen: %p", http, dlen);
  assert(http != NULL);
  
  attribute_t *attr;
  const char *key = "Transfer-Encoding";
  const char *chunked = "chunked";
  int klen;

  klen = (int)strlen(key);

  if (dlen)
  {
    attr = find_header_attribute(http, key, klen);

    if (attr && attr->vlen == strlen(chunked) && !strncmp(attr->value, chunked, attr->vlen))
      *dlen = -1;
    else
      *dlen = http->dlen;
  }

  ffinish("data: %p", http->data);
  return http->data;
}

int http_make_version(http_t *http, buf_t *msg)
{
  fstart("http: %p, msg: %p", http, msg);

  switch (http->version)
  {
    case HTTP_VERSION_1_0:
      update_buf_mem(msg, "HTTP/1", 6);
      break;
    case HTTP_VERSION_1_1:
      update_buf_mem(msg, "HTTP/1.1", 8);
      break;
    default:
      emsg("Unsupported Version: %d", http->version);
      goto err;
  }

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_make_code_and_reason(http_t *http, buf_t *msg)
{
  fstart("http: %p, msg: %p", http, msg);

  const char *code, *reason;
  int clen, rlen;

  if (!http->code)
  {
    emsg("HTTP Code is not set");
    goto err;
  }

  code = status_code[http->code];
  reason = reason_phrase[http->code];

  clen = (int) strlen(code);
  rlen = (int) strlen(reason);

  update_buf_mem(msg, code, clen);
  update_buf_mem(msg, reason, rlen);

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_make_request_line(http_t *http, buf_t *msg)
{
  fstart("http: %p, msg: %p", http, msg);
  assert(http != NULL);
  assert(msg != NULL);

  int ret;

  switch (http->method)
  {
    case HTTP_METHOD_GET:
      ret = update_buf_mem(msg, "GET ", 4);
      break;
    case HTTP_METHOD_POST:
      ret = update_buf_mem(msg, "POST ", 5);
      break;
    case HTTP_METHOD_PUT:
      ret = update_buf_mem(msg, "PUT ", 4);
      break;
    case HTTP_METHOD_DELETE:
      ret = update_buf_mem(msg, "DELETE ", 7);
      break;
    default:
      emsg("Unsupported Method");
      goto err;
  }

  if (ret < 0) goto err;

  if (http->abs_path && http->alen > 0)
    ret = update_buf_mem(msg, http->abs_path, http->alen);
  else
    ret = update_buf_mem(msg, "/ ", 2);

  ret = http_make_version(http, msg);
  if (ret == HTTP_FAILURE) goto err;

  ADD_CRLF(msg);

  ret = update_buf_mem(msg, "Host: ", 6);
  if (ret < 0) goto err;

  ret = update_buf_mem(msg, http->host, http->hlen);
  if (ret < 0) goto err;

  ADD_CRLF(msg);

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_make_status_line(http_t *http, buf_t *msg)
{
  fstart("http: %p, msg: %p", http, msg);
  assert(http != NULL);
  assert(msg != NULL);

  int ret;

  ret = http_make_version(http, msg);
  if (ret < 0) goto err;
  
  ret = add_buf_char(msg, ' ');
  if (ret < 0) goto err;

  ret = http_make_code_and_reason(http, msg);
  if (ret < 0) goto err;

  ADD_CRLF(msg);

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_make_message_header(http_t *http, buf_t *msg)
{
  fstart("http: %p, msg: %p", http, msg);

  attribute_t *attr;

  attr = http->hdr;

  while (attr)
  {
    ret = update_buf_mem(msg, attr->key, attr->klen);
    if (ret < 0) goto err;
    COLON(msg);

    ret = update_buf_mem(msg, attr->value, attr->vlen);
    if (ret < 0) goto err;
    ADD_CRLF(msg);
  }

  ADD_CRLF(msg);

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_make_message_body(http_t *http, buf_t *msg)
{
  fstart("http: %p, msg: %p", http, msg);

  int ret;

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_serialize(http_t *http, uint8_t *msg, int max, int *mlen)
{
  fstart("http: %p, msg: %p, max: %d, mlen: %p", http, msg, max, mlen);
  assert(http != NULL);
  assert(msg != NULL);
  assert(max > 0);
  assert(mlen != NULL);
  
  int ret;
  buf_t *buf;

  init_alloc_buf_mem(&buf, max);

  if (http->type == HTTP_TYPE_REQUEST)
    ret = http_make_request_line(http, buf);
  else if (http->type == HTTP_TYPE_RESPONSE)
    ret = http_make_status_line(http, buf);
  if (ret < 0) goto err;

  ret = http_make_message_header(http, buf);
  if (ret < 0) goto err;

  ret = http_make_message_body(http, buf);
  if (ret < 0) goto err;

  *mlen = get_buf_len(buf);
  memcpy(msg, get_buf_data(buf), *mlen);

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_parse_message_header(http_t *http, const char *p, int l)
{
  fstart("http: %p, p: %p, l: %d", http, p, l);
  dmsg("p: %s", p);
  if (l <= 0) goto err;

  const char *key, *value, *end, *q;
  int klen, vlen;

  end = p + l;
  while (*p == ' ')
    p++;

  value = strchr(p, ':');
  if (!value || (value - p > l))
  {
    if (!strncmp(p, "GET", 3))
    {
      http->type = HTTP_TYPE_REQUEST;
      http->method = HTTP_METHOD_GET;

      while (*p != '/')
        p++;

      q = p;

      while (*q != ' ')
        q++;

      if (q - p == 1)
      {
        http->content = INDEX_FILE;
        http->clen = INDEX_FILE_LEN;
      }
      else if (q - p > 1)
      {
        http->content = (char *)malloc(q - p);
        if (!http->content) goto err;
        memset(http->content, 0x0, q - p);
        memcpy(http->content, p + 1, q - p - 1);
        http->clen = q - p - 1;
        dmsg("Content (%d bytes): %s", http->clen, http->content);
      }
      else
      {
        emsg("Error in parsing the content name");
        goto err;
      }
    }
    else if (!strncmp(p, "HTTP", 4))
    {
      http->type = HTTP_TYPE_RESPONSE;
      http->method = HTTP_METHOD_NONE;
      p += 4;

      if (*p == '/')
      {
        p += 1;
        if (*p == '1' && *(p+1) == ' ')
        {
          http->version = HTTP_VERSION_1_0;
          p += 1;
        }
        else if (*p == '1' && *(p+1) == '.' && *(p+2) == '1')
        {
          http->version = HTTP_VERSION_1_1;
          p += 3;
        }
        else if (*p == '2')
        {
          http->version = HTTP_VERSION_2;
          p += 1;
        }
      }
      while (*p == ' ')
        p++;
      q = p;
      p = strchr(q, ' ');
      http->code = char_to_int(q, p - q);
    }
  }
  else
  {
    key = p;
    klen = value - key;
    value = value + 1;
    while (*value == ' ')
      value++;
    vlen = l - (value - key);

    if (!strncmp(key, "Host:", 5))
    {
      dmsg("Host:\n%s", p);
      p += 5;

      dmsg("p: %p", p);
      while (*p == ' ')
        p++;

      if (end - p > 0)
      {
        http->host = (char *)malloc(end - p + 1);
        if (!http->host) goto err;
        memset(http->host, 0x0, end - p + 1);
        memcpy(http->host, p, end - p);
        http->hlen = end - p;
      }
      else
      {
        emsg("Error in parsing the domain name");
        goto err;
      }
    }
    else if ((l > 0) && !strncmp((const char *)p, "Content-Length:", 15))
    {
      while (*p == ' ')
        p++;
      http->dlen = char_to_int(p, end - p);
    }
    else
    {
      add_header_attribute(http, key, klen, value, vlen);

      attribute_t *attr;
      attr = find_header_attribute(http, key, klen);
      dmsg("key (%d bytes): %s", attr->klen, attr->key);
      dmsg("value (%d bytes): %s", attr->vlen, attr->value);
    }
  }

  ffinish();
  return 1;

err:
  ferr();
  return -1;
}

int http_deserialize(uint8_t *buf, int len, http_t *http)
{
  fstart("buf: %p, len: %d, http: %p", buf, len, http);
  assert(buf != NULL);
  assert(len > 0);
  assert(http != NULL);

  const char *cptr, *nptr, *p, *start;
  int start_line;
#ifdef DEBUG
  int l;
  uint8_t debug[BUF_LEN] = {0, };
#endif /* DEBUG */

  start = (const char *)buf;
  cptr = (const char *)buf;
  start_line = 0;

  while ((nptr = strstr(cptr, CRLF)))
  {
#ifdef DEBUG
    l = nptr - cptr;
    memcpy(debug, cptr, l);
    debug[l + 1] = 0;
    dmsg("Token (%d bytes): %s", l, debug);
#endif /* DEBUG */

    p = cptr;

    while (*p == ' ')
      p++;

    if (!start_line)
      http_parse_start_line(http, p, l);
    else
      http_parse_message_header(http, p, l);
    cptr = nptr + CRLF_LEN;

#ifdef DEBUG
    memset(debug, 0x0, BUF_LEN);
#endif /* DEBUG */
  }

  dmsg("len: %d, p - start: %lu", len, p - start);

  http->data = p;

  if (http->hlen > 0)
    dmsg("Domain name in the parser (%d bytes): %s", http->hlen, http->host);
  if (http->clen > 0)
    dmsg("Content name in the parser (%d bytes): %s", http->clen, http->content);
  if (http->dlen > 0)
    dmsg("Content length in the parser (%d bytes): %s", http->dlen, http->data);

  ffinish();
  return 1;
}

/**
 * @brief Translate the character into the integer
 * @param str the string to be changed into the integer
 * @param slen the length of the string
 * @return the translated integer
 */
static int char_to_int(const char *str, uint32_t slen)
{
  fstart("str: %s, slen: %d", str, slen);
  assert(str != NULL);
  assert(slen > 0);

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

  ffinish("ret: %d", ret);
  return ret;
}
