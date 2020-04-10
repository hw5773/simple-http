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

  http->host = domain;
  http->hlen = dlen;

  ffinish();
}

void http_set_content(http_t *http, const char *content, int clen)
{
  fstart("http: %p, content: %s, clen: %d", http, content, clen);
  assert(http != NULL);
  assert(content != NULL);
  assert(clen > 0);

  http->content = content;
  http->clen = clen;

  ffinish();
}

void http_set_default_attributes(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  const char *user_agent_key = "User-Agent";
  const char *user_agent_value = "Wget/1.17.1 (linux-gnu)";

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
  fstart("http: %p, key: %s, klen: %d, value: %s, vlen: %d", http, key, klen, value, vlen);
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
  
  if (dlen)
    *dlen = http->dlen;

  ffinish("data: %p", http->data);
  return http->data;
}

// TODO: Should check the buffer overflow by adding the maximum value of the buffer
int http_make_get_request(http_t *http, uint8_t *hdr, int *hlen)
{
  fstart("http: %p, hdr: %p, hlen: %p", http, hdr, hlen);
  assert(http != NULL);
  assert(http->host != NULL);
  assert(http->hlen > 0);
  assert(hdr != NULL);
  assert(hlen != NULL);

  const char *method = "GET /";
  const char *host = "Host: ";
  const char *version;
  uint8_t *p;
  attribute_t *attr;
  int vlen, hostlen;

  p = hdr;

  switch (http->version)
  {
    case HTTP_VERSION_1_0:
      version = " HTTP/1";
      break;
    case HTTP_VERSION_1_1:
      version = " HTTP/1.1";
      break;
    case HTTP_VERSION_2:
      version = " HTTP/2";
      break;
    default:
      emsg("Unsupported version: %d", http->version);
      goto err;
  }

  memcpy(p, method, 5);
  p += 5;

  if (http->clen > 0)
  {
    memcpy(p, http->content, http->clen);
    p += http->clen;
  }

  vlen = (int)strlen(version);
  memcpy(p, version, vlen);
  p += vlen;
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;

  hostlen = (int)strlen(host);
  memcpy(p, host, hostlen);
  p += hostlen;
  memcpy(p, http->host, http->hlen);
  p += http->hlen;
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;

  attr = http->hdr;
  while (attr)
  {
    memcpy(p, attr->key, attr->klen);
    p += attr->klen;
    memcpy(p, COLON, COLON_LEN);
    p += COLON_LEN;
    memcpy(p, attr->value, attr->vlen);
    p += attr->vlen;
    memcpy(p, DELIMITER, DELIMITER_LEN);
    p += DELIMITER_LEN;
    attr = attr->next;
  }
  memcpy(p, DELIMITER, DELIMITER_LEN);
  p += DELIMITER_LEN;

  *hlen = p - hdr;

  dmsg("HTTP Header:\n%s\n", hdr);

  ffinish();
  return 1;

err:
  ferr();
  return -1;
}

int http_make_post_request(http_t *http, uint8_t *hdr, int *hlen)
{
  fstart("http: %p, hdr: %p, hlen: %p", http, hdr, hlen);
  assert(http != NULL);
  assert(hdr != NULL);
  assert(hlen != NULL);

  ffinish();
  return 1;

err:
  ferr();
  return -1;
}

int http_make_put_request(http_t *http, uint8_t *hdr, int *hlen)
{
  fstart("http: %p, hdr: %p, hlen: %p", http, hdr, hlen);
  assert(http != NULL);
  assert(hdr != NULL);
  assert(hlen != NULL);

  ffinish();
  return 1;

err:
  ferr();
  return -1;
}

int http_make_delete_request(http_t *http, uint8_t *hdr, int *hlen)
{
  fstart("http: %p, hdr: %p, hlen: %p", http, hdr, hlen);
  assert(http != NULL);
  assert(hdr != NULL);
  assert(hlen != NULL);

  ffinish();
  return 1;

err:
  ferr();
  return -1;
}

int http_serialize(http_t *http, uint8_t *hdr, int *hlen, uint8_t *data, int *dlen)
{
  fstart("http: %p, hdr: %p, hlen: %p, data: %p, dlen: %p", http, hdr, hlen, data, dlen);
  assert(http != NULL);
  assert(hdr != NULL);
  assert(hlen != NULL);
  
  int ret;

  if (http->type == HTTP_TYPE_REQUEST)
  {
    if (http->method == HTTP_METHOD_GET)
    {
      ret = http_make_get_request(http, hdr, hlen);
    }
    else if (http->method == HTTP_METHOD_POST)
    {
      ret = http_make_post_request(http, hdr, hlen);
    }
    else if (http->method == HTTP_METHOD_PUT)
    {
      ret = http_make_put_request(http, hdr, hlen);
    }
    else if (http->method == HTTP_METHOD_DELETE)
    {
      ret = http_make_delete_request(http, hdr, hlen);
    }
    else
    {
      emsg("Unsupported method: method: %d", http->method);
      goto err;
    }
    
    if (ret < 0) goto err;
  }
  else if (http->type == HTTP_TYPE_RESPONSE)
  {

  }

  data = http->data;
  *dlen = http->dlen;

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

  int l;
  const char *cptr, *nptr, *p, *q;
#ifdef DEBUG
  uint8_t buf[BUF_LEN] = {0, };
#endif /* DEBUG */

  cptr = buf;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;

#ifdef DEBUG
    memcpy(buf, cptr, l);
    buf[l + 1] = 0;
    dmsg("Token (%d bytes): %s", l, buf);
#endif /* DEBUG */

    p = cptr;

    while (*p == ' ')
      p++;

    if ((l > 0) && !strncmp((const char *)p, "GET", 3))
    {
      p += 3;

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
      }
      else
      {
        emsg("Error in parsing the content name");
        goto err;
      }
    }

    if ((l > 0) && !strncmp((const char *)p, "Host:", 5) == 0)
    {
      p += 5;

      while (*p == ' ')
        p++;

      if (nptr - p > 0)
      {
        http->host = (char *)malloc(nptr - p + 1);
        if (!http->host) goto err;
        memset(http->host, 0x0, nptr - p + 1);
        memcpy(http->host, p, nptr - p);
        http->hlen = nptr - p;
      }
      else
      {
        emsg("Error in parsing the domain name");
        goto err;
      }
    }

    if ((l > 0) && !strncmp((const char *)p, "Content-Length:", 15))
    {
      while (*p == ' ')
        p++;
      http->dlen = char_to_int(p, nptr - p);
    }

    cptr = nptr + DELIMITER_LEN;

#ifdef DEBUG
    memset(buf, 0x0, BUF_LEN);
#endif /* DEBUG */
  }

  http->data = p;

  if (http->hlen > 0)
    dmsg("Domain name in the parser (%d bytes): %s", http->hlen, http->host);
  if (http->clen > 0)
    dmsg("Content name in the parser (%d bytes): %s", http->clen, http->content);
  if (http->dlen > 0)
    dmsg("Content length in the parser (%d bytes): %s", http->dlen, http->data);

  ffinish();
  return 1;

err:
  ferr();
  return -1;
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
