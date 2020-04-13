#include "simple_http.h"
#include <ctype.h>

static int char_to_int(uint8_t *str, uint32_t slen, int base);
static int int_to_char(int num, uint8_t *str, int base);

void init_http_module(void)
{
  init_http_status();
}

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

void http_set_abs_path(http_t *http, const char *abs_path, int alen)
{
  fstart("http: %p, abs_path: %s, alen: %d", http, abs_path, alen);
  assert(http != NULL);
  assert(abs_path != NULL);
  assert(alen > 0);

  http->abs_path = (char *)abs_path;
  http->alen = alen;

  ffinish();
}

void http_set_default_request_attributes(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  const char *user_agent_key = "User-Agent";
  const char *user_agent_value = "curl/7.47.0";

  const char *accept_key = "Accept";
  const char *accept_value = "*/*";

  add_header_attribute(http, (char *) user_agent_key, (int) strlen(user_agent_key), 
      (char *) user_agent_value, (int) strlen(user_agent_value));

  add_header_attribute(http, (char *) accept_key, (int) strlen(accept_key),
      (char *) accept_value, (int) strlen(accept_value));

  ffinish();
}

void http_set_default_response_attributes(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  const char *expires_key = "Expires";
  const char *expires_value = "-1";

  const char *content_type_key = "Content-Type";
  const char *content_type_value = "text/html; charset=utf-8";

  const char *transfer_encoding_key = "Transfer-Encoding";
  const char *transfer_encoding_value = "chunked";

  const char *vary_key = "Vary";
  const char *vary_value = "Accept-Encoding";

  add_header_attribute(http, (char *) expires_key, (int) strlen(expires_key),
      (char *) expires_value, (int) strlen(expires_value));

  add_header_attribute(http, (char *) content_type_key, (int) strlen(content_type_key),
      (char *) content_type_value, (int) strlen(content_type_value));

  add_header_attribute(http, (char *) transfer_encoding_key, (int) strlen(transfer_encoding_key),
      (char *) transfer_encoding_value, (int) strlen(transfer_encoding_value));

  add_header_attribute(http, (char *) vary_key, (int) strlen(vary_key),
      (char *) vary_value, (int) strlen(vary_value));

  ffinish();
}

void http_set_default_attributes(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  if (http->type == HTTP_TYPE_REQUEST)
    http_set_default_request_attributes(http);
  else if (http->type == HTTP_TYPE_RESPONSE)
    http_set_default_response_attributes(http);
  else
  {
    emsg("Unsupported type: %d", http->type);
    abort();
  }

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
  return HTTP_SUCCESS;
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

resource_t *http_get_resource(http_t *http)
{
  fstart("http: %p", http);
  assert(http != NULL);

  if (!http->resource) goto err;
  
  return http->resource;

err:
  return NULL;
}

void http_update_resource(http_t *http, int offset)
{
  fstart("http: %p, offset: %d", http, offset);
  assert(http != NULL);
  assert(offset >= 0);

  resource_t *resource;
  resource = http_get_resource(http);
  if (resource)
    resource->offset += offset;

  ffinish();
}

int http_make_version(http_t *http, buf_t *msg)
{
  fstart("http: %p, msg: %p", http, msg);

  const char *http1 = "HTTP/1";
  const char *http1_1 = "HTTP/1.1";
  const char *http2 = "HTTP/2";

  switch (http->version)
  {
    case HTTP_VERSION_1_0:
      update_buf_mem(msg, (uint8_t *)http1, (int)strlen(http1));
      break;
    case HTTP_VERSION_1_1:
      update_buf_mem(msg, (uint8_t *)http1_1, (int)strlen(http1_1));
      break;
    case HTTP_VERSION_2:
      update_buf_mem(msg, (uint8_t *)http2, (int)strlen(http2));
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
  int ret, clen, rlen;

  if (!http->code)
  {
    emsg("HTTP Code is not set");
    goto err;
  }

  code = status_code[http->code];
  reason = reason_phrase[http->code];

  clen = (int) strlen(code);
  rlen = (int) strlen(reason);

  update_buf_mem(msg, (uint8_t *)code, clen);
  ret = add_buf_char(msg, ' ');
  if (ret < 0) goto err;
  update_buf_mem(msg, (uint8_t *)reason, rlen);

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
  const char *get = "GET ";
  const char *post = "POST ";
  const char *put = "PUT ";
  const char *delete = "DELETE ";

  switch (http->method)
  {
    case HTTP_METHOD_GET:
      ret = update_buf_mem(msg, (uint8_t *)get, strlen(get));
      break;
    case HTTP_METHOD_POST:
      ret = update_buf_mem(msg, (uint8_t *)post, strlen(post));
      break;
    case HTTP_METHOD_PUT:
      ret = update_buf_mem(msg, (uint8_t *)put, strlen(put));
      break;
    case HTTP_METHOD_DELETE:
      ret = update_buf_mem(msg, (uint8_t *)delete, strlen(delete));
      break;
    default:
      emsg("Unsupported Method");
      goto err;
  }

  if (ret < 0) goto err;

  if (http->abs_path && http->alen > 0)
    ret = update_buf_mem(msg, (uint8_t *)http->abs_path, http->alen);
  else
    ret = update_buf_mem(msg, (uint8_t *)"/ ", 2);

  ret = http_make_version(http, msg);
  if (ret != HTTP_SUCCESS) goto err;

  ADD_CRLF(msg);

  ret = update_buf_mem(msg, (uint8_t *)"Host: ", 6);
  if (ret < 0) goto err;

  ret = update_buf_mem(msg, (uint8_t *)http->host, http->hlen);
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
  if (ret != HTTP_SUCCESS) goto err;
  
  ret = add_buf_char(msg, ' ');
  if (ret < 0) goto err;

  ret = http_make_code_and_reason(http, msg);
  if (ret != HTTP_SUCCESS) goto err;

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
  int ret;

  ret = HTTP_SUCCESS;
  attr = http->hdr;

  while (attr)
  {
    ret = update_buf_mem(msg, (uint8_t *)attr->key, attr->klen);
    if (ret < 0) goto err;
    ADD_COLON(msg);

    ret = update_buf_mem(msg, (uint8_t *)attr->value, attr->vlen);
    if (ret < 0) goto err;
    ADD_CRLF(msg);

    attr = attr->next;
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

  int ret, remaining, len;
  FILE *fp;
  uint8_t *buf;
  resource_t *resource;

  ret = HTTP_SUCCESS;
  fp = NULL;
  buf = NULL;
  resource = http_get_resource(http);

  if (resource)
  {
    remaining = get_buf_remaining(msg);
    if (resource->type == HTTP_RESOURCE_MEM)
    {
      buf = (uint8_t *)resource->ptr + resource->offset;
      if (remaining >= resource->size - resource->offset)
        len = resource->size - resource->offset;
      else
        len = remaining;
      update_buf_mem(msg, buf, len);
    }
    else if (resource->type == HTTP_RESOURCE_FILE)
    {
      fp = (FILE *)resource->ptr;
      buf = (uint8_t *)malloc(BUF_SIZE);
      
      fseek(fp, resource->offset, SEEK_SET);
      if (remaining >= resource->size - resource->offset)
        len = resource->size - resource->offset;
      else
        len = remaining;
      fread(buf, 1, len, fp);
      update_buf_mem(msg, buf, len);
      free(buf);
    }
    
    remaining = get_buf_remaining(msg);
    if (!remaining)
      ret = HTTP_SUCCESS;
    else
      ret = HTTP_NOT_FINISHED;
  }

  ffinish();
  return ret;
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

  if (!http->header)
  {
    if (http->type == HTTP_TYPE_REQUEST)
      ret = http_make_request_line(http, buf);
    else if (http->type == HTTP_TYPE_RESPONSE)
      ret = http_make_status_line(http, buf);
    if (ret != HTTP_SUCCESS) goto err;

    ret = http_make_message_header(http, buf);
    if (ret != HTTP_SUCCESS) goto err;

    http->header = 1;
  }

  ret = http_make_message_body(http, buf);

  *mlen = get_buf_offset(buf);
  memcpy(msg, get_buf_data(buf), *mlen);

  ffinish();
  return ret;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_parse_version(http_t *http, uint8_t *p, int len)
{
  fstart("http: %p, p: %p, len: %d", http, p, len);

  const char *http1 = "HTTP/1";
  const char *http1_1 = "HTTP/1.1";
  const char *http2 = "HTTP/2";

  if (len == 6 && !strncmp((const char *)p, http1, strlen(http1)))
    http->version = HTTP_VERSION_1_0;
  else if (len == 8 && !strncmp((const char *)p, http1_1, strlen(http1_1)))
    http->version = HTTP_VERSION_1_1;
  else if (len == 6 && !strncmp((const char *)p, http2, strlen(http2)))
    http->version = HTTP_VERSION_2;
  else
    http->version = HTTP_VERSION_NONE;

  ffinish();
  return HTTP_SUCCESS;
}

int http_parse_status_code(http_t *http, uint8_t *p, int len)
{
  fstart("http: %p, p: %p, len: %d", http, p, len);

  int status_code;
  status_code = char_to_int(p, 3, 10);

  switch (status_code)
  {
    case 100:
      http->code = HTTP_STATUS_CODE_100;
      break;
    case 101:
      http->code = HTTP_STATUS_CODE_101;
      break;
    case 200:
      http->code = HTTP_STATUS_CODE_200;
      break;
    case 201:
      http->code = HTTP_STATUS_CODE_201;
      break;
    case 202:
      http->code = HTTP_STATUS_CODE_202;
      break;
    case 203:
      http->code = HTTP_STATUS_CODE_203;
      break;
    case 204:
      http->code = HTTP_STATUS_CODE_204;
      break;
    case 205:
      http->code = HTTP_STATUS_CODE_205;
      break;
    case 206:
      http->code = HTTP_STATUS_CODE_206;
      break;
    case 300:
      http->code = HTTP_STATUS_CODE_300;
      break;
    case 301:
      http->code = HTTP_STATUS_CODE_301;
      break;
    case 302:
      http->code = HTTP_STATUS_CODE_302;
      break;
    case 303:
      http->code = HTTP_STATUS_CODE_303;
      break;
    case 304:
      http->code = HTTP_STATUS_CODE_304;
      break;
    case 305:
      http->code = HTTP_STATUS_CODE_305;
      break;
    case 307:
      http->code = HTTP_STATUS_CODE_307;
      break;
    case 400:
      http->code = HTTP_STATUS_CODE_400;
      break;
    case 401:
      http->code = HTTP_STATUS_CODE_401;
      break;
    case 402:
      http->code = HTTP_STATUS_CODE_402;
      break;
    case 403:
      http->code = HTTP_STATUS_CODE_403;
      break;
    case 404:
      http->code = HTTP_STATUS_CODE_404;
      break;
    case 405:
      http->code = HTTP_STATUS_CODE_405;
      break;
    case 406:
      http->code = HTTP_STATUS_CODE_406;
      break;
    case 407:
      http->code = HTTP_STATUS_CODE_407;
      break;
    case 408:
      http->code = HTTP_STATUS_CODE_408;
      break;
    case 409:
      http->code = HTTP_STATUS_CODE_409;
      break;
    case 410:
      http->code = HTTP_STATUS_CODE_410;
      break;
    case 411:
      http->code = HTTP_STATUS_CODE_411;
      break;
    case 412:
      http->code = HTTP_STATUS_CODE_412;
      break;
    case 413:
      http->code = HTTP_STATUS_CODE_413;
      break;
    case 414:
      http->code = HTTP_STATUS_CODE_414;
      break;
    case 415:
      http->code = HTTP_STATUS_CODE_415;
      break;
    case 416:
      http->code = HTTP_STATUS_CODE_416;
      break;
    case 417:
      http->code = HTTP_STATUS_CODE_417;
      break;
    case 500:
      http->code = HTTP_STATUS_CODE_500;
      break;
    case 501:
      http->code = HTTP_STATUS_CODE_501;
      break;
    case 502:
      http->code = HTTP_STATUS_CODE_502;
      break;
    case 503:
      http->code = HTTP_STATUS_CODE_503;
      break;
    case 504:
      http->code = HTTP_STATUS_CODE_504;
      break;
    case 505:
      http->code = HTTP_STATUS_CODE_505;
      break;
    default:
      http->code = HTTP_STATUS_CODE_NONE;
  }

  ffinish();
  return HTTP_SUCCESS;
}

int http_parse_request_line(http_t *http, buf_t *line)
{
  fstart("http: %p, line: %p", http, line);

  uint8_t *p;
  int len;
  const char *get = "GET";
  const char *post = "POST";
  const char *put = "PUT";
  const char *delete = "DELETE";

  // Method
  p = get_next_token(line, " ", &len);
  if (!p) goto err;

  if (len == 3 && !strncmp((const char *)p, get, len))
    http->method = HTTP_METHOD_GET;
  else if (len == 4 && !strncmp((const char *)p, post, len))
    http->method = HTTP_METHOD_POST;
  else if (len == 3 && !strncmp((const char *)p, put, len))
    http->method = HTTP_METHOD_PUT;
  else if (len == 6 && !strncmp((const char *)p, delete, len))
    http->method = HTTP_METHOD_DELETE;
  else
    http->method = HTTP_METHOD_NONE;

  // Request-URI
  p = get_next_token(line, " ", &len);
  http->abs_path = (char *)malloc(len + 1);
  memcpy(http->abs_path, p, len);
  http->abs_path[len] = 0;
  http->alen = len;

  // HTTP-Version
  p = get_next_token(line, " ", &len);
  http_parse_version(http, p, len);

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_parse_status_line(http_t *http, buf_t *line)
{
  fstart("http: %p, line: %p", http, line);

  uint8_t *p;
  int len;

  // HTTP-Version
  p = get_next_token(line, " ", &len);
  if (!p) goto err;
  http_parse_version(http, p, len);

  // Status-Code
  p = get_next_token(line, " ", &len);
  if (!p) goto err;
  http_parse_status_code(http, p, len);

  // Reason-Phrase (Do nothing)
  p = get_next_token(line, " ", &len);
  if (!p) goto err;

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_parse_start_line(http_t *http, buf_t *line)
{
  fstart("http: %p, line: %p", http, line);

  uint8_t *p;
  int ret;
  p = get_buf_curr(line);

  if (p[0] == 'H' && p[1] == 'T' && p[2] == 'T' && p[3] == 'P')
  {
    http->type = HTTP_TYPE_RESPONSE;
    ret = http_parse_status_line(http, line);
  }
  else
  {
    http->type = HTTP_TYPE_REQUEST;
    ret = http_parse_request_line(http, line);
  }

  if (ret != HTTP_SUCCESS) goto err;

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_parse_message_header(http_t *http, buf_t *line)
{
  fstart("http: %p, line: %p", http, line);

  char *key, *value, *end, *p;
  int klen, vlen;

  end = (char *)get_buf_end(line);
  if (!end) goto err;

  p = (char *)get_buf_curr(line);
  value = strchr(p, ':');
  key = p;
  klen = value - key;
  value = value + 1;
  value = (char *)delete_space((uint8_t *)value);
  vlen = end - value;

  if (!strncmp(key, "Host:", 5))
  {
    dmsg("Host:\n%s", p);
    p += 5;
    p = (char *)delete_space((uint8_t *)p);

    if (line->data + line->max - (uint8_t *)p > 0)
    {
      http->hlen = end - p;
      http->host = (char *)malloc(http->hlen + 1);
      if (!http->host) goto err;
      memcpy(http->host, p, end - p);
      http->host[http->hlen] = 0;
    }
    else
    {
      emsg("Error in parsing the domain name");
      goto err;
    }
  }
  else
  {
    add_header_attribute(http, key, klen, value, vlen);

    attribute_t *attr;
    attr = find_header_attribute(http, key, klen);
    dmsg("key (%d bytes): %s", attr->klen, attr->key);
    dmsg("value (%d bytes): %s", attr->vlen, attr->value);
  }

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_parse_request_message_body(http_t *http, buf_t *buf, FILE *fp)
{
  fstart("http: %p, buf: %p, fp: %p", http, buf, fp);
  assert(http != NULL);
  assert(buf != NULL);

  int ret;
  ret = HTTP_SUCCESS;

  switch (http->method)
  {
    case HTTP_METHOD_GET:
      ret = HTTP_SUCCESS;
      break;
    case HTTP_METHOD_POST:
      emsg("Not implemented");
      goto err;
    case HTTP_METHOD_PUT:
      emsg("Not implemented");
      goto err;
    case HTTP_METHOD_DELETE:
      emsg("Not implemented");
      goto err;
    default:
      break;
  }

  ffinish();
  return ret;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_parse_response_message_body(http_t *http, buf_t *buf, FILE *fp)
{
  fstart("http: %p, buf: %p, fp: %p", http, buf, fp);
  assert(http != NULL);
  assert(buf != NULL);

  attribute_t *attr;
  resource_t *resource;
  const char *key1, *key2, *key3, *chunked, *p;
  uint8_t tmp[10] = {0, };
  uint8_t tbuf[BUF_SIZE] = {0, };
  int len, clen, tlen, vlen, next;
  key1 = "Transfer-Encoding";
  key2 = "Content-Length";
  key3 = "Content-length";
  chunked = "chunked";
  len = 0;
  clen = 0;
  next = 0;

  resource = http_get_resource(http);
  if (!http->body)
  {
    attr = find_header_attribute(http, (char *)key1, strlen(key1));
    if (attr)
      if (!strncmp(attr->value, chunked, attr->vlen))
        http->chunked = 1;

    if (!http->chunked)
    {
      attr = find_header_attribute(http, (char *)key2, strlen(key2));

      if (attr)
      {
        clen = char_to_int((uint8_t *)attr->value, attr->vlen, 10);
        if (clen == 0) goto out;
      }
      else
      {
        attr = find_header_attribute(http, (char *)key3, strlen(key3));
        if (attr)
        {
          clen = char_to_int((uint8_t *)attr->value, attr->vlen, 10);
          if (clen == 0) goto out;
        }
      }
    }

    if (clen > 0 || http->chunked)
    {
      if (!resource)
      {
        http->resource = (resource_t *)malloc(sizeof(resource_t));
        memset(http->resource, 0x0, sizeof(resource_t));
        resource = http_get_resource(http);
        resource->type = HTTP_RESOURCE_FILE;
      }

      if (http->chunked)
        resource->size = 0;
      else if (clen > 0)
        resource->size = clen;
      resource->offset = 0;
    }

    http->body = 1;
  }

  // Transfer-Encoding: chunked
  if (http->chunked)
  {
    if (resource->offset < resource->size)
    {
      p = (const char *)get_next_token(buf, CRLF, &tlen);
      len = get_buf_remaining(buf);
      if (tlen < len)
      {
        memcpy(tbuf, p, tlen);
        fprintf(fp, "%s", tbuf);
      }
      else
      {
        fprintf(fp, "%s", p);
      }
      resource->offset += tlen;
    }

    if (resource->offset >= resource->size)
    {
      next = 1;
    }

    if (next)
    {
      p = (const char *)get_next_token(buf, CRLF, &tlen);
      
      clen = char_to_int((uint8_t *)p, tlen, 16);

      if (tlen > 0 && !clen)
      {
        vlen = int_to_char(resource->size, tmp, 10);
        add_header_attribute(http, (char *)key1, (int) strlen(key1), (char *)tmp, vlen);
        goto out;
      }

      if (clen > 0)
      {
        resource->size += clen;
        p = (const char *)get_next_token(buf, CRLF, &tlen);
        resource->offset += tlen;
        fprintf(fp, "%s", p);
      }
    }
  }
  else
  {
    if (resource->offset < resource->size)
    {
      p = (const char *)get_buf_curr(buf);
      len = get_buf_remaining(buf);
      fprintf(fp, "%s", p);
      resource->offset += len;
    }
    else
      goto out;
  }

  ffinish();
  return HTTP_NOT_FINISHED;

out:
  ffinish();
  return HTTP_SUCCESS;
}

int http_parse_message_body(http_t *http, buf_t *buf, FILE *fp)
{
  fstart("http: %p, buf: %p", http, buf);
  assert(http != NULL);
  assert(buf != NULL);

  int ret;
  ret = HTTP_SUCCESS;

  switch (http->type)
  {
    case HTTP_TYPE_REQUEST:
      ret = http_parse_request_message_body(http, buf, fp);
      break;
    case HTTP_TYPE_RESPONSE:
      ret = http_parse_response_message_body(http, buf, fp);
      break;
    default:
      goto err;
  }

  ffinish();
  return ret;

err:
  ferr();
  return HTTP_FAILURE;
}

int http_deserialize(uint8_t *buf, int len, http_t *http, FILE *fp)
{
  fstart("buf: %p, len: %d, http: %p", buf, len, http);
  assert(buf != NULL);
  assert(len > 0);
  assert(http != NULL);

  const char *cptr, *nptr, *p;
  int start_line, hlen, l, ret;
  buf_t *line;
#ifdef DEBUG
  uint8_t debug[BUF_LEN] = {0, };
#endif /* DEBUG */

  cptr = (const char *)buf;
  start_line = hlen = 0;
  line = init_alloc_buf_mem(&line, BUF_SIZE);

  if (!http->header)
  {
    while ((nptr = strstr(cptr, CRLF)))
    {
      l = nptr - cptr;
      hlen += l;
      p = cptr;
      if (l == 0) break;
#ifdef DEBUG
      memcpy(debug, cptr, l);
      debug[l + 1] = 0;
      dmsg("Token (%d bytes): %s", l, debug);
#endif /* DEBUG */

      line = init_buf_mem(line, (uint8_t *)p, l);

      if (!start_line)
      {
        ret = http_parse_start_line(http, line);
        start_line = 1;
      }
      else
        ret = http_parse_message_header(http, line);
      if (ret != HTTP_SUCCESS) goto err;
      cptr = nptr + CRLF_LEN;
      hlen += CRLF_LEN;
      cptr = (const char *)delete_space((uint8_t *)cptr);

#ifdef DEBUG
      memset(debug, 0x0, BUF_LEN);
#endif /* DEBUG */
    }
    http->header = 1;
    p = p + CRLF_LEN;
    hlen += CRLF_LEN;
    line = init_buf_mem(line, (uint8_t *)p, len - hlen);
  }
  else
  {
    line = init_buf_mem(line, (uint8_t *)cptr, len);
  }

  ret = http_parse_message_body(http, line, fp);
  if (ret == HTTP_FAILURE) goto err;

  if (http->hlen > 0)
    dmsg("Domain name in the parser (%d bytes): %s", http->hlen, http->host);
  if (http->alen > 0)
    dmsg("Content name in the parser (%d bytes): %s", http->alen, http->abs_path);

  ffinish();
  return ret;

err:
  ferr();
  return HTTP_FAILURE;
}

/**
 * @brief Translate the character into the integer
 * @param str the string to be changed into the integer
 * @param slen the length of the string
 * @return the translated integer
 */
static int char_to_int(uint8_t *str, uint32_t slen, int base)
{
  fstart("str: %s, slen: %d", str, slen);
  assert(str != NULL);

  int i;
  int ret = 0;
  uint8_t ch;

  if (!slen) goto out;

  for (i=0; i<slen; i++)
  {
    ch = str[i];
    if (ch == ' ')
      break;

    switch(ch)
    {
      case '0':
        ret *= base;
        break;
      case '1':
        ret = ret * base + 1;
        break;
      case '2':
        ret = ret * base + 2;
        break;
      case '3':
        ret = ret * base + 3;
        break;
      case '4':
        ret = ret * base + 4;
        break;
      case '5':
        ret = ret * base + 5;
        break;
      case '6':
        ret = ret * base + 6;
        break;
      case '7':
        ret = ret * base + 7;
        break;
      case '8':
        ret = ret * base + 8;
        break;
      case '9':
        ret = ret * base + 9;
        break;
      case 'a':
        ret = ret * base + 10;
        break;
      case 'b':
        ret = ret * base + 11;
        break;
      case 'c':
        ret = ret * base + 12;
        break;
      case 'd':
        ret = ret * base + 13;
        break;
      case 'e':
        ret = ret * base + 14;
        break;
      case 'f':
        ret = ret * base + 15;
        break;
      default:
        break;
    }
  }

out:
  ffinish("ret: %d", ret);
  return ret;
}

static int int_to_char(int num, uint8_t *str, int base)
{
  fstart("num: %d, str: %p", num, str);
  assert(str != NULL);

  int i, tmp, rem, ret;

  ret = 0;
  tmp = num;
  for (i=0; i<10; i++)
  {
    rem = tmp % base;
    if (rem > 0)
      ret = i;
    tmp /= base;
  }

  ret++;

  tmp = num;
  for (i=0; i<ret; i++)
  {
    rem = tmp % base;
    if (rem >= 0 && rem <= 9)
      str[ret - i - 1] = rem + 48;
    if (rem >= 10)
      str[ret - i - 1] = rem + 87;
    tmp /= base;
  }

  ffinish("str (%d bytes): %s", ret, str);
  return ret;
}
