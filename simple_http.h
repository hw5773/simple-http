#ifndef __SIMPLE_HTTP_H__
#define __SIMPLE_HTTP_H__

#include <inttypes.h>
#include <string.h>
#include "buf.h"

#define BUF_LEN           256
#define INDEX_FILE        "/index.html"
#define INDEX_FILE_LEN    12

#define DELIMITER             "\r\n"
#define DELIMITER_LEN         2

#define DOMAIN_DELIMITER      "\n\n"
#define DOMAIN_DELIMITER_LEN  2

#define HTTP_VERSION_NONE     0
#define HTTP_VERSION_1_0      1
#define HTTP_VERSION_1_1      2
#define HTTP_VERSION_2        3

#define HTTP_METHOD_NONE      0
#define HTTP_METHOD_GET       1
#define HTTP_METHOD_POST      2
#define HTTP_METHOD_PUT       3
#define HTTP_METHOD_DELETE    4

#define HTTP_TYPE_REQUEST     0
#define HTTP_TYPE_RESPONSE    1

typedef struct attribute_st {
  uint8_t *key;
  int klen;
  uint8_t *value;
  int vlen;
  attribute_t *next;
} attribute_t;

typedef struct http_st {
  int version;
  int method;
  int type;
  int num_of_attr;
  int hlen;
  attribute_t *hdr;
  int dlen;
  uint8_t *data;
} http_t;

typedef struct request_st {
} request_t;

int init_http_message(http_t **http);
int add_header_attribute(http_t *http, uint8_t *key, int klen, uint8_t *value, int vlen);

int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content, uint32_t clen,
    uint8_t *msg, uint32_t *mlen);
int http_parse_request(uint8_t *msg, uint32_t mlen, request_t **req);
int http_parse_response(uint8_t *msg, uint32_t mlen);

#endif /* __SIMPLE_HTTP_H__ */
