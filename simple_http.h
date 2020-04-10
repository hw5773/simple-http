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

#define COLON                 ": "
#define COLON_LEN             2

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
  char *key;
  int klen;
  char *value;
  int vlen;
  struct attribute_st *next;
} attribute_t;

typedef struct http_st {
  int type;
  int version;
  int method;
  int code;

  char *host;
  int hlen;
  char *content;
  int clen;

  int num_of_attr;
  attribute_t *hdr;
  
  uint8_t *data;
  int dlen;
} http_t;

attribute_t *init_attribute(char *key, int klen, char *value, int vlen);
void free_attribute(attribute_t *attr);

http_t *init_http_message(int type);
void free_http_message(http_t *http);

void http_set_version(http_t *http, int version);
void http_set_method(http_t *http, int method);
void http_set_domain(http_t *http, const char *domain, int dlen);
void http_set_content(http_t *http, const char *content, int clen);
void http_set_default_attributes(http_t *http);

attribute_t *find_header_attribute(http_t *http, char *key, int klen);
int add_header_attribute(http_t *http, char *key, int klen, char *value, int vlen);
void del_header_attribute(http_t *http, char *key, int klen);
void print_header(http_t *http);

uint8_t *http_get_data(http_t *http, int *dlen);

int http_serialize(http_t *http, uint8_t *hdr, int *hlen, uint8_t *data, int *dlen);
int http_deserialize(uint8_t *buf, int len, http_t *http);

#endif /* __SIMPLE_HTTP_H__ */
