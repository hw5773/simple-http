#ifndef __HTTP_STATUS_H__
#define __HTTP_STATUS_H__

#define MAX_STATUS_CODES      40
#define HTTP_STATUS_CODE_100  0
#define HTTP_STATUS_CODE_101  1
#define HTTP_STATUS_CODE_200  2
#define HTTP_STATUS_CODE_201  3
#define HTTP_STATUS_CODE_202  4
#define HTTP_STATUS_CODE_203  5
#define HTTP_STATUS_CODE_204  6
#define HTTP_STATUS_CODE_205  7
#define HTTP_STATUS_CODE_206  8
#define HTTP_STATUS_CODE_300  9
#define HTTP_STATUS_CODE_301  10
#define HTTP_STATUS_CODE_302  11
#define HTTP_STATUS_CODE_303  12
#define HTTP_STATUS_CODE_304  13
#define HTTP_STATUS_CODE_305  14
#define HTTP_STATUS_CODE_307  15
#define HTTP_STATUS_CODE_400  16
#define HTTP_STATUS_CODE_401  17
#define HTTP_STATUS_CODE_402  18
#define HTTP_STATUS_CODE_403  19
#define HTTP_STATUS_CODE_404  20
#define HTTP_STATUS_CODE_405  21
#define HTTP_STATUS_CODE_406  22
#define HTTP_STATUS_CODE_407  23
#define HTTP_STATUS_CODE_408  24
#define HTTP_STATUS_CODE_409  25
#define HTTP_STATUS_CODE_410  26
#define HTTP_STATUS_CODE_411  27
#define HTTP_STATUS_CODE_412  28
#define HTTP_STATUS_CODE_413  29
#define HTTP_STATUS_CODE_414  30
#define HTTP_STATUS_CODE_415  31
#define HTTP_STATUS_CODE_416  32
#define HTTP_STATUS_CODE_417  33
#define HTTP_STATUS_CODE_500  34
#define HTTP_STATUS_CODE_501  35
#define HTTP_STATUS_CODE_502  36
#define HTTP_STATUS_CODE_503  37
#define HTTP_STATUS_CODE_504  38
#define HTTP_STATUS_CODE_505  39

static const char *status_code[MAX_STATUS_CODES];
status_code[HTTP_STATUS_CODE_100] = "100";
status_code[HTTP_STATUS_CODE_101] = "101";
status_code[HTTP_STATUS_CODE_200] = "200";
status_code[HTTP_STATUS_CODE_201] = "201";
status_code[HTTP_STATUS_CODE_202] = "202";
status_code[HTTP_STATUS_CODE_203] = "203";
status_code[HTTP_STATUS_CODE_204] = "204";
status_code[HTTP_STATUS_CODE_205] = "205";
status_code[HTTP_STATUS_CODE_206] = "206";
status_code[HTTP_STATUS_CODE_300] = "300";
status_code[HTTP_STATUS_CODE_301] = "301";
status_code[HTTP_STATUS_CODE_302] = "302";
status_code[HTTP_STATUS_CODE_303] = "303";
status_code[HTTP_STATUS_CODE_304] = "304";
status_code[HTTP_STATUS_CODE_305] = "305";
status_code[HTTP_STATUS_CODE_307] = "307";
status_code[HTTP_STATUS_CODE_400] = "400";
status_code[HTTP_STATUS_CODE_401] = "401";
status_code[HTTP_STATUS_CODE_402] = "402";
status_code[HTTP_STATUS_CODE_403] = "403";
status_code[HTTP_STATUS_CODE_404] = "404";
status_code[HTTP_STATUS_CODE_405] = "405";
status_code[HTTP_STATUS_CODE_406] = "406";
status_code[HTTP_STATUS_CODE_407] = "407";
status_code[HTTP_STATUS_CODE_408] = "408";
status_code[HTTP_STATUS_CODE_409] = "409";
status_code[HTTP_STATUS_CODE_410] = "410";
status_code[HTTP_STATUS_CODE_411] = "411";
status_code[HTTP_STATUS_CODE_412] = "412";
status_code[HTTP_STATUS_CODE_413] = "413";
status_code[HTTP_STATUS_CODE_414] = "414";
status_code[HTTP_STATUS_CODE_415] = "415";
status_code[HTTP_STATUS_CODE_416] = "416";
status_code[HTTP_STATUS_CODE_417] = "417";
status_code[HTTP_STATUS_CODE_500] = "500";
status_code[HTTP_STATUS_CODE_501] = "501";
status_code[HTTP_STATUS_CODE_502] = "502";
status_code[HTTP_STATUS_CODE_503] = "503";
status_code[HTTP_STATUS_CODE_504] = "504";
status_code[HTTP_STATUS_CODE_505] = "505";

static const char *reason_phrase[MAX_STATUS_CODES];
reason_phrase[HTTP_STATUS_CODE_100] = "Continue";
reason_phrase[HTTP_STATUS_CODE_101] = "Switching Protocols";
reason_phrase[HTTP_STATUS_CODE_200] = "OK";
reason_phrase[HTTP_STATUS_CODE_201] = "Created";
reason_phrase[HTTP_STATUS_CODE_202] = "Accepted";
reason_phrase[HTTP_STATUS_CODE_203] = "Non-Authoritative Information";
reason_phrase[HTTP_STATUS_CODE_204] = "No Content";
reason_phrase[HTTP_STATUS_CODE_205] = "Reset Content";
reason_phrase[HTTP_STATUS_CODE_206] = "Partial Content";
reason_phrase[HTTP_STATUS_CODE_300] = "Multiple Choices";
reason_phrase[HTTP_STATUS_CODE_301] = "Moved Permanently";
reason_phrase[HTTP_STATUS_CODE_302] = "Found";
reason_phrase[HTTP_STATUS_CODE_303] = "See Other";
reason_phrase[HTTP_STATUS_CODE_304] = "Not Modified";
reason_phrase[HTTP_STATUS_CODE_305] = "Use Proxy";
reason_phrase[HTTP_STATUS_CODE_307] = "Temporary Redirect";
reason_phrase[HTTP_STATUS_CODE_400] = "Bad Request";
reason_phrase[HTTP_STATUS_CODE_401] = "Unauthorized";
reason_phrase[HTTP_STATUS_CODE_402] = "Payment Required";
reason_phrase[HTTP_STATUS_CODE_403] = "Forbidden";
reason_phrase[HTTP_STATUS_CODE_404] = "Not Found";
reason_phrase[HTTP_STATUS_CODE_405] = "Method Not Allowed";
reason_phrase[HTTP_STATUS_CODE_406] = "Not Acceptable";
reason_phrase[HTTP_STATUS_CODE_407] = "Proxy Authentication Required";
reason_phrase[HTTP_STATUS_CODE_408] = "Request Time-out";
reason_phrase[HTTP_STATUS_CODE_409] = "Conflict";
reason_phrase[HTTP_STATUS_CODE_410] = "Gone";
reason_phrase[HTTP_STATUS_CODE_411] = "Length Required";
reason_phrase[HTTP_STATUS_CODE_412] = "Precondition Failed";
reason_phrase[HTTP_STATUS_CODE_413] = "Request Entity Too Large";
reason_phrase[HTTP_STATUS_CODE_414] = "Request-URI Too Large";
reason_phrase[HTTP_STATUS_CODE_415] = "Unsupported Media Type";
reason_phrase[HTTP_STATUS_CODE_416] = "Requested range not satisfiable";
reason_phrase[HTTP_STATUS_CODE_417] = "Expectation Failed";
reason_phrase[HTTP_STATUS_CODE_500] = "Internal Server Error";
reason_phrase[HTTP_STATUS_CODE_501] = "Not Implemented";
reason_phrase[HTTP_STATUS_CODE_502] = "Bad Gateway";
reason_phrase[HTTP_STATUS_CODE_503] = "Service Unavailable";
reason_phrase[HTTP_STATUS_CODE_504] = "Gateway Time-out";
reason_phrase[HTTP_STATUS_CODE_505] = "HTTP Version not supported";

#endif /* __HTTP_STATUS_H__ */
