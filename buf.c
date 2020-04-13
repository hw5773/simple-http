#include "buf.h"
#include <string.h>

buf_t *init_alloc_buf_mem(buf_t **buf, int len)
{
  fstart("buf: %p, len: %d", buf, len);
  assert(buf != NULL);
  assert(len > 0);

  (*buf) = (buf_t *)malloc(sizeof(buf_t));
  if (!(*buf))
  {
    emsg("Out of memory for struct (%d bytes)", (int)sizeof(buf_t));
    goto err;
  }
  memset((*buf), 0x0, sizeof(buf_t));
  (*buf)->data = (uint8_t *)malloc(len + 1);
  if (!(*buf)->data)
  {
    emsg("Out of memory for data (%d bytes)", len);
    goto err;
  }
  memset((*buf)->data, 0x0, len + 1);
  (*buf)->offset = 0;
  (*buf)->max = len;

  ffinish();
  return (*buf);

err:
  if (*buf)
  {
    if ((*buf)->data)
      free((*buf)->data);

    free(*buf);
  }

  ferr();
  return NULL;
}

buf_t *init_memcpy_buf_mem(buf_t *buf, uint8_t *data, int len)
{
  fstart("buf: %p, data: %p, len: %d", buf, data, len);
  assert(buf != NULL);
  assert(len > 0);

  buf_t *ret;
  int internal;
  ret = NULL;
  internal = 0;

  if (!buf)
  {
    ret = (buf_t *)malloc(sizeof(buf_t));
    if (!ret) 
    {
      emsg("Out of memory");
      goto err;
    }
    internal = 1;
    memset(ret, 0x0, sizeof(buf_t));
  }
  else
    ret = buf;

  if (ret->data)
    free(ret->data);

  ret->data = (uint8_t *)malloc(len + 1);
  if (!ret->data) 
  {
    emsg("Out of memory");
    goto err;
  }
  memcpy(ret->data, data, len);
  ret->data[len] = 0;
  ret->offset = 0;
  ret->max = len;

  ffinish("ret: %p", ret);
  return ret;

err:
  if (ret)
  {
    if (ret->data)
      free(ret->data);

    if (internal)
      free(ret);
  }

  ferr();
  return NULL;
}

buf_t *init_buf_mem(buf_t *buf, uint8_t *data, int len)
{
  fstart("buf: %p, data: %p, len: %d", buf, data, len);
  
  buf_t *ret;
  int internal;

  ret = NULL;
  internal = 0;

  if (!buf)
  {
    ret = (buf_t *)malloc(sizeof(buf_t));
    if (!ret)
    {
      emsg("Out of memory");
      goto err;
    }
    memset(ret, 0x0, sizeof(buf_t));
    internal = 1;
  }
  else
    ret = buf;

  ret->data = data;
  ret->offset = 0;
  ret->max = len;

  ffinish("ret: %p", ret);
  return ret;

err:
  if (ret && internal)
    free(ret);

  ferr();
  return NULL;
}

int update_buf_mem(buf_t *buf, uint8_t *data, int len)
{
  fstart("buf: %p, data: %p, len: %u", buf, data, len);
  assert(buf != NULL);
  assert(data != NULL);

  int ret;

  if (buf->offset + len <= buf->max)
  {
    memcpy(buf->data + buf->offset, data, len);
    buf->offset += len;
    ret = len;
  }
  else
  {
    emsg("Out of memory");
    ret = -1;
  }

  return ret;
}

int add_buf_char(buf_t *buf, uint8_t ch)
{
  fstart("buf: %p, ch: %c", buf, ch);

  int ret;

  if (buf->offset + 1 <= buf->max)
  {
    *(buf->data + buf->offset) = ch;
    buf->offset += 1;
    ret = 1;
  }
  else
  {
    emsg("Out of memory");
    ret = -1;
  }

  return ret;
}

int get_buf_remaining(buf_t *buf)
{
  return buf->max - buf->offset;
}

uint8_t *get_buf_data(buf_t *buf)
{
  fstart("buf: %p", (void *)buf);
  assert(buf != NULL);
  assert(buf->data != NULL);

  if (!buf) goto err;
  if (!buf->data) goto err;

  ffinish("buf->data: %p", buf->data);
  return buf->data;

err:
  ferr();
  return NULL;
}

uint8_t *get_buf_curr(buf_t *buf)
{
  fstart("buf: %p", buf);

  uint8_t *ret;
  ret = NULL;

  if (buf && buf->data && buf->offset >= 0)
    ret = buf->data + buf->offset;
  else
  {
    emsg("Error in the buffer");
    goto err;
  }

  ffinish("ret: %p", ret);
  return ret;

err:
  ferr();
  return NULL;
}

uint8_t *get_buf_end(buf_t *buf)
{
  fstart("buf: %p", buf);

  uint8_t *ret;
  ret = NULL;

  if (buf && buf->data && buf->max >= 0)
    ret = buf->data + buf->max;
  else
  {
    emsg("Error in the buffer");
    goto err;
  }

  ffinish("ret: %p", ret);
  return ret;

err:
  ferr();
  return NULL;
}

int get_buf_offset(buf_t *buf)
{
  fstart("buf: %p", (void *)buf);
  assert(buf != NULL);
  assert(buf->data != NULL);

  if (!buf) goto err;
  if (!buf->data) goto err;

  ffinish("buf->len: %d", buf->offset);
  return buf->offset;

err:
  ferr();
  return -1;
}

int get_buf_total(buf_t *buf)
{
  fstart("buf: %p", (void *)buf);
  assert(buf != NULL);
  assert(buf->data != NULL);

  if (!buf) goto err;
  if (!buf->data) goto err;

  ffinish("buf->max: %d", buf->max);
  return buf->max;

err:
  ferr();
  return -1;
}

void free_buf(buf_t *buf)
{
  fstart("buf: %p", (void *)buf);
  if (buf)
  {
    if (buf->data)
    {
      free(buf->data);
    }
    buf->offset = 0;
    buf->data = NULL;
    free(buf);
    buf = NULL;
  }
  ffinish();
}

uint8_t *delete_space(uint8_t *p)
{
  fstart("p: %p", p);

  while (*p == ' ')
    p++;

  ffinish("p: %p", p);
  return p;
}

uint8_t *get_next_token(buf_t *buf, char *str, int *len)
{
  fstart("buf: %p, ch: %s, len: %p", buf, str, len);
  assert(buf != NULL);
  assert(len != NULL);

  uint8_t *ret, *space;
  ret = get_buf_curr(buf);
  ret = delete_space(ret);
  space = (uint8_t *)strstr((const char *)ret, str);
  
  if (space - buf->data > buf->max)
    space = NULL;

  if (!space)
  {
    *len = get_buf_remaining(buf);
  }
  else if (space > ret)
  {
    *len = space - ret;
    buf->offset += *len + strlen(str);
  }
  else
  {
    *len = get_buf_remaining(buf);
  }

  ffinish();
  return ret;
}
