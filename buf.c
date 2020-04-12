#include "buf.h"

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
  (*buf)->len = 0;
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

buf_t *init_memcpy_buf_mem(buf_t **buf, uint8_t *data, int len)
{
  fstart("buf: %p, data: %p, len: %d", buf, data, len);
  assert(buf != NULL);
  assert(len > 0);

  (*buf) = (buf_t *)malloc(sizeof(buf_t));
  if (!(*buf))
    goto err;
  memset((*buf), 0x0, sizeof(struct buf_st));
  (*buf)->data = (uint8_t *)malloc(len + 1);
  if (!(*buf)->data)
    goto err;
  memset((*buf)->data, 0x0, len + 1);
  memcpy((*buf)->data, data, len);
  (*buf)->len = len;
  (*buf)->max = len;

  ffinish("buf: %p", buf);
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

buf_t *init_buf_mem(buf_t **buf, uint8_t *data, int len)
{
  fstart("buf: %p, data: %p, len: %d", buf, data, len);
  (*buf) = (struct buf_st *)malloc(sizeof(struct buf_st));
  if (!(*buf))
    goto err;
  (*buf)->data = data;
  (*buf)->len = len;
  (*buf)->max = len;

  ffinish("buf: %p", buf);
  return (*buf);

err:
  ferr();
  return NULL;
}

int update_buf_mem(buf_t *buf, uint8_t *data, int len)
{
  fstart("buf: %p, data: %p, len: %u", buf, data, len);
  assert(buf != NULL);
  assert(data != NULL);

  int ret;

  if (buf->len + len <= buf->max)
  {
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    ret = len;
  }
  else
  {
    emsg("Out of memory");
    ret = -1
  }

  return ret;
}

int add_buf_char(buf_t *buf, uint8_t ch)
{
  fstart("buf: %p, ch: %c", buf, ch);

  int ret;

  if (buf->len + 1 <= buf->max)
  {
    *(buf->data + buf->len) = ch;
    buf->len += 1;
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
  return buf->max - buf->len;
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

  if (buf && buf->data && buf->len >= 0)
    ret = buf->data + buf->len;
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

int get_buf_len(buf_t *buf)
{
  fstart("buf: %p", (void *)buf);
  assert(buf != NULL);
  assert(buf->data != NULL);

  if (!buf) goto err;
  if (!buf->data) goto err;

  ffinish("buf->len: %d", buf->len);
  return buf->len;

err:
  ffinish();
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
    buf->len = 0;
    buf->data = NULL;
    free(buf);
    buf = NULL;
  }
  ffinish();
}
