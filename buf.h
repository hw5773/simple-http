/**
 * @file buf.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define the buffer operation
 */

#ifndef __BUF_H__
#define __BUF_H__

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include "debug.h"

typedef struct buf_st
{
  uint8_t *data;
  uint16_t len;
  uint16_t max;
} buf_t;

static inline buf_t *init_alloc_buf_mem(buf_t **buf, uint32_t len)
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

static inline buf_t *init_memcpy_buf_mem(buf_t **buf, uint8_t *data, uint32_t len)
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

static inline buf_t *init_buf_mem(buf_t **buf, uint8_t *data, uint32_t len)
{
  fstart("buf: %p, data: %p, len: %d", buf, data, len);
  (*buf) = (struct buf_st *)malloc(sizeof(struct buf_st));
  if (!(*buf))
    goto err;
  (*buf)->data = data;
  (*buf)->len = len;

  ffinish("buf: %p", buf);
  return (*buf);

err:
  ferr();
  return NULL;
}

static inline uint32_t update_buf_mem(buf_t *buf, uint32_t offset, uint8_t *data, uint32_t len)
{
  fstart("buf: %p, offset: %u, data: %p, len: %u", buf, offset, data, len);
  assert(buf != NULL);
  assert(data != NULL);
  assert(offset + len < buf->max);

  memcpy(buf->data + offset, data, len);
  buf->len = len;

  ffinish("len: %u", len);
  return len;
}

static inline uint8_t *get_buf_data(buf_t *buf)
{
  fstart("buf: %p", (void *)buf);
  assert(buf != NULL);
  assert(buf->data != NULL);

  if (!buf) goto err;
  if (!buf->data) goto err;

  ffinish("buf->data: %p", buf->data);
  return buf->data;

err:
  ffinish();
  return NULL;
}

static inline int get_buf_len(buf_t *buf)
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

static inline void free_buf(buf_t *buf)
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

#endif /* __TA_BUF_H__ */
