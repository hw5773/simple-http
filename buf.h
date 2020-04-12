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
  int len;
  int max;
} buf_t;

buf_t *init_alloc_buf_mem(buf_t **buf, int len);
buf_t *init_memcpy_buf_mem(buf_t **buf, uint8_t *data, int len);
buf_t *init_buf_mem(buf_t **buf, uint8_t *data, int len);
int update_buf_mem(buf_t *buf, uint8_t *data, int len);
int add_buf_char(buf_t *buf, uint8_t ch);
int get_buf_remaining(buf_t *buf);
uint8_t *get_buf_data(buf_t *buf);
uint8_t *get_curr_ptr(buf_t *buf);
int get_buf_len(buf_t *buf);
void free_buf(buf_t *buf);

#endif /* __BUF_H__ */
