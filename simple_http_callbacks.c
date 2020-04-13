#include "simple_http_callbacks.h"
#include <unistd.h>

http_cbs_t *init_http_callbacks(void)
{
  fstart();

  http_cbs_t *cbs;
  cbs = (http_cbs_t *)malloc(sizeof(http_cbs_t));
  if (!cbs) 
  {
    emsg("Out of memory");
    goto err;
  }
  memset(cbs, 0x0, sizeof(http_cbs_t));

  ffinish("cbs: %p", cbs);
  return cbs;

err:
  ferr();
  return cbs;
}

int register_callback(http_cbs_t *cbs, int method, char *abs_path, int alen, 
    int (*callback)(http_t *req, http_t *resp))
{
  fstart("cbs: %p, abs_path: %s, alen: %d, callback: %p", cbs, abs_path, alen, callback);

  http_cb_t *cb;
  cb = (http_cb_t *)malloc(sizeof(http_cb_t));
  if (!cb) 
  {
    emsg("Out of memory");
    goto err;
  }
  memset(cb, 0x0, sizeof(http_cb_t));

  cb->method = method;
  cb->abs_path = abs_path;
  cb->alen = alen;
  cb->callback = callback;

  if (cbs->head)
    cb->next = cbs->head;
  cbs->head = cb;

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}

http_cb_t *retrieve_callback(http_cbs_t *cbs, int method, char *abs_path, int alen)
{
  fstart("cbs: %p, abs_path: %s, alen: %d", cbs, abs_path, alen);

  http_cb_t *ret, *curr;
  ret = NULL;
  curr = cbs->head;

  while (curr)
  {
    if ((method & curr->method) 
        && alen == curr->alen 
        && !strncmp(abs_path, curr->abs_path, alen))
    {
      ret = curr;
      break;
    }
    curr = curr->next;
  }

  if (!ret)
  {
    emsg("Cannot found the callback function");
    goto err;
  }

  ffinish();
  return ret;

err:
  ferr();
  return NULL;
}

int process_request(http_cbs_t *cbs, http_t *req, http_t *resp)
{
  fstart("cbs: %p, req: %p, resp: %p", cbs, req, resp);

  http_cb_t *cb;
  int ret;
  cb = retrieve_callback(cbs, req->type, req->abs_path, req->alen);
  if (!cb)
  {
    if (access(req->abs_path + 1, F_OK) != -1)
    {
      dmsg("File exists: %s", req->abs_path + 1);
    }
    else
    {
      emsg("No file found");
      resp->code = HTTP_STATUS_CODE_404;
    }
  }
  else
  {
    ret = cb->callback(req, resp);
    if (ret != HTTP_SUCCESS) goto err;
  }

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}
