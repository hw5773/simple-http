#ifndef __DEBUG_H__
#define __DEBUG_H__

#define IDX_VAR(x, y) var_##x_##y_idx
#define DEBUG_LEVEL 0

#define LFINFO 0
#define LDEBUG 1
#define LINFO 2
#define LERROR 3

#if DEBUG_LEVEL <= LFINFO
  #ifdef SGXSSL
    #define fstart(format, ...) sgx_printf("[HTTP/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ffinish(format, ...) sgx_printf("[HTTP/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ferr(format, ...) sgx_printf("[HTTP/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define efstart(format, ...) sgx_printf("[ENCLAVE/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define effinish(format, ...) sgx_printf("[ENCLAVE/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define eferr(format, ...) sgx_printf("[ENCLAVE/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
  #else
    #define fstart(format, ...) printf("[HTTP/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ffinish(format, ...) printf("[HTTP/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ferr(format, ...) printf("[HTTP/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define efstart(format, ...) printf("[ENCLAVE/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define effinish(format, ...) printf("[ENCLAVE/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define eferr(format, ...) printf("[ENCLAVE/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
  #endif /* SGXSSL */
#else
#define fstart(format, ...)
#define ffinish(format, ...)
#define ferr(format, ...)
#define efstart(format, ...)
#define effinish(format, ...)
#define eferr(format, ...)
#endif /* LFINFO */

#if DEBUG_LEVEL <= LDEBUG
  #ifdef SGXSSL
    #define dmsg(format, ...) sgx_printf("[HTTP/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define edmsg(format, ...) sgx_printf("[ENCLAVE/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define dprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      sgx_printf("[HTTP/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        sgx_printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ -5) % interval == (interval - 1)) \
        { \
          sgx_printf("\n"); \
        } \
      } \
      sgx_printf("\n");
    #define edprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      sgx_printf("[ENCLAVE/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        sgx_printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ - 5) % interval == (interval - 1)) \
        { \
          sgx_printf("\n"); \
        } \
      } \
      sgx_printf("\n");
  #else
    #define dmsg(format, ...) printf("[HTTP/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define edmsg(format, ...) printf("[ENCLAVE/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define dprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      printf("[HTTP/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ -5) % interval == (interval - 1)) \
        { \
          printf("\n"); \
        } \
      } \
      printf("\n");
    #define edprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      printf("[ENCLAVE/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ - 5) % interval == (interval - 1)) \
        { \
          printf("\n"); \
        } \
      } \
      printf("\n");
    #endif /* SGXSSL */
#else
#define dmsg(format, ...)
#define edmsg(format, ...)
#define dprint(msg, buf, start, end, interval)
#define edprint(msg, buf, start, end, interval)
#endif /* DEBUG */

#if DEBUG_LEVEL <= LINFO
  #ifdef SGXSSL
    #define imsg(format, ...) sgx_printf("[HTTP/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define eimsg(format, ...) sgx_printf("[ENCLAVE/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define iprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      sgx_printf("[HTTP/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        sgx_printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ - 5) % interval == (interval - 1)) \
        { \
          sgx_printf("\n"); \
        } \
      } \
      sgx_printf("\n");
    #define eiprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      sgx_printf("[ENCLAVE/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        sgx_printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ - 5) % interval == (interval - 1)) \
        { \
          sgx_printf("\n"); \
        } \
      } \
      sgx_printf("\n");
  #else
    #define imsg(format, ...) printf("[HTTP/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define eimsg(format, ...) printf("[ENCLAVE/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define iprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      printf("[HTTP/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ - 5) % interval == (interval - 1)) \
        { \
          printf("\n"); \
        } \
      } \
      printf("\n");
    #define eiprint(msg, buf, start, end, interval) \
      int IDX_VAR(__func__, __LINE__); \
      printf("[ENCLAVE/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
      for (IDX_VAR(__func__, __LINE__ - 2) = start; IDX_VAR(__func__, __LINE__ - 2) < end; IDX_VAR(__func__, __LINE__ - 2)++) \
      { \
        printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
        if (IDX_VAR(__func__, __LINE__ - 5) % interval == (interval - 1)) \
        { \
          printf("\n"); \
        } \
      } \
      printf("\n");
  #endif /* SGXSSL */
#else
#define imsg(format, ...)
#define eimsg(format, ...)
#define iprint(msg, buf, start, end, interval)
#define eiprint(msg, buf, start, end, interval)
#endif /* INFO */

#if DEBUG_LEVEL <= LERROR
  #ifdef SGXSSL
    #define emsg(format, ...) sgx_printf("[HTTP/ERROR] " format "\n", ## __VA_ARGS__)
    #define eemsg(format, ...) sgx_printf("[ENCLAVE/ERROR] " format "\n", ## __VA_ARGS__)
  #else
    #define emsg(format, ...) printf("[HTTP/ERROR] " format "\n", ## __VA_ARGS__)
    #define eemsg(format, ...) printf("[ENCLAVE/ERROR] " format "\n", ## __VA_ARGS__)
  #endif /* SGXSSL */   
#else
#define emsg(format, ...)
#define eemsg(format, ...)
#endif /* ERROR */

#endif /* __DEBUG_H__ */
