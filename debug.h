#ifndef __DEBUG_H__
#define __DEBUG_H__

#define DEBUG_LEVEL 0

#define LFINFO 0
#define LDEBUG 1
#define LINFO 2
#define LERROR 3

#if DEBUG_LEVEL <= LFINFO
  #ifdef SGXSSL
    #define fstart(format, ...) sgx_printf("[SEED/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ffinish(format, ...) sgx_printf("[SEED/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ferr(format, ...) sgx_printf("[SEED/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define efstart(format, ...) sgx_printf("[ENCLAVE/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define effinish(format, ...) sgx_printf("[ENCLAVE/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define eferr(format, ...) sgx_printf("[ENCLAVE/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
  #else
    #define fstart(format, ...) printf("[SEED/FINFO] Start: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ffinish(format, ...) printf("[SEED/FINFO] Finish: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define ferr(format, ...) printf("[SEED/FINFO] Error: %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
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
    #define dmsg(format, ...) sgx_printf("[SEED/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define edmsg(format, ...) sgx_printf("[ENCLAVE/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define dprint(msg, buf, start, end, interval) \
      do { \
        int i; \
        sgx_printf("[SEED/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
        for (i = start; i < end; i++) \
        { \
          sgx_printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
          if (i % interval == (interval - 1)) \
          { \
            sgx_printf("\n"); \
          } \
        } \
        sgx_printf("\n"); \
      } while (0);
    #define edprint(msg, buf, start, end, interval) \
      do { \
        int i; \
        sgx_printf("[ENCLAVE/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
        for (i = start; i < end; i++) \
        { \
          sgx_printf("%02X ", buf[i]); \
          if (i % interval == (interval - 1)) \
          { \
            sgx_printf("\n"); \
          } \
        } \
        sgx_printf("\n"); \
      } while (0);
  #else
    #define dmsg(format, ...) printf("[SEED/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define edmsg(format, ...) printf("[ENCLAVE/DEBUG] %s:%s:%d: " format "\n", __FILE__, __func__, __LINE__, ## __VA_ARGS__)
    #define dprint(msg, buf, start, end, interval) \
      do { \
        int i; \
        printf("[SEED/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
        for (i = start; i < end; i++) \
        { \
          printf("%02X ", buf[i]); \
          if (i % interval == (interval - 1)) \
          { \
            printf("\n"); \
          } \
        } \
        printf("\n"); \
      } while (0);
    #define edprint(msg, buf, start, end, interval) \
      do { \
        int i; \
        printf("[ENCLAVE/DEBUG] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
        for (i = start; i < end; i++) \
        { \
          printf("%02X ", buf[i]); \
          if (i % interval == (interval - 1)) \
          { \
            printf("\n"); \
          } \
        } \
        printf("\n"); \
      } while (0);
    #endif /* SGXSSL */
#else
#define dmsg(format, ...)
#define edmsg(format, ...)
#define dprint(msg, buf, start, end, interval)
#define edprint(msg, buf, start, end, interval)
#endif /* DEBUG */

#if DEBUG_LEVEL <= LINFO
  #ifdef SGXSSL
    #define imsg(format, ...) sgx_printf("[SEED/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define eimsg(format, ...) sgx_printf("[ENCLAVE/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define iprint(msg, buf, start, end, interval) \
      do { \
        int i; \
        sgx_printf("[SEED/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
        for (i = start; i < end; i++) \
        { \
          sgx_printf("%02X ", buf[i]); \
          if (i % interval == (interval - 1)) \
          { \
            sgx_printf("\n"); \
          } \
        } \
        sgx_printf("\n"); \
      } while (0);
    #define eiprint(msg, buf, start, end, interval) \
      do { \
        int i; \
        sgx_printf("[ENCLAVE/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
        for (i = start; i < end; i++) \
        { \
          sgx_printf("%02X ", buf[i]); \
          if (i % interval == (interval - 1)) \
          { \
            sgx_printf("\n"); \
          } \
        } \
        sgx_printf("\n"); \
      } while (0);
  #else
    #define imsg(format, ...) printf("[SEED/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define eimsg(format, ...) printf("[ENCLAVE/INFO] %s:%s: " format "\n", __FILE__, __func__, ## __VA_ARGS__)
    #define iprint(msg, buf, start, end, interval) \
      do { \
          int i; \
          printf("[SEED/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
          for (i = start; i < end; i++) \
        { \
          printf("%02X ", buf[IDX_VAR(__func__, __LINE__ - 4)]); \
          if (i % interval == (interval - 1)) \
          { \
            printf("\n"); \
          } \
        } \
        printf("\n"); \
      } while (0);
    #define eiprint(msg, buf, start, end, interval) \
      do { \
        int i; \
        printf("[ENCLAVE/INFO] %s:%s: %s (%d bytes)\n", __FILE__, __func__, msg, end - start); \
        for (i = start; i < end; i++) \
        { \
          printf("%02X ", buf[i]); \
          if (i % interval == (interval - 1)) \
          { \
            printf("\n"); \
          } \
        } \
        printf("\n"); \
      } while (0);
  #endif /* SGXSSL */
#else
#define imsg(format, ...)
#define eimsg(format, ...)
#define iprint(msg, buf, start, end, interval)
#define eiprint(msg, buf, start, end, interval)
#endif /* INFO */

#if DEBUG_LEVEL <= LERROR
  #ifdef SGXSSL
    #define emsg(format, ...) sgx_printf("[SEED/ERROR] " format "\n", ## __VA_ARGS__)
    #define eemsg(format, ...) sgx_printf("[ENCLAVE/ERROR] " format "\n", ## __VA_ARGS__)
  #else
    #define emsg(format, ...) printf("[SEED/ERROR] " format "\n", ## __VA_ARGS__)
    #define eemsg(format, ...) printf("[ENCLAVE/ERROR] " format "\n", ## __VA_ARGS__)
  #endif /* SGXSSL */   
#else
#define emsg(format, ...)
#define eemsg(format, ...)
#endif /* ERROR */

#endif /* __DEBUG_H__ */
