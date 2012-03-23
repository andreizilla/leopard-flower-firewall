#ifndef SYSCALL_WRAPPERS_H
#define SYSCALL_WRAPPERS_H

#include <stdarg.h> //for dynamic arguments

#ifndef RELEASE
#include <stdio.h>
#include "../conntrack.h"
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#endif

#define _fopen(retval, ...) \
  do { \
    if (retval != NULL){ \
      if ((retval = fopen (__VA_ARGS__)) == NULL){ \
	M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
	return; \
      } \
    } \
    else \
    fopen (__VA_ARGS__); \
  } while (0); \

#define _nfct_query(...) \
do { \
    if (nfct_query (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "nfct_query: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfct_callback_register(...) \
do { \
    if (nfct_callback_register (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "nfct_callback_register: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _fseek(...) \
do { \
    if (fseek (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "fseek: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _fclose(...) \
do { \
    if (fclose (__VA_ARGS__) == EOF){ \
      M_PRINTF ( MLOG_INFO, "fclose: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _fputs(...) \
do { \
    if (fputs (__VA_ARGS__) == EOF){ \
      M_PRINTF ( MLOG_INFO, "fputs: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _fputc(...) \
do { \
    if (fputc (__VA_ARGS__) == EOF){ \
      M_PRINTF ( MLOG_INFO, "fputc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _fgets(...) \
do { \
    if (fgets (__VA_ARGS__) == NULL){ \
      M_PRINTF ( MLOG_INFO, "fgets: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _access(...) \
do { \
    if (access (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "access: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _stat(...) \
do { \
    if (stat (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "stat: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _system(...) \
do { \
    if (system (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "system: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfq_unbind_pf(...) \
do { \
    if (nfq_unbind_pf (__VA_ARGS__) < 0){ \
      M_PRINTF ( MLOG_INFO, "nfq_unbind_pf: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfq_bind_pf(...) \
do { \
    if (nfq_bind_pf (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "nfq_bind_pf: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _system(...) \
do { \
    if (system (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "system: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfq_set_mode(...) \
do { \
    if (nfq_set_mode (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "nfq_set_mode: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfq_set_queue_maxlen(...) \
do { \
    if (nfq_set_queue_maxlen (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "nfq_set_queue_maxlen: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfct_new(retval) \
do { \
    if ((retval = nfct_new ()) == NULL){ \
      M_PRINTF ( MLOG_INFO, "nfct_new: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfct_open(retval, ...) \
do { \
  if (retval != NULL){ \
    if ((retval = nfct_open (__VA_ARGS__)) == NULL){ \
      M_PRINTF ( MLOG_INFO, "nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
  } \
  else \
  nfct_open (__VA_ARGS__); \
} while (0); \


#define _write(retval, ...) \
do { \
  if (retval != 0){ \
    if ((retval = write (__VA_ARGS__)) == -1){ \
      M_PRINTF ( MLOG_INFO, "write: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
  } \
  else \
  write (__VA_ARGS__); \
} while (0); \


#define _nfq_create_queue(retval, ...) \
do { \
  if (retval != NULL){ \
    if ((retval = nfq_create_queue (__VA_ARGS__)) == NULL){ \
      M_PRINTF ( MLOG_INFO, "nfq_create_queue: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
  } \
  else \
  nfq_create_queue (__VA_ARGS__); \
} while (0); \

#define _nfq_open(retval, ...) \
do { \
  if (retval != NULL){ \
    if ((retval = nfq_open (__VA_ARGS__)) == NULL){ \
      M_PRINTF ( MLOG_INFO, "nfq_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
  } \
  else \
  nfq_open (__VA_ARGS__); \
} while (0); \





#endif // SYSCALL_WRAPPERS_H
