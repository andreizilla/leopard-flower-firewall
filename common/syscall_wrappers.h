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
#include <pthread.h>
#include <sys/capability.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

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

#define _opendir(retval, ...) \
  do { \
    if (retval != NULL){ \
      if ((retval = opendir (__VA_ARGS__)) == NULL){ \
	M_PRINTF ( MLOG_INFO, "opendir: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
	return; \
      } \
    } \
    else \
    opendir (__VA_ARGS__); \
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

#define _fileno(retval, ...) \
do { \
    if ((retval = fileno (__VA_ARGS__)) == -1){ \
      M_PRINTF ( MLOG_INFO, "fileno: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _pthread_mutex_lock(...) \
do { \
    if (pthread_mutex_lock (__VA_ARGS__) != 0){ \
      M_PRINTF ( MLOG_INFO, "pthread_mutex_lock: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _pthread_mutex_unlock(...) \
do { \
    if (pthread_mutex_unlock (__VA_ARGS__) != 0){ \
      M_PRINTF ( MLOG_INFO, "pthread_mutex_unlock: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _cap_get_proc(retval) \
do { \
    if ((retval = cap_get_proc ()) == NULL){ \
      M_PRINTF ( MLOG_INFO, "cap_get_proc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _cap_set_proc(...) \
do { \
    if (cap_set_proc (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "cap_set_proc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _cap_clear(...) \
do { \
    if (cap_clear (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "cap_clear: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _cap_free(...) \
do { \
    if (cap_free (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "cap_free: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _cap_set_flag(...) \
do { \
    if (cap_set_flag (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "cap_set_flag: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _nfq_close(...) \
do { \
    if (nfq_close (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "nfq_close: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _malloc(retval, ...) \
do { \
    if ((retval = malloc (__VA_ARGS__)) == NULL){ \
      M_PRINTF ( MLOG_INFO, "malloc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _closedir(...) \
do { \
    if (closedir (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "closedir: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _pthread_cond_signal(...) \
do { \
    if (pthread_cond_signal (__VA_ARGS__) != 0){ \
      M_PRINTF ( MLOG_INFO, "pthread_cond_signal: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _mkfifo(...) \
do { \
    if (mkfifo (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "mkfifo: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _open(retval , ...) \
do { \
    if ((retval = open (__VA_ARGS__)) == -1){ \
      M_PRINTF ( MLOG_INFO, "open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _fsync(...) \
do { \
    if (fsync (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "fsync: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _lseek(...) \
do { \
    if (lseek (__VA_ARGS__) == (off_t)-1){ \
      M_PRINTF ( MLOG_INFO, "lseek: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _read(retval, ...) \
do { \
    if ((retval = read (__VA_ARGS__)) == -1){ \
      M_PRINTF ( MLOG_INFO, "read: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _ftok(retval, ...) \
do { \
    if ((retval = ftok (__VA_ARGS__)) == (key_t)-1){ \
      M_PRINTF ( MLOG_INFO, "ftok: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _msgget(retval, ...) \
do { \
    if ((retval = msgget (__VA_ARGS__)) == -1){ \
      M_PRINTF ( MLOG_INFO, "msgget: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _getenv(retval, ...) \
do { \
    if ((retval = getenv (__VA_ARGS__)) == NULL){ \
      M_PRINTF ( MLOG_INFO, "getenv: DISPLAY environment variable is not set (tip:usually it looks like  :0.0) ,%s,%d\n", __FILE__, __LINE__ ); \
      return ; \
    } \
} while (0); \

#define _msgsnd(...) \
do { \
    if (msgsnd (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "msgsnd: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _remove(...) \
do { \
    if (remove (__VA_ARGS__) == -1){ \
      M_PRINTF ( MLOG_INFO, "remove: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _readlink(...) \
do { \
    if (readlink (__VA_ARGS__) == -1){ \
    M_PRINTF ( MLOG_INFO, "msgsnd: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _mmap(retval, ...) \
do { \
    if ((retval = mmap (__VA_ARGS__)) == MAP_FAILED){ \
    M_PRINTF ( MLOG_INFO, "mmap: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return ; \
    } \
} while (0); \

#define _close(...) \
do { \
    if (close (__VA_ARGS__) == -1){ \
    M_PRINTF ( MLOG_INFO, "close: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _munmap(...) \
do { \
    if (munmap (__VA_ARGS__) == -1){ \
    M_PRINTF ( MLOG_INFO, "munmap: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _pthread_create(...) \
do { \
    if (pthread_create (__VA_ARGS__) != 0){ \
    M_PRINTF ( MLOG_INFO, "pthread_create: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#define _msgctl(...) \
do { \
    if (msgctl (__VA_ARGS__) == -1){ \
    M_PRINTF ( MLOG_INFO, "msgctl: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ ); \
      return; \
    } \
} while (0); \

#endif // SYSCALL_WRAPPERS_H
