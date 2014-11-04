#include <stdarg.h> //for dynamic arguments
#include <stdio.h>
#include "conntrack.h"
#include "common/includes.h"
#include "common/defines.h"
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <pthread.h>
#include <sys/capability.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/msg.h>

extern pthread_mutex_t logstring_mutex;
extern char logstring[PATHSIZE];
extern int (*m_printf)(int loglevel, char *logstring);

FILE* __real_fopen (const char* filename, const char* mode);
DIR*  __real_opendir (const char *dirname);
int   __real_nfct_query(struct nfct_handle *h, const enum nf_conntrack_query query, const void *data);
int __real_nfct_callback_register(struct nfct_handle *h,
				  enum nf_conntrack_msg_type type,
				  int (*cb)(enum nf_conntrack_msg_type type,
					    struct nf_conntrack *ct,
					    void *data),
				  void *data);
int __real_fseek(FILE *stream, long offset, int whence);
int __real_fclose(FILE *stream);
int __real_fputs(const char* s, FILE* stream);
int __real_fputc(int c, FILE *stream);
char* __real_fgets(char* s, int n, FILE* stream);
int __real_access(const char *path, int amode);
int __real_stat(const char* path, struct stat* buf);
int __real_system(const char *command);
int __real_nfq_unbind_pf(struct nfq_handle *h, u_int16_t pf);
int __real_nfq_bind_pf(struct nfq_handle *h, u_int16_t pf);
int __real_nfq_set_mode(struct nfq_q_handle *qh, u_int8_t mode, unsigned int len);
int __real_nfq_set_queue_maxlen(struct nfq_q_handle *qh, u_int32_t queuelen);
struct nf_conntrack* __real_nfct_new(void);
struct nfct_handle* __real_nfct_open(u_int8_t, unsigned);
ssize_t __real_write(int fildes, const void *buf, size_t nbyte);
struct nfq_q_handle* __real_nfq_create_queue(struct nfq_handle *h,
						 u_int16_t num,
						 nfq_callback *cb,
						 void *data);
struct nfq_handle* __real_nfq_open(void);
int __real_fileno(FILE *stream);
int __real_pthread_mutex_lock(pthread_mutex_t *mutex);
int __real_pthread_mutex_unlock(pthread_mutex_t *mutex);
cap_t __real_cap_get_proc(void);
int __real_cap_set_proc(cap_t);
int __real_cap_clear(cap_t);
int __real_cap_free(void *);
int __real_cap_set_flag(cap_t, cap_flag_t, int, const cap_value_t *,
			    cap_flag_value_t);
int __real_nfq_close(struct nfq_handle *h);
void* __real_malloc(size_t size);
int __real_closedir(DIR *dirp);
int __real_pthread_cond_signal(pthread_cond_t *cond);
int __real_mkfifo(const char *path, mode_t mode);
int __real_open2(const char *path, int oflag, ... );
int __real_fsync(int fildes);
off_t __real_lseek(int fildes, off_t offset, int whence);
ssize_t __real_read(int fildes, void *buf, size_t nbyte);
key_t __real_ftok(const char *path, int id);
int __real_msgget(key_t key, int msgflg);
char* __real_getenv(const char *name);
int __real_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
int __real_remove(const char *path);
ssize_t __real_readlink(const char* path, char* buf,
       size_t bufsize);
void* __real_mmap(void *addr, size_t len, int prot, int flags,
       int fildes, off_t off);
int __real_close(int fildes);
int __real_munmap(void *addr, size_t len);
int __real_pthread_create(pthread_t* thread,
       const pthread_attr_t* attr,
       void *(*start_routine)(void*), void* arg);
int __real_msgctl(int msqid, int cmd, struct msqid_ds *buf);

FILE* __wrap_fopen (const char* filename, const char* mode) {
  FILE* retval = __real_fopen (filename, mode);
  if (retval == NULL){
	M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

DIR* __wrap_opendir(const char *dirname) {
  DIR* retval = __real_opendir (dirname);
  if (retval == NULL){
	M_PRINTF ( MLOG_INFO, "opendir: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_nfct_query(struct nfct_handle *h, const enum nf_conntrack_query query, const void *data){
  int retval = __real_nfct_query (h,query,data);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "nfct_query: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_nfct_callback_register(struct nfct_handle *h,
				  enum nf_conntrack_msg_type type,
				  int (*cb)(enum nf_conntrack_msg_type type,
					    struct nf_conntrack *ct,
					    void *data),
void *data) {
  int retval = __real_nfct_callback_register (h,type,cb,data);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "nfct_callback_register: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_fseek(FILE *stream, long offset, int whence){
  int retval = __real_fseek(stream,offset,whence);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "fseek: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_fclose(FILE *stream){
  int retval = __real_fclose(stream);
  if (retval == EOF){
    M_PRINTF ( MLOG_INFO, "fclose: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_fputs(const char* s, FILE* stream) {
  int retval = __real_fputs(s,stream);
  if (retval == EOF){
    M_PRINTF ( MLOG_INFO, "fputs: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_fputc(int c, FILE *stream) {
  int retval = __real_fputc(c,stream);
  if (retval == EOF){
    M_PRINTF ( MLOG_INFO, "fputc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

char* __wrap_fgets(char* s, int n, FILE* stream) {
  char* retval = __real_fgets(s,n,stream);
  if (retval == NULL){
    M_PRINTF ( MLOG_INFO, "fgets: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_access(const char *path, int amode){
  int retval = __real_access(path,amode);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "access: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_stat(const char* path, struct stat* buf){
  int retval = __real_stat(path,buf);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "stat: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_system(const char *command) {
  int retval = __real_system(command);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "system: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_nfq_unbind_pf(struct nfq_handle *h, u_int16_t pf) {
  int retval = __real_nfq_unbind_pf(h,pf);
  if (retval < 0){
    M_PRINTF ( MLOG_INFO, "nfq_unbind_pf: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_nfq_bind_pf(struct nfq_handle *h, u_int16_t pf){
  int retval = __real_nfq_bind_pf(h,pf);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "nfq_bind_pf: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_nfq_set_mode(struct nfq_q_handle *qh,
			  u_int8_t mode, unsigned int len) {
  int retval = __real_nfq_set_mode(qh,mode,len);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "nfq_set_mode: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_nfq_set_queue_maxlen(struct nfq_q_handle *qh,
			u_int32_t queuelen) {
  int retval = __real_nfq_set_queue_maxlen(qh,queuelen);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "nfq_set_queue_maxlen: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

struct nf_conntrack* __wrap_nfct_new(void) {
  struct nf_conntrack* retval = __real_nfct_new();
  if (retval == NULL){
    M_PRINTF ( MLOG_INFO, "nfct_new: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

struct nfct_handle* __wrap_nfct_open(u_int8_t a, unsigned b) {
  struct nfct_handle* retval = __real_nfct_open(a,b);
  if (retval == NULL){
    M_PRINTF ( MLOG_INFO, "nfct_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte) {
  int retval = __real_write(fildes,buf,nbyte);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "write: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

struct nfq_q_handle* __wrap_nfq_create_queue(struct nfq_handle *h,
						 u_int16_t num,
						 nfq_callback *cb,
						 void *data) {
  struct nfq_q_handle* retval = __real_nfq_create_queue(h,num,cb,data);
  if (retval == NULL){
    M_PRINTF ( MLOG_INFO, "nfq_create_queue: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

struct nfq_handle* __wrap_nfq_open(void) {
  struct nfq_handle* retval = __real_nfq_open();
  if (retval == NULL){
    M_PRINTF ( MLOG_INFO, "nfq_open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_fileno(FILE *stream) {
  int retval = __real_fileno(stream);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "fileno: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
  int retval = __real_pthread_mutex_lock(mutex);
  if (retval != 0){
    M_PRINTF ( MLOG_INFO, "pthread_mutex_lock: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
  int retval = __real_pthread_mutex_unlock(mutex);
  if (retval != 0){
    M_PRINTF ( MLOG_INFO, "pthread_mutex_unlock: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

cap_t __wrap_cap_get_proc(void) {
  cap_t retval = __real_cap_get_proc();
  if (retval == NULL){
    M_PRINTF ( MLOG_INFO, "cap_get_proc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_cap_set_proc(cap_t a) {
  int retval = __real_cap_set_proc(a);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "cap_set_proc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_cap_clear(cap_t a) {
  int retval = __real_cap_clear(a);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "cap_clear: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_cap_free(void* a) {
  int retval = __real_cap_free(a);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "cap_free: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_cap_set_flag(cap_t a, cap_flag_t b, int c, const cap_value_t* d,
			    cap_flag_value_t e) {
  int retval = __real_cap_set_flag(a,b,c,d,e);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "cap_set_flag: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_nfq_close(struct nfq_handle *h) {
  int retval = __real_nfq_close(h);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "nfq_close: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

void* __wrap_malloc(size_t size) {
  void* retval = __real_malloc(size);
  if (retval == NULL){
    M_PRINTF ( MLOG_INFO, "malloc: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_closedir(DIR *dirp) {
  int retval = __real_closedir(dirp);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "closedir: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_pthread_cond_signal(pthread_cond_t *cond) {
  int retval = __real_pthread_cond_signal(cond);
  if (retval != 0){
    M_PRINTF ( MLOG_INFO, "pthread_cond_signal: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_mkfifo(const char *path, mode_t mode) {
  int retval = __real_mkfifo(path,mode);
  if (retval != 0){
    M_PRINTF ( MLOG_INFO, "mkfifo: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

//MAybe we shouldn't wrap this function because __VA_ARGS__ can be used only with macros
//But va_list, va_start, va_end gave me lotf of headaches a while ago
int __wrap_open(const char *path, int oflag, ... ) {
  int retval = __real_open(path, oflag/*, __VA_ARGS__*/ );
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "open: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_fsync(int fildes) {
  int retval = __real_fsync(fildes);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "fsync: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

off_t __wrap_lseek(int fildes, off_t offset, int whence) {
  int retval = __real_lseek(fildes, offset, whence);
  if (retval == (off_t)-1){
    M_PRINTF ( MLOG_INFO, "lseek: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte) {
  int retval = __real_read(fildes, buf, nbyte);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "lseek: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

key_t __wrap_ftok(const char *path, int id) {
  int retval = __real_ftok(path, id);
  if (retval == (key_t)-1){
    M_PRINTF ( MLOG_INFO, "ftok: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_msgget(key_t key, int msgflg) {
  int retval = __real_msgget(key, msgflg);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "msgget: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

char* __wrap_getenv(const char *name) {
  char* retval = __real_getenv(name);
  if (retval == NULL){
     M_PRINTF ( MLOG_INFO, "getenv: DISPLAY environment variable is not set (tip:usually it looks like  :0.0) ,%s,%d\n", __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) {
  int retval = __real_msgsnd (msqid, msgp, msgsz, msgflg);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "msgsnd: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_remove(const char *path) {
  int retval = __real_remove (path);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "remove: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

ssize_t __wrap_readlink(const char* path, char* buf,
       size_t bufsize) {
  ssize_t retval = __real_readlink (path, buf, bufsize);
  if (retval == -1){
    //M_PRINTF ( MLOG_INFO, "readlink(%s): %s,%s,%d\n",  path, strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}


void* __wrap_mmap(void *addr, size_t len, int prot, int flags,
       int fildes, off_t off) {
  void* retval = __real_mmap (addr, len, prot, flags, fildes, off);
  if (retval == MAP_FAILED){
    M_PRINTF ( MLOG_INFO, "mmap: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_close(int fildes) {
  int retval = __real_close (fildes);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "close: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_munmap(void *addr, size_t len) {
  int retval = __real_munmap (addr, len);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "munmap: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_pthread_create(pthread_t* thread,
       const pthread_attr_t* attr,
       void *(*start_routine)(void*), void* arg) {
  int retval = __real_pthread_create (thread, attr, start_routine, arg);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "pthread_create: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}

int __wrap_msgctl(int msqid, int cmd, struct msqid_ds *buf) {
  int retval = __real_msgctl (msqid, cmd, buf);
  if (retval == -1){
    M_PRINTF ( MLOG_INFO, "msgctl: %s,%s,%d\n",  strerror ( errno ), __FILE__, __LINE__ );
  }
  return retval;
}
