#ifndef LPFW_H
#define LPFW_H

#include "common/defines.h"
#include "common/includes.h"

extern char ownpath[PATHSIZE];
extern char owndir[PATHSIZE];

//type has to be initialized to one, otherwise if it is 0 we'll get EINVAL on msgsnd
extern msg_struct msg_d2f;
extern msg_struct msg_f2d;
extern msg_struct msg_d2fdel;
extern msg_struct msg_d2flist;
extern msg_struct_creds msg_creds;

extern gid_t lpfwuser_gid;

extern char logstring[PATHSIZE];
extern struct arg_file *cli_path, *gui_path, *pygui_path;
//mutex to avoid fe_ask_* to send data simultaneously
extern pthread_mutex_t msgq_mutex, logstring_mutex;
//netfilter mark number for the packet (to be added to NF_MARK_BASE)
extern int nfmark_count;
//PID of currently active frontend
extern pid_t fe_pid;
extern int (*m_printf)(int loglevel, char *logstring);

int dlist_add ( const char *path, const char *pid, const char *perms, const mbool current, const char *sha,
		const unsigned long long stime, const off_t size, const int nfmark, const unsigned char first_instance );
unsigned long long starttimeGet(int mypid);
void fe_active_flag_set (int boolean);
void child_close_nfqueue();
int sha512_stream(FILE *stream, void *resblock);
dlist * dlist_copy();
void dlist_del ( char *path, char *pid );
void capabilities_modify(int capability, int set, int action);


#endif // LPFW_H
