#ifndef MSGQ_H
#define MSGQ_H

#include <stdio.h>

int fe_ask_out ( char*, char*, unsigned long long* , char*, int*, int*);
int fe_ask_in(const char *path, const char *pid, const unsigned long long *stime, const char *ipaddr,
	      const int *sport, const int *dport);
int fe_list();
void init_msgq();
void* unit_test_thread(void *);
int sha512_stream ( FILE *stream, void *resblock );

extern int awaiting_reply_from_fe;
extern int mqd_d2ftraffic;
extern struct msqid_ds *msgqid_d2ftraffic;

#endif // MSGQ_H
