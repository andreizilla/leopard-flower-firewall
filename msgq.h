#ifndef MSGQ_H
#define MSGQ_H

int fe_ask_out ( char*, char*, unsigned long long* );
int fe_ask_in(char *path, char *pid, unsigned long long *stime, char *ipaddr, int sport, int dport);
int fe_list();
void init_msgq();
void* run_tests(void *);
int sha512_stream ( FILE *stream, void *resblock );

extern int awaiting_reply_from_fe;
extern int mqd_d2ftraffic;
extern struct msqid_ds *msgqid_d2ftraffic;

#endif // MSGQ_H
