#ifndef LPFW_H
#define LPFW_H

#include "common/defines.h"
#include "common/includes.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h> // for FILE*

extern char ownpath[PATHSIZE];
extern char owndir[PATHSIZE];

extern msg_struct msg_f2d,msg_d2fdel,msg_d2flist;
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
extern int (*m_printf)(const int loglevel, const char *logstring);

int dlist_add ( const char *path, const char *pid, const char *perms, const mbool current, const char *sha,
		const unsigned long long stime, const off_t size, const int nfmark, const unsigned char first_instance );
dlist * dlist_copy();
void dlist_del ( const char *path, const char *pid );

void child_close_nfqueue();
int sha512_stream(FILE *stream, void *resblock);
int global_rules_filter(const int m_direction, const int protocol, const int port, const int verdict);
void denied_traffic_add (const int direction, const int mark, const int bytes);
void capabilities_modify(const int capability, const int set, const int action);

int build_tcp_port_cache(long *socket_found, const int *port_to_find);
int build_tcp6_port_cache(long *socket_found, const int *port_to_find);
int build_udp_port_cache(long *socket_found, const int *port_to_find);
int build_udp6_port_cache(long *socket_found, const int *port_to_find);

int conntrack_delete_mark(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int traffic_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int conntrack_destroy_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
void * ct_dump_thread( void *ptr);
void * ct_destroy_hook_thread( void *ptr);
void* frontend_poll_thread ( void* ptr );
void* ct_delete_nfmark_thread ( void* ptr );

int setmark_out_tcp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int setmark_out_udp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int setmark_out_icmp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int setmark_in (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);

int fe_active_flag_get();
void fe_active_flag_set (const unsigned char boolean);

int m_printf_stdout ( const int loglevel, const char * logstring );
int m_printf_file ( const int loglevel, const char * logstring );
int m_printf_syslog (const int loglevel, const char * logstring);

unsigned long long starttimeGet ( const int mypid );
int socket_cache_in_search(const long *socket, char *path, char *pid, int *nfmark_to_set_in);
int socket_cache_out_search(const long *socket, char *path, char *pid, int *nfmark_to_set_out);
void* cache_build_thread ( void *ptr );
void* nfq_out_udp_thread ( void *ptr );
void* nfq_gid_thread ( void *ptr );
void* nfq_out_rest_thread ( void *ptr );
void* nfq_in_thread ( void *ptr );
void* rules_dump_thread ( void *ptr );
void* refresh_thread ( void* ptr );
void global_rule_add( const char *str_direction, char *str_ports);

void rules_load();
void rulesfileWrite();

int path_find_in_dlist ( int *nfmark_to_set, const char *path, const char *pid, unsigned long long *stime);
int socket_active_processes_search ( const long *mysocket, char *m_path, char *m_pid, int *nfmark_to_set);
int socket_procpidfd_search ( const long *mysocket, char *m_path, char *m_pid, unsigned long long *stime );
int icmp_check_only_one_inode ( long *socket );


int inkernel_check_udp(const int *port);
int inkernel_check_tcp(const int *port);
int inkernel_make_verdict(const char *ipaddr, int *nfmark);


int port2socket_udp ( int *portint, int *socketint );
int port2socket_tcp ( int *portint, int *socketint );

int packet_handle_tcp_in ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int packet_handle_tcp_out ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int packet_handle_udp_in ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int packet_handle_udp_out ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int packet_handle_icmp(int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);

long is_tcp_port_in_cache (const int *port);
long is_udp_port_in_cache (const int *port);
void print_traffic_log(const int proto, const int direction, const char *ip, const int srcport,
		       const int dstport, const char *path, const char *pid, const int verdict);

int  nfq_handle_gid ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );
int  nfq_handle_in ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );
int  nfq_handle_out_rest ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );
int  nfq_handle_out_udp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );
int  nfq_handle_out_tcp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );


void init_log();
void pidfile_check();
void SIGTERM_handler ( int signal );
int parse_command_line(int argc, char* argv[]);
void capabilities_setup();
void setgid_lpfwuser();
void setuid_root();
void setup_signal_handlers();
void save_own_path();
void init_iptables();
void init_nfq_handlers();
void init_dlist();
void open_proc_net_files();
void chown_and_setgid_frontend();
void  init_conntrack();
void child_close_nfqueue();





























































#endif // LPFW_H
