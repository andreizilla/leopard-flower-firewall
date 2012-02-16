#ifndef LPFW_H
#define LPFW_H

#include "common/defines.h"
#include "common/includes.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h> // for FILE*

#if 0
//OBSOLETE for now since frontend starts standalone
//Full path to lpfw executable
extern char ownpath[PATHSIZE];
//Full path to lpfw executable's folder
extern char owndir[PATHSIZE];
#endif

//PID of currently active frontend
extern pid_t fe_pid;
//Pointer to function which does the logging
extern int (*m_printf)(const int loglevel, const char *logstring);
//get sha512 digest in resblock
extern int sha512_stream(FILE *stream, void *resblock);
//enables other files to use the logging facility
extern pthread_mutex_t logstring_mutex;
extern char logstring[PATHSIZE];



//add a new rule and if nfmark is not specified, return a new nfmark for the newly added rule
int ruleslist_add ( const char *path, const char *pid, const char *perms, const mbool current, const char *sha,
		const unsigned long long stime, const off_t size, const int nfmark, const unsigned char first_instance );

//make a copy of ruleslist and return a pointer to it
ruleslist * ruleslist_copy();

//remove rule from ruleslist
void ruleslist_del ( const char *path, const char *pid );

//builds correlation tables between ports and sockets for variour /proc/net/* files and at the same time
//checks if port_to_find is in the table. Returns socket corresponding to port_to_find or -1
//if port_to_find was not found
int build_tcp_port_and_socket_cache(long *socket_found, const int *port_to_find);
int build_tcp6_port_and_socket_cache(long *socket_found, const int *port_to_find);
int build_udp_port_and_socket_cache(long *socket_found, const int *port_to_find);
int build_udp6_port_and_socket_cache(long *socket_found, const int *port_to_find);
//returns socket corresponding to port or -1 if not found
long is_tcp_port_in_cache (const int *port);
long is_udp_port_in_cache (const int *port);

//print logstring to the preffered logging facility. A pointer to one of these functions is assigned
//to m_printf
int m_printf_stdout ( const int loglevel, const char * logstring );
int m_printf_file ( const int loglevel, const char * logstring );
int m_printf_syslog (const int loglevel, const char * logstring);

//find socket in pid_and_socket cache of active rules only and return path,pid,nfmark if found
int search_pid_and_socket_cache_in(const long *socket, char *path, char *pid, int *nfmark_to_set_in);
int search_pid_and_socket_cache_out(const long *socket, char *path, char *pid, int *nfmark_to_set_out);
//build a correlation of pid to socket of only the active rules, excluding inkernel rules
void* build_pid_and_socket_cache ( void *ptr );

//thread-safe getter and setter for fe_active_flag
int fe_active_flag_get();
void fe_active_flag_set (const unsigned char boolean);

//threads which receive packets from NFQUEUE and call handlers on those pakets
//NB nfq_out_tcp loop is at the end of main()
void* nfq_out_udp_thread ( void *ptr );
void* nfq_out_rest_thread ( void *ptr ); //all the rest, i.e. non-tcp & non-udp
void* nfq_in_thread ( void *ptr );

//handlers for NFQUEUE traffic
int  nfq_handle_in ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );
int  nfq_handle_out_rest ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );
int  nfq_handle_out_udp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );
int  nfq_handle_out_tcp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );

//EXPERIMENTAL. Like the above but uses the -m owner --gid-owner workaround to receive packets only from that gid
void* nfq_gid_thread ( void *ptr );
int nfq_handle_gid ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata );

//find the process which owns the socket and return nfmark,path,pid,stime, otherwise SOCKET_NOT_FOUND_IN_PROCPIDFD
int socket_handle_tcp_in ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int socket_handle_tcp_out ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int socket_handle_udp_in ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int socket_handle_udp_out ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);
int socket_handle_icmp(int *nfmark_to_set, char *path, char *pid, unsigned long long *stime);

//----CONNTRACK ROUTINES

//Register a callback to delete nfmark and wait on condition to be triggered.
void* ct_delete_mark_thread ( void* ptr );
//delete ct entry according to mark (e.g. when process exits and we don't want any of its established
//connections to linger in ct
int ct_delete_mark_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);

//dump all ct entries every second, extract the traffic statistics and send it to frontend
void * ct_dump_thread( void *ptr);
//callback gets called on every packet that is dumped from ct. It build ct_array which is later
//exported to frontend
int ct_dump_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);

//Register a callback that gets triggered whenever conntrack tries to destroy a connection
void * ct_destroy_thread( void *ptr);
//callback gets called when conntrack deletes a ct entry internally (e.g. when TCP connection closes)
//we want the deleted connections traffic statistics
int ct_destroy_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);

//sets the same mark on a process's connections in conntrack. This way we always know which conntrack
//entries belong to which process and we can collect traffic statistics
int setmark_out_tcp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int setmark_out_udp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int setmark_out_icmp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);
int setmark_in (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);

//---END CONNTRACK ROUTINES

//determine if port belongs to a in-kernel process. Kernel modules can open sockets but the have no PID
int inkernel_check_udp(const int *port);
int inkernel_check_tcp(const int *port);
//if in-kernel socket found, see if there is a rule for it already
int inkernel_get_verdict(const char *ipaddr, int *nfmark);

//check if packet is subject to some global rule which will override any other rule
//at this stage global rules can only allow/deny ports and port ranges (not IPs or regex domain names)
int global_rules_filter(const int m_direction, const int protocol, const int port, const int verdict);

//modify traffic stats in ct_array for denied packets
void denied_traffic_add (const int direction, const int mark, const int bytes);

//SET/CLEAR capability of a set
void capabilities_modify(const int capability, const int set, const int action);

//Get pid's starttime
unsigned long long starttimeGet ( const int pid );

//check if frontend is still running
void* frontend_poll_thread ( void* ptr );

//check which active rules are still running and remove them if they are not running anymore
void* refresh_thread ( void* ptr );

//process rules.conf
void global_rule_add( const char *str_direction, char *str_ports);
void rules_load();
void rulesfileWrite();

//chack if path+pid combo is already in ruleslist
int path_find_in_ruleslist ( int *nfmark_to_set, const char *path, const char *pid, unsigned long long *stime);

//search socket in /proc/<PID>/fd of the active rules
int socket_active_processes_search ( const long *mysocket, char *m_path, char *m_pid, int *nfmark_to_set);

//search socket in the whole of /proc/<PID>s
int socket_procpidfd_search ( const long *mysocket, char *m_path, char *m_pid, unsigned long long *stime );

//if there's >1 entry in /proc/net/raw for icmp, it's impossible to tell which process is sending the packet
int icmp_check_only_one_socket ( long *socket );

//contruct a string to print to logging facility
void print_traffic_log(const int proto, const int direction, const char *ip, const int srcport,
		       const int dstport, const char *path, const char *pid, const int verdict);

//setup logging facility
void init_log();

void pidfile_check();
void setup_signal_handlers();
void SIGTERM_handler ( int signal );
int parse_command_line(int argc, char* argv[]);

// chack that we have the needed capabilities and if we do, then drop all the other capabilities
void capabilities_setup();

// Create group lpfwuser. Backend and frontend both should belong to this group to communicate over IPC
void setgid_lpfwuser();

// uid == 0. It is not full-fledged root because it has stripped capabilities
void setuid_root();
void init_iptables();
void init_nfq_handlers();
void init_ruleslist();
void open_proc_net_files();
void chown_and_setgid_frontend();
void init_conntrack();

// USED FOR TESTING AND DEBUGGING
int port2socket_udp ( int *portint, int *socketint );
int port2socket_tcp ( int *portint, int *socketint );
//dump all rules to a files
void* rules_dump_thread ( void *ptr );

#endif // LPFW_H
