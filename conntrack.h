#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <pthread.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

//ct_delete_mark_thread uses waiting on condition
extern pthread_cond_t condvar;
extern pthread_mutex_t condvar_mutex;
extern char predicate;
extern int nfmark_to_delete_in, nfmark_to_delete_out;
extern struct nf_conntrack *ct_out_tcp, *ct_out_udp, *ct_out_icmp, *ct_in;
extern int nfmark_to_set_out_tcp, nfmark_to_set_out_udp,nfmark_to_set_out_icmp, nfmark_to_set_in;
extern struct nfct_handle *setmark_handle_out_tcp, *setmark_handle_in, *setmark_handle_out_udp, *setmark_handle_out_icmp;

//Register a callback to delete nfmark and wait on condition to be triggered.
void* ct_delete_mark_thread ( void* ptr );
//delete ct entry according to mark (e.g. when process exits and we don't want any of its established
//connections to linger in ct
int ct_delete_mark_cb (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data);

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


//modify traffic stats in ct_array for denied packets
void denied_traffic_add (const int direction, const int mark, const int bytes);




#endif // LPFW_H
