#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h> //required for netfilter.h
#include <sys/time.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/mman.h> //for mmap
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h> //for malloc
#include <ctype.h> // for toupper
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <grp.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h> //for ntohl()
#include <linux/netfilter.h> //for NF_ACCEPT, NF_DROP etc
#include <assert.h>

#include <glib.h>

#include "common/includes.h"
#include "common/defines.h"
#include "argtable/argtable2.h"
#include "version.h" //for version string during packaging
#include "main.h"
#include "msgq.h"
#include "conntrack.h"
#include "test.h"

GKeyFile* addressRules = NULL;

void init_address_rules() {
	M_PRINTF(MLOG_INFO, "Loading address rules...\n");

	addressRules = g_key_file_new ();
	g_key_file_load_from_file(addressRules, "/etc/lpfw.ini", G_KEY_FILE_NONE, NULL);
}

//should be available globally to call nfq_close from sigterm handler
struct nfq_handle *globalh_out_tcp, *globalh_out_udp, *globalh_out_rest, *globalh_in, *globalh_gid;

//command line arguments available globally
struct arg_str *logging_facility;
struct arg_file *rules_file, *pid_file, *log_file, *allow_rule;
struct arg_int *log_info, *log_traffic, *log_debug;
struct arg_lit *test;
//Paths of various frontends kept track of in order to chown&chmod them
struct arg_file *cli_path, *gui_path, *pygui_path;

FILE *fileloginfo_stream, *filelogtraffic_stream, *filelogdebug_stream;

//first element of dlist is an empty one,serves as reference to determine the start of dlist
ruleslist *first_rule;

global_rule_t *first_global_rule = NULL;

pid_t fe_pid;

//pointer to the actual logging function
int ( *m_printf ) ( const int loglevel, const char *logstring );

//mutex to protect ruleslist AND nfmark_count
pthread_mutex_t dlist_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_t refresh_thr, nfq_in_thr, cache_build_thr, nfq_out_udp_thr, nfq_out_rest_thr, ct_dump_thr,
          ct_destroy_hook_thr, read_stats_thread, ct_delete_nfmark_thr, frontend_poll_thr, nfq_gid_thr,
          unittest_thr, rules_dump_thr;

//flag which shows whether frontend is running
int fe_active_flag = 0;
pthread_mutex_t fe_active_flag_mutex = PTHREAD_MUTEX_INITIALIZER;
//fe_was_busy_* is a flag to know whether frontend was processing another "add" request from lpfw
//Normally, if path is not found in ruleslist, we send a request to frontend
//But in case it was busy when we started packet_handle_*, we assume FRONTEND_BUSY
//This prevents possible duplicate entries in ruleslist
int fe_was_busy_in, fe_was_busy_out;

//mutexed string which threads use for logging
pthread_mutex_t logstring_mutex = PTHREAD_MUTEX_INITIALIZER;
char logstring[PATHSIZE];

FILE *tcpinfo, *tcp6info, *udpinfo, *udp6info;
int tcpinfo_fd, tcp6info_fd, udpinfo_fd, udp6info_fd, procnetrawfd;

int nfqfd_input, nfqfd_tcp, nfqfd_udp, nfqfd_rest, nfqfd_gid;

//track time when last packet was seen to put to sleep some threads when there is no traffic
struct timeval lastpacket = {0};
pthread_mutex_t lastpacket_mutex = PTHREAD_MUTEX_INITIALIZER;

//netfilter mark number for the packet (to be summed with NF_MARK_BASE)
int nfmark_count = 0;
//for debug purposed - how many times read() was called
int tcp_stats, udp_stats;
//cache that holds correlation of ports<-->sockets from various /proc/net/* files
int tcp_port_and_socket_cache[MEMBUF_SIZE], udp_port_and_socket_cache[MEMBUF_SIZE],
    tcp6_port_and_socket_cache[MEMBUF_SIZE], udp6_port_and_socket_cache[MEMBUF_SIZE];

//array of global ports rules
ports_list_t * ports_list_array[8] = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};

int global_rules_filter(const int m_direction, const int protocol, const int port, const int verdict)
{
    int direction;
    ports_list_t *ports_list;

    if (verdict > GLOBAL_RULES_VERDICT_MAX) return verdict;
    if (m_direction == DIRECTION_OUT)
    {
        if (protocol == PROTO_TCP) direction = TCP_OUT_ALLOW;
        else if (protocol == PROTO_UDP) direction =  UDP_OUT_ALLOW;
    }
    else if (m_direction == DIRECTION_IN)
    {
        if (protocol == PROTO_TCP) direction = TCP_IN_ALLOW;
        else if (protocol == PROTO_UDP) direction =  UDP_IN_ALLOW;
    }
    ports_list = ports_list_array[direction];
    while (ports_list != NULL)
    {
        if (ports_list->is_range)
        {
            if ((ports_list->min_port <= port)&&(ports_list->max_port >= port)) {
                return GLOBAL_RULE_ALLOW;
            }
        }
        else
        {
            if (ports_list->min_port == port) {
                return GLOBAL_RULE_ALLOW;
            }
        }
        ports_list = ports_list->next;
    }

    ports_list = ports_list_array[direction+1];
    while (ports_list != NULL)
    {
        if (ports_list->is_range)
        {
            if ((ports_list->min_port <= port)&&(ports_list->max_port >= port)) {
                return GLOBAL_RULE_DENY;
            }
        }
        else
        {
            if (ports_list->min_port == port) {
                return GLOBAL_RULE_DENY;
            }
        }
        ports_list = ports_list->next;
    }
    return verdict;
}

void fe_active_flag_set ( const unsigned char boolean )
{
    pthread_mutex_lock ( &fe_active_flag_mutex );
    fe_active_flag = boolean;
    pthread_mutex_unlock ( &fe_active_flag_mutex );
}

void capabilities_modify(const int capability, const int set, const int action)
{
    cap_t cap_current;
    const cap_value_t caps_list[] = {capability};

    cap_current = cap_get_proc();
    cap_set_flag(cap_current,  set, 1, caps_list, action);
    cap_set_proc(cap_current);
}

int build_tcp_port_and_socket_cache(long *socket_found, const int *port_to_find)
{
    char tcp_smallbuf[4096];
    int bytesread_tcp;
    char newline[2] = {'\n','\0'};
    int port,found_flag, i;
    long socket;
    char *token, *lasts;

    i = 0;
    memset(tcp_smallbuf,0, 4096);
    fseek(tcpinfo,0,SEEK_SET);
    found_flag = 0;
    while ((bytesread_tcp = read(tcpinfo_fd, tcp_smallbuf, 4060)) > 0)
    {
        if (bytesread_tcp == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(tcp_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*8s:%4X %*s %*s %*s %*s %*s %*s %*s %ld \n", &port, &socket);
            tcp_port_and_socket_cache[i*2] = (long)port;
            tcp_port_and_socket_cache[i*2+1] = socket;
            if (*port_to_find == port)
            {
                i++;
                *socket_found = socket;
				found_flag = 1;
                continue;
            }
            //else
            i++;
        }
    }
    tcp_port_and_socket_cache[i*2] = (long)MAGIC_NO;
    if (!found_flag) {
        return -1;
    }
    else {
        return 1;
    }
}

int build_tcp6_port_and_socket_cache(long *socket_found, const int *port_to_find)
{
    char tcp6_smallbuf[4096];
    int bytesread_tcp6;
    char newline[2] = {'\n','\0'};
    int port, found_flag, i;
    long socket;
    char *token, *lasts;

    i=0;
    memset(tcp6_smallbuf,0, 4096);
    fseek(tcp6info,0,SEEK_SET);
    found_flag = 0;
    while ((bytesread_tcp6 = read(tcp6info_fd, tcp6_smallbuf, 4060)) > 0)
    {
        if (bytesread_tcp6 == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(tcp6_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*32s:%4X %*s %*s %*s %*s %*s %*s %*s %ld \n", &port, &socket);
            tcp6_port_and_socket_cache[i*2] = (long)port;
            tcp6_port_and_socket_cache[i*2+1] = socket;
            if (*port_to_find == port)
            {
                i++;
                *socket_found = socket;
				found_flag = 1;
                continue;
            }
            //else
            i++;
        }
    }
    tcp6_port_and_socket_cache[i*2] = (long)MAGIC_NO;
    if (!found_flag) {
        return -1;
    }
    else {
        return 1;
    }
}

int build_udp_port_and_socket_cache(long *socket_found, const int *port_to_find)
{
    char udp_smallbuf[4096];
    int bytesread_udp;
    char newline[2] = {'\n','\0'};
    int port, found_flag, i;
    long socket;
    char *token, *lasts;

    i = 0;
    memset(udp_smallbuf,0, 4096);
    fseek(udpinfo,0,SEEK_SET);
    found_flag = 0;
    while ((bytesread_udp = read(udpinfo_fd, udp_smallbuf, 4060)) > 0)
    {
        if (bytesread_udp == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(udp_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*8s:%4X %*s %*s %*s %*s %*s %*s %*s %ld \n", &port, &socket);
            udp_port_and_socket_cache[i*2] = (long)port;
            udp_port_and_socket_cache[i*2+1] = socket;
            if (*port_to_find == port)
            {
                i++;
                *socket_found = socket;
				found_flag = 1;
                continue;
            }
            //else
            i++;
        }
    }
    udp_port_and_socket_cache[i*2] = MAGIC_NO;
    if (!found_flag) {
        return -1;
    }
    else {
        return 1;
    }
}

int build_udp6_port_and_socket_cache(long *socket_found, const int *port_to_find)
{
    char udp6_smallbuf[4096];
    int bytesread_udp6;
    char newline[2] = {'\n','\0'};
    int port, found_flag, i;
    long socket;
    char *token, *lasts;

    i = 0;
    memset(udp6_smallbuf,0, 4096);
    fseek(udp6info,0,SEEK_SET);
    found_flag = 0;
    while ((bytesread_udp6 = read(udp6info_fd, udp6_smallbuf, 4060)) > 0)
    {
        if (bytesread_udp6 == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(udp6_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*32s:%4X %*s %*s %*s %*s %*s %*s %*s %ld \n", &port, &socket);
            udp6_port_and_socket_cache[i*2] = (long)port;
            udp6_port_and_socket_cache[i*2+1] = socket;
            if (*port_to_find == port)
            {
                i++;
                *socket_found = socket;
				found_flag = 1;
                continue;
            }
            //else
            i++;
        }
    }
    udp6_port_and_socket_cache[i*2] = (long)MAGIC_NO;
    if (!found_flag) {
        return -1;
    }
    else {
        return 1;
    }
}

//For debug purposes only - measure read()s per second on /proc/net* files
void * readstatsthread( void *ptr)
{
    static int old_tcp_stats;
    static int old_udp_stats;

    old_tcp_stats = 0;
    old_udp_stats = 0;
    int new_tcp_stats, new_udp_stats;

    while(1)
    {
        sleep(1);
        new_tcp_stats = tcp_stats - old_tcp_stats;
        new_udp_stats = udp_stats - old_udp_stats;
        printf (" %d %d \n", new_tcp_stats, new_udp_stats);
        old_tcp_stats = tcp_stats;
        old_udp_stats = udp_stats;
    }
}

void* frontend_poll_thread ( void* ptr )
{
    capabilities_modify( CAP_KILL, CAP_EFFECTIVE, CAP_SET);
    while(1)
    {
        sleep(2);
        if (!fe_active_flag_get()) continue;
        if (kill(fe_pid,0) != 0)
        {
            M_PRINTF (MLOG_DEBUG, "kill: pid== %d %s,%s,%d\n", fe_pid, strerror ( errno ), __FILE__, __LINE__ );
            fe_active_flag_set(FALSE);
            awaiting_reply_from_fe = FALSE;
        }
    }
}

void child_close_nfqueue()
{
    if (nfq_close( globalh_out_tcp ))
    {
        M_PRINTF ( MLOG_INFO,"error in nfq_close\n" );
    }
    else
        M_PRINTF ( MLOG_DEBUG, "Done closing nfqueue\n" );
    if (nfq_close( globalh_out_udp ))
    {
        M_PRINTF ( MLOG_INFO,"error in nfq_close\n" );
    }
    else
        M_PRINTF ( MLOG_DEBUG, "Done closing nfqueue\n" );
    return;
}

int fe_active_flag_get()
{
    int temp;
    pthread_mutex_lock ( &fe_active_flag_mutex );
    temp = fe_active_flag;
    pthread_mutex_unlock ( &fe_active_flag_mutex );
    return temp;
}

int m_printf_stdout ( const int loglevel, const char * logstring )
{
    switch ( loglevel )
    {
    case MLOG_INFO:
        // check if INFO logging enabled
        if ( !* ( log_info->ival ) ) return 0;
        printf ( "%s", logstring );
        return 0;
    case MLOG_TRAFFIC:
        if ( !* ( log_traffic->ival ) ) return 0;
        printf ( "%s", logstring );
        return 0;
    case MLOG_DEBUG:
        if ( !* ( log_debug->ival ) ) return 0;
        printf ( "%s", logstring );
        return 0;
    case MLOG_DEBUG2:
#ifdef DEBUG2
        if ( !* ( log_debug->ival ) ) return 0;
        printf ( "%s", logstring );
#endif
        return 0;
    case MLOG_DEBUG3:
#ifdef DEBUG3
        if ( !* ( log_debug->ival ) ) return 0;
        printf ( "%s", logstring );
#endif
        return 0;
    case MLOG_ALERT: //Alerts get logged unconditionally to all log channels
        printf ( "ALERT: " );
        printf ( "%s", logstring );
        return 0;
    }
}

//technically vfprintf followed by fsync should be enough, but for some reason on my system it can take more than 1 minute before data gets actually written to disk. So until the mystery of such a huge delay is solved, we use write() so data gets written to dist immediately
int m_printf_file ( const int loglevel, const char * logstring )
{
    switch ( loglevel )
    {
    case MLOG_INFO:
        // check if INFO logging enabled
        if ( !* ( log_info->ival ) ) return 0;
        write ( fileno ( fileloginfo_stream ), logstring, strlen ( logstring ) );
        return 0;
    case MLOG_TRAFFIC:
        if ( !* ( log_traffic->ival ) ) return 0;
        write ( fileno ( filelogtraffic_stream ), logstring, strlen ( logstring ) );
        return 0;
    case MLOG_DEBUG:
        if ( !* ( log_debug->ival ) ) return 0;
        write ( fileno ( filelogdebug_stream ), logstring, strlen ( logstring ) );
        return 0;
    case MLOG_ALERT: //Alerts get logged unconditionally to all log channels
        write ( fileno ( filelogdebug_stream ), "ALERT: ", strlen ( logstring ) );
        return 0;
    }
}

#ifndef WITHOUT_SYSLOG
int m_printf_syslog (const int loglevel, const char * logstring)
{
    switch ( loglevel )
    {
    case MLOG_INFO:
        // check if INFO logging enabled
        if ( !* ( log_info->ival ) ) return 0;
        syslog ( LOG_INFO, "%s", logstring );
        return 0;
    case MLOG_TRAFFIC:
        if ( !* ( log_traffic->ival ) ) return 0;
        syslog ( LOG_INFO, "%s", logstring );
        return 0;
    case MLOG_DEBUG:
        if ( !* ( log_debug->ival ) ) return 0;
        syslog ( LOG_INFO, "%s", logstring );
        return 0;
    case MLOG_ALERT: //Alerts get logget unconditionally to all log channels
        syslog ( LOG_INFO, "ALERT: " );
        syslog ( LOG_INFO, "%s", logstring );
        return 0;
    }
}
#endif

unsigned long long starttimeGet ( const int mypid )
{
    char pidstring[8];
    char path[32] = "/proc/";
    sprintf ( pidstring, "%d", mypid );
    strcat ( path, pidstring );
    strcat ( path, "/stat" );

    unsigned long long starttime;
    FILE *stream;

    stream = fopen (path, "r" );
    fscanf ( stream, "%*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %llu",
             &starttime );
    fclose ( stream );
    return starttime;
}

ruleslist * ruleslist_copy()
{
    ruleslist *copy_rule;
    pthread_mutex_lock ( &dlist_mutex );
    copy_rule = malloc ((sizeof(ruleslist))*first_rule->rules_number );

    copy_rule[0].rules_number = first_rule->rules_number;
    ruleslist *rule = first_rule->next;
    int i = 1;
    for (i; i < first_rule->rules_number; i++)
    {
        strncpy ( copy_rule[i].path, rule->path, PATHSIZE );
        strncpy ( copy_rule[i].perms, rule->perms, PERMSLENGTH );
        strncpy ( copy_rule[i].pid, rule->pid, PIDLENGTH );
        copy_rule[i].is_active = rule->is_active;
        copy_rule[i].nfmark_out = rule->nfmark_out;
        rule = rule->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );

    return copy_rule;
}

int ruleslist_add ( const char *path, const char *pid, const char *perms, const mbool active, const char *sha,
                    const unsigned long long stime, const off_t size, const int nfmark, const unsigned char first_instance)
{
    int retnfmark;
    pthread_mutex_lock ( &dlist_mutex );
    ruleslist *rule = first_rule;

    if (!strcmp(path, KERNEL_PROCESS))  //make sure it is not a duplicate KERNEL_PROCESS
    {
        while ( rule->next != NULL )
        {
            rule = rule->next;
            if (strcmp(rule->path, KERNEL_PROCESS)) continue;
            if (!strcmp(rule->pid, pid))  //same IP, quit
            {
                pthread_mutex_unlock ( &dlist_mutex );
                return;
            }
        }
    }
    else //make sure it's not a duplicate of a regular (i.e. non-kernel) rule
    {
        rule = first_rule;
        while ( rule->next != NULL )
        {
            rule = rule->next;
            if ((!strcmp(rule->path, path)) && (!strcmp(rule->pid, pid)))
            {
                pthread_mutex_unlock ( &dlist_mutex );
                return;
            }
        }
    }

    rule = first_rule;
    //find the last element in dlist
    while ( rule->next != NULL )
    {
        rule = rule->next;
    }
    //last element's .next should point now to our newly created one
    rule->next = malloc (sizeof ( ruleslist ) );
    // new element's prev field should point to the former last element...
    rule->next->prev = rule;
    // point temp to the newly added element...
    rule = rule->next;
    //initialize fields
    rule->next = NULL;
    strncpy ( rule->path, path, PATHSIZE);
    strncpy ( rule->pid, pid, PIDLENGTH );
    strncpy ( rule->perms, perms, PERMSLENGTH );
    rule->is_active = active;
    rule->stime = stime;
    assert(sha != NULL);
    memcpy ( rule->sha, sha, DIGEST_SIZE );
    rule->exesize = size;
    if (nfmark == 0)
    {
        rule->nfmark_in = NFMARKIN_BASE + nfmark_count;
        retnfmark = rule->nfmark_out = NFMARKOUT_BASE +  nfmark_count;
        nfmark_count++;
    }
    else // nfmark > 0 => assign parent's nfmark
    {
        //either nfmark is for in or out traffic
        if (nfmark >= NFMARKIN_BASE)
        {
            rule->nfmark_in = nfmark;
            retnfmark = rule->nfmark_out = nfmark - NFMARK_DELTA;
        }
        else
        {
            retnfmark = rule->nfmark_out = nfmark;
            rule->nfmark_in = nfmark + NFMARK_DELTA;
        }
        nfmark_count++;
    }
    rule->first_instance = first_instance;
    if (rule->is_active && strcmp(rule->path, KERNEL_PROCESS))
    {
        strcpy(rule->pidfdpath,"/proc/");
        strcat(rule->pidfdpath, rule->pid);
        strcat(rule->pidfdpath, "/fd/");
        rule->dirstream = opendir (rule->pidfdpath );
    }

    //add to cache regardless if pid is active
    //TODO we only need cache for active rules - should socket_cache be allocated/removed dynamically?
//    if (current){
//	pthread_mutex_lock(&cache_mutex);
//	cache_item *cache_temp = first_cache;
//	while (cache_temp->next != NULL){
//	    cache_temp =cache_temp->next;
//	}
//	if ((cache_temp->next = malloc (sizeof (cache_item))) == NULL){perror("malloc");}
//	cache_temp->next->prev = cache_temp;
//	//make cache temp point to the newly created baby
//	cache_temp = cache_temp->next;
//	strcpy(cache_temp->path, temp->path);
//	strcpy(cache_temp->pid, temp->pid);
//	cache_temp->sockets[0][0] = MAGIC_NO;
//	pthread_mutex_unlock(&cache_mutex);
//    }
    if ((rule->sockets_cache = (long*)malloc(sizeof(long)*MAX_CACHE)) == NULL)
    {
        perror("malloc");
    }
    *rule->sockets_cache = MAGIC_NO;

    first_rule->rules_number = first_rule->rules_number + 1;
    pthread_mutex_unlock ( &dlist_mutex );
    return retnfmark;
}

void ruleslist_del ( const char *path, const char *pid )
{
    mbool was_active;
    pthread_mutex_lock ( &dlist_mutex );
    ruleslist *temp = first_rule->next;
    while ( temp != NULL )
    {
        if ( !strcmp ( temp->path, path ) && !strcmp ( temp->pid, pid ) )
        {
            //free cache entry first
            free(temp->sockets_cache);
            //free dirstream
            closedir (temp->dirstream);
            //remove the item
            temp->prev->next = temp->next;
            if ( temp->next != NULL )
            {
                temp->next->prev = temp->prev;
            }
            nfmark_to_delete_in = temp->nfmark_in;
            nfmark_to_delete_out = temp->nfmark_out;
            was_active = temp->is_active;
            free ( temp );
            first_rule->rules_number--;

            //remove tracking for this app's active connection only if this app was active
            if (was_active)
            {
                pthread_mutex_lock(&condvar_mutex);
                predicate = TRUE;
                pthread_mutex_unlock(&condvar_mutex);
                pthread_cond_signal(&condvar);
            }
            pthread_mutex_unlock ( &dlist_mutex );
            if (fe_active_flag_get())
            {
                fe_list();
            }
            return;
        }
        temp = temp->next;
    }
    M_PRINTF ( MLOG_INFO, "%s with PID %s was not found in dlist\n", path, pid );
    pthread_mutex_unlock ( &dlist_mutex );
}

int search_pid_and_socket_cache_in(const long *socket, char *path, char *pid, int *nfmark_to_set_in)
{
    int i;
    int retval;
    ruleslist *temp;
    pthread_mutex_lock(&dlist_mutex);
    temp = first_rule;
    while (temp->next != NULL)
    {
        temp = temp->next;
        if(!temp->is_active) continue;
        i = 0;
        while (temp->sockets_cache[i] != (long)MAGIC_NO)
        {
            if (i >= MAX_CACHE-1) break;
            if (temp->sockets_cache[i] == *socket)  //found match
            {
                if (!strcmp(temp->perms, ALLOW_ONCE) || !strcmp(temp->perms, ALLOW_ALWAYS)) retval = CACHE_TRIGGERED_ALLOW;
                else retval = CACHE_TRIGGERED_DENY;
                strncpy(path, temp->path, PATHSIZE);
                strncpy(pid, temp->pid, PIDLENGTH);
                if (temp->stime != starttimeGet(atoi (temp->pid))) {
                    return SPOOFED_PID;
                }
                *nfmark_to_set_in = temp->nfmark_out;
                pthread_mutex_unlock(&dlist_mutex);
                return retval;
            }
            i++;
        }
    }
    pthread_mutex_unlock(&dlist_mutex);
    return SOCKETS_CACHE_NOT_FOUND;
}

int search_pid_and_socket_cache_out(const long *socket, char *path, char *pid, int *nfmark_to_set_out)
{
    int i;
    int retval;
    ruleslist *temp;
    pthread_mutex_lock(&dlist_mutex);
    temp = first_rule;
    while (temp->next != NULL)
    {
        temp = temp->next;
        if(!temp->is_active) continue;
        i = 0;
        while (temp->sockets_cache[i] != (long)MAGIC_NO)
        {
            if (i >= MAX_CACHE-1) break;
            if (temp->sockets_cache[i] == *socket)  //found match
            {
                if (!strcmp(temp->perms, ALLOW_ONCE) || !strcmp(temp->perms, ALLOW_ALWAYS)) retval = CACHE_TRIGGERED_ALLOW;
                else {
                    retval = CACHE_TRIGGERED_DENY;
                }
                strncpy(path, temp->path, PATHSIZE);
                strncpy(pid, temp->pid, PIDLENGTH);
                if (temp->stime != starttimeGet(atoi (temp->pid))) {
                    return SPOOFED_PID;
                }
                *nfmark_to_set_out = temp->nfmark_out;
                pthread_mutex_unlock(&dlist_mutex);
                return retval;
            }
            i++;
        }
    }
    pthread_mutex_unlock(&dlist_mutex);
    return SOCKETS_CACHE_NOT_FOUND;
}

void* build_pid_and_socket_cache ( void *ptr )
{
    DIR *mdir;
    struct dirent *m_dirent;
    int proc_pid_fd_pathlen;
    char proc_pid_fd_path[32], proc_pid_exe[32];
    struct timespec refresh_timer,dummy;
    refresh_timer.tv_sec=0;
    refresh_timer.tv_nsec=1000000000/4;
    ruleslist *rule;
    struct timeval time;
    int i, delta;

    while(1)
    {
        nanosleep(&refresh_timer, &dummy);

        gettimeofday(&time, NULL);
        pthread_mutex_lock(&lastpacket_mutex);
        delta = time.tv_sec - lastpacket.tv_sec;
        pthread_mutex_unlock(&lastpacket_mutex);
        if (delta > 1)
        {
            continue;
        }
        pthread_mutex_lock(&dlist_mutex);
        rule = first_rule;
        while (rule->next != NULL)
        {
            rule = rule->next;
            if (!rule->is_active || !strcmp(rule->path, KERNEL_PROCESS)) continue;
            proc_pid_fd_pathlen = strlen(rule->pidfdpath);
            strncpy(proc_pid_fd_path, rule->pidfdpath, sizeof(proc_pid_fd_path));
            rewinddir(rule->dirstream);
            i = 0;
            errno=0;
            while (m_dirent = readdir ( rule->dirstream ))
            {
                proc_pid_fd_path[proc_pid_fd_pathlen]=0;
                strcat(proc_pid_fd_path, m_dirent->d_name);
                memset (proc_pid_exe, 0 , sizeof(proc_pid_exe));
				// TODO: Ignore . or ..
                if (readlink ( proc_pid_fd_path, proc_pid_exe, SOCKETBUFSIZE ) == -1)  //not a symlink but . or ..
                {
                    errno=0;
                    continue;
                }
                if (proc_pid_exe[7] != '[') continue; //not a socket
                char *end;
                end = strrchr(&proc_pid_exe[8],']'); //put 0 instead of ]
                *end = 0;
                rule->sockets_cache[i] = atol(&proc_pid_exe[8]);
                i++;
            }
            rule->sockets_cache[i] = MAGIC_NO;
            if (errno==0)
            {
                continue; //readdir reached EOF, thus errno hasn't changed from 0
            }
            //else
            M_PRINTF ( MLOG_DEBUG, "readdir: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
        }
        pthread_mutex_unlock(&dlist_mutex);
    }
}

void* nfq_out_udp_thread ( void *ptr )
{
    ptr = 0;
    //endless loop of receiving packets and calling a handler on each packet
    int rv;
    char buf[4096] __attribute__ ( ( aligned ) );
    while ( ( rv = recv ( nfqfd_udp, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
        nfq_handle_packet ( globalh_out_udp, buf, rv );
    }
}

void* nfq_gid_thread ( void *ptr )
{
    ptr = 0;
    //endless loop of receiving packets and calling a handler on each packet
    int rv;
    char buf[4096] __attribute__ ( ( aligned ) );
    while ( ( rv = recv ( nfqfd_gid, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
        nfq_handle_packet ( globalh_gid, buf, rv );
    }
}

void* nfq_out_rest_thread ( void *ptr )
{
    ptr = 0;
    //endless loop of receiving packets and calling a handler on each packet
    int rv;
    char buf[4096] __attribute__ ( ( aligned ) );
    while ( ( rv = recv ( nfqfd_rest, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
        nfq_handle_packet ( globalh_out_rest, buf, rv );
    }
}

void* nfq_in_thread ( void *ptr )
{
    ptr = 0;
//endless loop of receiving packets and calling a handler on each packet
    int rv;
    char buf[4096] __attribute__ ( ( aligned ) );
    while ( ( rv = recv ( nfqfd_input, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
        nfq_handle_packet ( globalh_in, buf, rv );
    }
}

void* rules_dump_thread ( void *ptr )
{
    ptr = 0;
    int fifofd;
    char buf;
    int retval;

    mkfifo ( "/tmp/lpfwrulesdump.fifo", 0777 );
    fifofd = open ("/tmp/lpfwrulesdump.fifo", O_RDWR );

    while ( 1 )
    {
        if ( ( retval = read ( fifofd, &buf, 1 ) ) > 0 ) goto dump;
        sleep ( 1 );
        continue;
dump:
        ;
        FILE *fd;
        fd = fopen ("/tmp/lpfwrulesdump.txt", "w" );

        ruleslist *temp;
        pthread_mutex_lock ( &dlist_mutex );
        temp = first_rule->next;
        char nfmarkstr[16];
        while ( temp != NULL )
        {
            fputs ( temp->path, fd );
            fputc ( '\n', fd );
            fputs ( temp->pid, fd );
            fputc ( '\n', fd );
            fputs ( temp->perms, fd );
            fputc ( '\n', fd );
            fputc ( temp->is_active, fd );
            fputc ( '\n', fd );
            sprintf(nfmarkstr, "%d", temp->nfmark_out);
            fputs (nfmarkstr, fd);
            fputc ( '\n', fd );
            fputc ( '\n', fd );

            temp = temp->next;
        }
        pthread_mutex_unlock ( &dlist_mutex );
        fclose ( fd );
    }
}

//scan procfs and remove/mark inactive in dlist those apps that are no longer running
void* refresh_thread ( void* ptr )
{
    prctl(PR_SET_NAME,"refresh",0,0,0);
    ruleslist *rule, *prev, *temp_rule;
    ptr = 0;     //to prevent gcc warnings of unused variable
    char proc_pid_exe[32] = "/proc/";
    char exe_path[PATHSIZE];

    while ( 1 )
    {
loop:
        pthread_mutex_lock ( &dlist_mutex );
        rule = first_rule;
        while ( rule->next != NULL )
        {
            rule = rule->next;
            //kernel processes don't have /proc/PID entries
            if (!rule->is_active || !strcmp(rule->path, KERNEL_PROCESS)) continue;
            proc_pid_exe[6]=0;
            strcat ( proc_pid_exe, rule->pid );
            strcat ( proc_pid_exe, "/exe" );
            memset ( exe_path, 0, PATHSIZE );
            //readlink doesn't fail if PID is running
            if ( readlink ( proc_pid_exe, exe_path, PATHSIZE ) != -1 )
            {
                continue;
            }
            else
            {
                M_PRINTF ( MLOG_DEBUG, "readlink for:%s %s in %s:%d\n", rule->path, strerror ( errno ), __FILE__, __LINE__ );
                if ( !strcmp ( rule->perms, ALLOW_ONCE ) || !strcmp ( rule->perms, DENY_ONCE ) )
                {
                    char path[PATHSIZE];
                    char pid[PIDLENGTH];
                    strncpy (path, rule->path, PATHSIZE);
                    strncpy (pid, rule->pid, PIDLENGTH);
                    pthread_mutex_unlock ( &dlist_mutex );
                    ruleslist_del ( path, pid );
                    continue;
                }
                //Only delete *ALWAYS rule if there is at least one more rule in dlist with the same PATH
                //If the rule is the only one in dlist with such PATH, simply toggle its_active flag
                if ( !strcmp ( rule->perms, ALLOW_ALWAYS ) || !strcmp ( rule->perms, DENY_ALWAYS ) )
                {
                    temp_rule = first_rule->next;
                    while ( temp_rule != NULL ) //scan the whole dlist again
                    {
                        if ( !strcmp ( temp_rule->path, rule->path ) && ( temp_rule != rule ) ) //Make sure we don't find our own rule :)
                        {
                            // TODO dlist_del is redundant we could keep a pointer to self in each dlist element and simply free(temp->self)
                            // is there really a need for dlistdel? apart from the fact that frontend deletes by path :(
                            char path[PATHSIZE];
                            char pid[PIDLENGTH];
                            strncpy (path, rule->path, PATHSIZE);
                            strncpy (pid, rule->pid, PIDLENGTH);
                            pthread_mutex_unlock ( &dlist_mutex );
                            ruleslist_del ( path, pid );
                            goto loop;
                        }
                        temp_rule=temp_rule->next;
                        continue;
                    }
                    //no PATH match
                    strcpy ( rule->pid, "0" );
                    rule->is_active = FALSE;
                    //nfmarks will be used by the next instance of app
                    rule->nfmark_in = NFMARKIN_BASE + nfmark_count;
                    rule->nfmark_out = NFMARKOUT_BASE +  nfmark_count;
                    nfmark_count++;
                    if (fe_active_flag_get())
                    {
                        fe_list();
                    }
                    continue;
                }
            }
        }
        pthread_mutex_unlock ( &dlist_mutex );
        sleep ( REFRESH_INTERVAL );
    }
}

void global_rule_add( const char *str_direction, char *str_ports)
{
    int direction;
    char *token, *token_range, *lasts_out, *lasts_in;
    int port_min, port_max, is_range;
    ports_list_t *m_ports_list = NULL, *m_ports_list_prev = NULL, *m_ports_list_to_add = NULL;

    if (!strcmp(str_direction, "TCP_IN_ALLOW")) direction = TCP_IN_ALLOW;
    else if (!strcmp(str_direction, "TCP_IN_DENY")) direction = TCP_IN_DENY;
    else if (!strcmp(str_direction, "TCP_OUT_ALLOW")) direction = TCP_OUT_ALLOW;
    else if (!strcmp(str_direction, "TCP_OUT_DENY")) direction = TCP_OUT_DENY;
    else if (!strcmp(str_direction, "UDP_IN_ALLOW")) direction = UDP_IN_ALLOW;
    else if (!strcmp(str_direction, "UDP_IN_DENY")) direction = UDP_IN_DENY;
    else if (!strcmp(str_direction, "UDP_OUT_ALLOW")) direction = UDP_OUT_ALLOW;
    else if (!strcmp(str_direction, "UDP_OUT_DENY")) direction = UDP_OUT_DENY;
    else {
        printf ("Invalid format of rulesfile \n");
        return;
    }
    token = strtok_r(str_ports, ",", &lasts_out);
    while (token != NULL)
    {
        if (strstr(token, "-") == NULL) {
            is_range = FALSE;
            port_min = atoi(token);
        }
        else
        {
            is_range = TRUE;
            token_range = strtok_r(token,"-",&lasts_in);
            port_min = atoi(token_range);
            token_range = strtok_r(NULL,"-", &lasts_in);
            port_max = atoi(token_range);
            if (port_min >= port_max)
            {
                printf ("In global rules: port range is specified incorrectly \n");
                return;
            }
        }

        int i, delta;
        if (direction % 2 == 0) delta = 1;
        else delta = -1;
        //scan both ALLOW and DENY port_lists - there should be no overlap in either
        for (i = 0; i < 2; i++)
        {
            m_ports_list = ports_list_array[direction + delta*i];
            while (m_ports_list != NULL)
            {
                if (m_ports_list->is_range)
                {
                    if (is_range)
                    {
                        if ((m_ports_list->min_port = port_min) ||
                                ((m_ports_list->min_port > port_min) && (m_ports_list->min_port <= port_max)) ||
                                ((m_ports_list->min_port < port_min) && (m_ports_list->max_port >= port_min)))
                            goto error;
                    }
                    else //not a range
                    {
                        if ((m_ports_list->min_port <= port_min) && (m_ports_list->max_port >= port_min))
                            goto error;
                    }
                }
                else // not a range
                {
                    if (is_range)
                    {
                        if ((port_min <= m_ports_list->min_port) && (port_max>= m_ports_list->min_port))
                            goto error;
                    }
                    else //not a range
                    {
                        if (m_ports_list->min_port == port_min)
                            goto error;
                    }
                }
                m_ports_list_prev = m_ports_list;
                m_ports_list = m_ports_list->next;
            }
        }

        if ((m_ports_list_to_add = ( ports_list_t * ) malloc ( sizeof ( ports_list_t ) ) ) == NULL )
        {
            M_PRINTF ( MLOG_INFO, "malloc: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
            exit(0);
        }
        m_ports_list_to_add->is_range = is_range;
        m_ports_list_to_add->min_port = port_min;
        m_ports_list_to_add->max_port = port_max;
        m_ports_list_to_add->next = NULL;
        m_ports_list_to_add->prev = m_ports_list_prev;
        //if it's the very first element of array
        if (m_ports_list_prev == NULL)
        {
            ports_list_array[direction] = m_ports_list_to_add;
        }
        else
        {
            m_ports_list_prev->next = m_ports_list_to_add;
        }
        token = strtok_r(NULL, ",", &lasts_out);
    }
    return;

error:
    printf ("Error validating port \n");
    return;
}

//Read RULESFILE into dlist
void rules_load()
{
    FILE *stream;
    char path[PATHSIZE], laststring[PATHSIZE] , line[PATHSIZE], perms[PERMSLENGTH];;
    char *result;
    char ip[INET_ADDRSTRLEN+1];//plus trailing /n and 0
    unsigned long sizeint;
    char sizestring[16];
    char shastring[DIGEST_SIZE * 2 + 2];
    unsigned char digest[DIGEST_SIZE];
    unsigned char hexchar[3] = "";
    char newline[2] = {'\n','\0'};
    char *token, *lasts;
    char direction[14];
    char ports[PATHSIZE - 100];

    if ( access ( rules_file->filename[0], F_OK ) == -1 )
    {
        M_PRINTF ( MLOG_INFO, "CONFIG doesnt exist...creating" );
        stream = fopen (rules_file->filename[0], "w+");
    }
    stream = fopen (rules_file->filename[0], "r");

//First read the global rules
    fgets ( path, PATHSIZE, stream );
    path[strlen ( path ) - 1] = 0; //remove newline
    if (!strcmp(path, "[GLOBAL]"))
    {
        while(fgets ( path, PATHSIZE, stream ))
        {
            if (!strcmp (path, newline)) break;
            path[strlen ( path ) - 1] = 0; //remove newline
            token = strtok_r(path, " ", &lasts);
            strncpy(direction, token, sizeof(direction));
            token = strtok_r(NULL, " ", &lasts);
            strncpy(ports, token, sizeof(ports));
            global_rule_add(direction, ports);
        }
    }
    else
    {
        fseek (stream, 0, SEEK_SET);
    }

    //Now process all the non-global, i.e. per-application rules
    while ( 1 )
    {
        //fgets reads <newline> into the string and terminates with /0
        if ( fgets ( path, PATHSIZE, stream ) == 0 ) break;
        path[strlen ( path ) - 1] = 0; //remove newline
        if (!strcmp(path, KERNEL_PROCESS)) //separate treatment for kernel process
        {
            if ( fgets ( ip, INET_ADDRSTRLEN+1, stream ) == 0 ) break; //read IP address
            ip[strlen ( ip ) - 1] = 0;
            if ( fgets ( perms, PERMSLENGTH, stream ) == 0 ) break;
            perms[strlen ( perms ) - 1] = 0;
            if ( fgets ( laststring, PATHSIZE, stream ) == 0 ) break; //read last newline
            ruleslist_add( path, ip , perms, FALSE, digest, 0, 0, 0, TRUE);
            continue;
        }
        if ( fgets ( perms, PERMSLENGTH, stream ) == 0 ) break;
        perms[strlen ( perms ) - 1] = 0;
        if ( fgets ( sizestring, 16, stream ) == 0 ) break;
        sizestring[strlen ( sizestring ) - 1] = 0;
        sizeint = atol ( sizestring );
        if ( fgets ( shastring, DIGEST_SIZE * 2 + 2, stream ) == 0 ) break;

        memset ( digest, 0, DIGEST_SIZE );
        int i = 0;
        for ( i; i < DIGEST_SIZE; ++i )
        {
            hexchar[0] = shastring[i * 2];
            hexchar[1] = shastring[i * 2 + 1];
            sscanf ( hexchar, "%x", ( unsigned int * ) &digest[i] );
        }
        if ( fgets ( laststring, PATHSIZE, stream ) == 0 ) break; //read last newline

        ruleslist_add ( path, "0", perms, FALSE, digest, 2, ( off_t ) sizeint, 0, TRUE);
    }
    fclose (stream);
}

//Write to RULESFILE only entries that have ALLOW/DENY_ALWAYS permissions and GLOBAL rules
void rulesfileWrite()
{
    FILE *fd, *stream;
    int i;
    unsigned char shastring[DIGEST_SIZE * 2 + 1] = "";
    unsigned char shachar[3] = "";
    char sizestring[16];
    int is_first_port=TRUE , is_first_rule=TRUE ;
    char portsstring [PATHSIZE];
    ports_list_t * ports_list;

    //rewrite/create the file regardless of whether it already exists
    fd = fopen (rules_file->filename[0], "w");

    //First write GLOBAL rules
    for (i=0; i < 8; i++)
    {
        is_first_port = TRUE;
        if (ports_list_array[i] == NULL) continue;
        else
        {
            if (is_first_rule == TRUE)
            {
                is_first_rule = FALSE;
                fputs ("[GLOBAL]", fd);
                fputc ('\n', fd );
            }
            if (i == TCP_IN_ALLOW) strcpy(portsstring, "TCP_IN_ALLOW ");
            else if (i == TCP_IN_DENY) strcpy(portsstring, "TCP_IN_DENY ");
            else if (i == TCP_OUT_ALLOW) strcpy(portsstring, "TCP_OUT_ALLOW ");
            else if (i == TCP_OUT_DENY) strcpy(portsstring, "TCP_OUT_DENY ");
            else if (i == UDP_IN_ALLOW) strcpy(portsstring, "UDP_IN_ALLOW ");
            else if (i == UDP_IN_DENY) strcpy(portsstring, "UDP_IN_DENY ");
            else if (i == UDP_OUT_ALLOW) strcpy(portsstring, "UDP_OUT_ALLOW ");
            else if (i == UDP_OUT_DENY) strcpy(portsstring, "UDP_OUT_DENY ");
        }
        ports_list = ports_list_array[i];
        while (ports_list != NULL)
        {
            if (ports_list_array[i]->is_range)
            {
                if (is_first_port)
                {
                    is_first_port = FALSE;
                    sprintf(&portsstring[strlen(portsstring)],"%d-%d", ports_list_array[i]->min_port,ports_list_array[i]->max_port);
                }
                else
                {
                    sprintf(&portsstring[strlen(portsstring)],",%d-%d", ports_list_array[i]->min_port,ports_list_array[i]->max_port);
                }
            }
            else
            {
                if (is_first_port)
                {
                    is_first_port = FALSE;
                    sprintf(&portsstring[strlen(portsstring)],"%d", ports_list_array[i]->min_port);
                }
                else
                {
                    sprintf(&portsstring[strlen(portsstring)],",%d", ports_list_array[i]->min_port);
                }
            }
            ports_list = ports_list->next;
        }
        fputs (portsstring, fd);
        fputc ('\n', fd );
    }
    if (is_first_rule == FALSE)
    {
        fputc ('\n', fd );
    }

    pthread_mutex_lock ( &dlist_mutex );
    ruleslist* temp = first_rule->next;
    ruleslist* temp2;

loop:
    while ( temp != NULL )
    {
        if ( ( !strcmp ( temp->perms, ALLOW_ALWAYS ) ) || ( !strcmp ( temp->perms, DENY_ALWAYS ) ) )
        {
            //now check if same path with perms ALWAYS wasn't present in previous rules and if not then add  this rules index to dlist
            //ignore inkernel rules, though
            if (!strcmp(temp->path, KERNEL_PROCESS)) goto inkernel;
            temp2 = temp->prev;
            while ( temp2 != NULL )
            {
                if ( !strcmp ( temp2->path, temp->path ) )
                {
                    if ( ( !strcmp ( temp2->perms, ALLOW_ALWAYS ) ) || ( !strcmp ( temp2->perms, DENY_ALWAYS ) ) )
                    {
                        temp = temp->next;
                        goto loop;
                    }
                }
                temp2 = temp2->prev;
            }
inkernel:
            if (!strcmp(temp->path, KERNEL_PROCESS))
            {
                fputs (temp->path, fd);
                fputc ('\n', fd );
                fputs (temp->pid, fd);
                fputc ('\n', fd );
                fputs (temp->perms, fd);
                fputc ('\n', fd );
                fputc ('\n', fd );
                fsync ( fileno ( fd ) );
                temp = temp->next;
                continue;
            }

            fputs (temp->path, fd);
            fputc ('\n', fd );
            fputs (temp->perms, fd);
            fputc ('\n', fd );
            sprintf ( sizestring, "%ld", ( long ) temp->exesize );
            fputs (sizestring, fd);
            fputc ('\n', fd );

            shastring[0] = 0;
            for ( i = 0; i < DIGEST_SIZE; ++i )
            {
                //pad single digits with a leading zero
                sprintf ( shachar, "%02x", temp->sha[i] );
                strcat ( shastring, shachar );
            }
            shastring[DIGEST_SIZE * 2] = 0;

            fputs (shastring, fd);
            fputc ('\n', fd );
            fputc ('\n', fd );

            //don't proceed until data is written to disk
            fsync ( fileno ( fd ) );
        }
        temp = temp->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );
    fclose (fd);
}

//if another rule with this path is in dlist already, check if our process is fork()ed or a new instance
int path_find_in_ruleslist ( int *nfmark_to_set, const char *path, const char *pid, unsigned long long *stime)
{
    struct stat exestat;
    ruleslist* rule_iterator;
    FILE *stream;
    int retval;

    pthread_mutex_lock ( &dlist_mutex );
    rule_iterator = first_rule->next;
    while ( rule_iterator != NULL )
    {
        if ( !strcmp ( rule_iterator->path, path ) )
        {
            if (!rule_iterator->is_active) //rule in dlist has been added from rulesfile and hasn't seen traffic yet.
                //Exesize and shasum our process once
            {
                if ( stat ( path, &exestat ) == -1 )
                {
                    M_PRINTF ( MLOG_INFO, "stat: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                    pthread_mutex_unlock ( &dlist_mutex );
                    return CANT_READ_EXE;
                }
                if ( rule_iterator->exesize != exestat.st_size )
                {
                    M_PRINTF ( MLOG_INFO, "Exe sizes dont match.  %s in %s, %d\n", path, __FILE__, __LINE__ );
                    pthread_mutex_unlock ( &dlist_mutex );
                    return EXESIZE_DONT_MATCH;
                }

                //TODO mutex will be held for way too long here, find a way to decrease time
                unsigned char sha[DIGEST_SIZE];
                if ((stream = fopen ( path, "r" )) == NULL)
                {
                    M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                    pthread_mutex_unlock ( &dlist_mutex );
                    return CANT_READ_EXE;
                }
                sha512_stream ( stream, ( void * ) sha );
                fclose ( stream );
                if ( memcmp ( rule_iterator->sha, sha, DIGEST_SIZE ) )
                {
                    M_PRINTF ( MLOG_INFO, "Shasums dont match. Impersonation attempt detected by %s in %s, %d\n", rule_iterator->path, __FILE__, __LINE__ );
                    pthread_mutex_unlock ( &dlist_mutex );
                    return SHA_DONT_MATCH;
                }

                strncpy ( rule_iterator->pid, pid, PIDLENGTH ); //update entry's PID and inode
                rule_iterator->is_active = TRUE;
                rule_iterator->stime = *stime;
                strcpy(rule_iterator->pidfdpath,"/proc/");
                strcat(rule_iterator->pidfdpath, rule_iterator->pid);
                strcat(rule_iterator->pidfdpath, "/fd/");
                rule_iterator->dirstream = opendir (rule_iterator->pidfdpath );

                if ( !strcmp ( rule_iterator->perms, ALLOW_ONCE ) || !strcmp ( rule_iterator->perms, ALLOW_ALWAYS ) )
                {
                    retval = PATH_FOUND_IN_DLIST_ALLOW;
                }
                else if ( !strcmp ( rule_iterator->perms, DENY_ONCE ) || !strcmp ( rule_iterator->perms, DENY_ALWAYS ) )
                {
                    retval = PATH_FOUND_IN_DLIST_DENY;
                }
                else
                {
                    M_PRINTF ( MLOG_INFO, "should never get here. Please report %s,%d\n", __FILE__, __LINE__ );
                }
                pthread_mutex_unlock ( &dlist_mutex );
                //notify fe that the rule has an active PID now
                if (fe_active_flag_get())
                {
                    fe_list();
                }
                return retval;
            }
            else if ( rule_iterator->is_active )
            {

//determine if this is new instance or fork()d child
// --------------------------
// Here is how to determine if a process with the same PATH is either a new instance or a fork()ed process.
//
// 1. Get new process's(NP) PPID.(parent PID)
// 2. Is there an entry in dlist with the same PATH as NP AND PID == PPID?
// 3. If no then we have a new instance, go to step A1
// 4. If yes, we have a fork()ed process, go to step B1
//
// A1. Are there any entries in dlist with the same PATH as NP AND *ALWAYS perms? If yes, then create new entry in dlist copy parent's perms and all other attributer over to NP and continue;
// A2. If No, i.e. there either aren't any entries in dlist with the same PATH as NP OR there are entries with the same path as NP AND *ONCE perms, then query user.
//
// B1. Create new entry in dlist copy parent's perms and all other attributes over to NP and continue.
// --------------------------

//get new process's PPID
                FILE *stream;
                char proc_stat_path[32] = "/proc/";
                strcat ( proc_stat_path, pid );
                strcat ( proc_stat_path, "/stat" );

                if ( ( stream = fopen ( proc_stat_path, "r" ) ) == 0 )
                {
                    M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                    return PROCFS_ERROR;
                };

                char ppid[16];

                fscanf ( stream, "%*s %*s %*s %s", ppid );

//first copy parent's attributes

                char tempperms[PERMSLENGTH];
                char tempsha [DIGEST_SIZE];
                char temppid [PIDLENGTH-1];
                off_t parent_size = rule_iterator->exesize;
                unsigned long long saved_stime = rule_iterator->stime;
                strncpy ( tempperms, rule_iterator->perms, PERMSLENGTH );
                strncpy ( temppid, rule_iterator->pid, PIDLENGTH );
                memcpy ( tempsha, rule_iterator->sha, DIGEST_SIZE );

//is it a fork()ed child? the "parent" above may not be the actual parent of this fork, e.g. there may be
//two or three instances of an app running aka three "parents". We have to rescan dlist to ascertain

                ruleslist * temp = first_rule->next;
                while ( temp != NULL )
                {
                    if ( !strcmp ( temp->path, path ) && !strcmp ( temp->pid, ppid ) ) //we have a fork()ed child
                    {
                        int retval;
                        if ( !strcmp ( temp->perms, ALLOW_ALWAYS ) || !strcmp ( temp->perms, ALLOW_ONCE ) )
                        {

                            retval = FORKED_CHILD_ALLOW;

                        }
                        else if ( !strcmp ( temp->perms, DENY_ALWAYS ) || !strcmp ( temp->perms, DENY_ONCE ) )
                        {
                            retval =  FORKED_CHILD_DENY;
                        }

                        char tempperms2[PERMSLENGTH];
                        char tempsha2 [DIGEST_SIZE];
                        off_t parent_size2 = temp->exesize;
                        strncpy ( tempperms2, temp->perms, PERMSLENGTH );
                        memcpy ( tempsha2, temp->sha, DIGEST_SIZE );

                        pthread_mutex_unlock ( &dlist_mutex );

                        unsigned long long stime;
                        stime = starttimeGet ( atoi ( pid ) );

                        *nfmark_to_set = ruleslist_add ( path, pid, tempperms2, TRUE, tempsha2, stime, parent_size2, 0, FALSE );
                        if (fe_active_flag_get())
                        {
                            fe_list();
                        }
                        return retval;
                    }
                    temp = temp->next;
                }
                pthread_mutex_unlock ( &dlist_mutex );

                //we have a new instance, need to ascertain that app instantiated from unmodified binary


                /*
                            //----------------OPTION 1----------------check shasum. Painful, may take 5 secs each time a user starts
                         //his web browser
                            char sha2[DIGEST_SIZE+1];
                            FILE *stream2;
                            memset(sha2, 0, DIGEST_SIZE+1);
                            stream2 = fopen(path, "r");
                            sha512_stream(stream2, (void *) sha2);
                            fclose(stream2);
                            if (strcmp(tempsha, sha2)){
                                M_PRINTF(MLOG_INFO, "Shasums dont match. Impersonation attempt detected by %s in %s, %d\n", path, __FILE__, __LINE__);
                                return SHA_DONT_MATCH;
                            }
                */

                /*
                //----------OPTION 2 -----------check if parent's /PID/exe doesnt have  " (deleted)" appended
                //The attacker might have deleted the binary and replaced it with his own
                //NB. it is impossible to modify an executable's file on disk while it is running, thus this method is secure (yet it is possible to delete it even while process is running)
                */

                //now make sure parent's exepath doesn't have " (deleted)" on its tail
                char exepath[32] = "/proc/";
                strcat ( exepath, temppid );
                strcat ( exepath, "/exe" );
                char exepathbuf[PATHSIZE];
                memset ( exepathbuf, 0, PATHSIZE );
                readlink ( exepath, exepathbuf, PATHSIZE-1 );

                int ssize;
                ssize = strlen ( exepathbuf );
                if ( !strcmp ( &exepathbuf[ssize-10], " (deleted)" ) )
                {
                    M_PRINTF ( MLOG_ALERT, "Red alert!!!! Executable has been changed...  %s, %s, %d\n",exepath, __FILE__, __LINE__ );
                    return EXE_HAS_BEEN_CHANGED;

                }

                //If exe hasnt been modified/deleted than taking its size is redundant, just use parent's size

                M_PRINTF ( MLOG_DEBUG, "Adding to dlist: %s, %s, %s\n", path, pid, tempperms );

                //See if we need to query user or silently add to dlist
                pthread_mutex_lock ( &dlist_mutex );
                ruleslist * temp2 = first_rule->next;

// A1. Are there any entries in dlist with the same PATH as NP AND *ALWAYS perms? If yes, then create new entry in dlist copy parent's perms and all other attributes over to NP and continue;
// A2. If No, i.e. there either aren't any entries in dlist with the same PATH as NP OR there are entries with the same path as NP AND *ONCE perms, then query user.

                while ( temp2 != NULL )
                {
                    if ( !strcmp ( temp2->path, path ) )
                    {
                        if ( !strcmp ( temp2->perms, ALLOW_ALWAYS ) )
                        {
                            pthread_mutex_unlock ( &dlist_mutex );
                            *nfmark_to_set = ruleslist_add ( path, pid, tempperms, TRUE, tempsha, *stime, parent_size, 0 ,FALSE);
                            if (fe_active_flag_get())
                            {
                                fe_list();
                            }
                            return NEW_INSTANCE_ALLOW;
                        }
                        else if ( !strcmp ( temp2->perms, DENY_ALWAYS ) )
                        {
                            pthread_mutex_unlock ( &dlist_mutex );
                            ruleslist_add ( path, pid, tempperms, TRUE, tempsha, *stime, parent_size, 0, FALSE );
                            if (fe_active_flag_get())
                            {
                                fe_list();
                            }
                            return NEW_INSTANCE_DENY;
                        }
                    }
                    temp2 = temp2->next;
                }
                // we need to send new query to user
                goto quit;

            } // else if (temp->current_pid == '1')
        } //  if (!strcmp(temp->path, path)) {
        rule_iterator = rule_iterator->next;
    } //while (temp != NULL)

quit:
    pthread_mutex_unlock ( &dlist_mutex );
    //if the path is not in dlist or is a new instance of an *ONCE rule
    return PATH_IN_DLIST_NOT_FOUND;
}

int socket_active_processes_search ( const long *mysocket, char *m_path, char *m_pid, int *nfmark_to_set)
{
    char find_socket[32]; //the string we are searching in /proc/PID/fd/1,2,3 etc.  a-la socket:[1234]
    char path[32];
    char path2[32];
    char socketbuf[32];
    char exepathbuf[PATHSIZE];
    DIR * m_dir;
    struct dirent *m_dirent;
    char socketstr[32];

    sprintf ( socketstr, "%ld", *mysocket );  //convert inode from int to string
    strcpy ( find_socket, "socket:[" );
    strcat ( find_socket, socketstr );
    strcat ( find_socket, "]" );

    pthread_mutex_lock ( &dlist_mutex );
    ruleslist * temp = first_rule->next;

    while ( temp != NULL )
    {
        //find entry with a known PID, i.e. this entry has already seen active packets in this session
        //and also ignore kernel processes
        if (!temp->is_active || !strcmp(temp->path, KERNEL_PROCESS))
        {
            temp = temp->next;
            continue;
        }
        strcpy ( path, "/proc/" );
        strcat ( path, temp->pid );
        strcat ( path, "/fd/" );
        if ( ! ( m_dir = opendir ( path ) ) )
        {
            //This condition can happen if the PID is still in the dlist, the process exited and refresh_thread hasn't yet purged it out of the dlist
            M_PRINTF ( MLOG_DEBUG, "opendir for %s %s: %s,%s,%d\n", temp->path, path, strerror ( errno ), __FILE__, __LINE__ );
            temp = temp->next;
            closedir ( m_dir );
            continue;
        }
        while ( m_dirent = readdir ( m_dir ) )
        {
            strncpy ( path2, path, sizeof(path2));
            strcat ( path2, m_dirent->d_name ); //path2 contains /proc/PID/fd/1,2,3 etc. which are symlinks
            memset ( socketbuf, 0, SOCKETBUFSIZE );
            readlink ( path2, socketbuf, SOCKETBUFSIZE ); //no trailing 0
            //TODO socketbuf[readlink's retval] = 0 instead of memset
            if ( strcmp ( find_socket, socketbuf ) == 0 )
            {
                //return link /proc/<pid>/exe
                strcpy ( path, "/proc/" );
                strcat ( path, temp->pid );
                strcat ( path, "/exe" );
                memset ( exepathbuf, 0, PATHSIZE );
                readlink ( path, exepathbuf, PATHSIZE );
                //TODO exepathbuf[readlink's retval] = 0 instead of memset
                strcpy(m_path, exepathbuf);
                strcpy (m_pid, temp->pid);
                closedir ( m_dir );

                unsigned long long stime;
                stime = starttimeGet ( atoi ( temp->pid ) );
                if ( temp->stime != stime )
                {
                    M_PRINTF ( MLOG_INFO, "SPOOFED_PID in %s %s %d", temp->path,  __FILE__, __LINE__ );
                    return SPOOFED_PID;
                }

                if ( !strcmp ( temp->perms, ALLOW_ONCE ) || !strcmp ( temp->perms, ALLOW_ALWAYS ) )
                {
                    *nfmark_to_set = temp->nfmark_out;

                    pthread_mutex_unlock ( &dlist_mutex );
                    return SOCKET_FOUND_IN_DLIST_ALLOW;
                }
                if ( !strcmp ( temp->perms, DENY_ONCE ) || !strcmp ( temp->perms, DENY_ALWAYS ) )
                {
                    pthread_mutex_unlock ( &dlist_mutex );
                    return SOCKET_FOUND_IN_DLIST_DENY;
                }
            }
        }
        closedir ( m_dir );
        temp = temp->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );
    return SOCKET_ACTIVE_PROCESSES_NOT_FOUND;
}

int socket_procpidfd_search ( const long *mysocket, char *m_path, char *m_pid, unsigned long long *stime )
{
    struct dirent *proc_dirent, *fd_dirent;
    DIR *proc_DIR, *fd_DIR;
    // holds path to /proc/<pid>/fd/<number_of_inode_opened>
    char path[32];
    char fdpath[32];
    // buffers to hold readlink()ed values of /proc/<pid>/exe and /proc/<pid>/fd/<inode>
    char exepathbuf[PATHSIZE];
    char socketbuf[SOCKETBUFSIZE];

    char socketstr[32];
    sprintf ( socketstr, "%ld", *mysocket ); //convert int to char* for future use
    char find_socket[32] = "socket:[";
    strcat ( find_socket, socketstr );
    strcat ( find_socket, "]" );

    proc_DIR = opendir ( "/proc" );
    do {
        proc_dirent = readdir ( proc_DIR );
        if ( !proc_dirent ) { //EOF reached or some error
            break;
        }
        if ( ( 47 < proc_dirent->d_name[0] ) && ( proc_dirent->d_name[0] < 58 ) ) { //ASCII 1 thru 9
            path[0] = 0; //empty the path
            strcpy ( path, "/proc/" );
            strcat ( path, proc_dirent->d_name );
            strcat ( path, "/fd" );
            fd_DIR = opendir ( path );
            if ( !fd_DIR ) { //NULL retval if process quit after readdir(proc_DIR) and path no longer exist
                M_PRINTF ( MLOG_INFO, "opendir(%s):%s,%s,%d\n", path, strerror ( errno ), __FILE__, __LINE__ );
                continue;
            }
            do {
                fd_dirent = readdir ( fd_DIR );
                if ( !fd_dirent ) { //EOF
                    closedir ( fd_DIR );
                    break;
                }
                //make sure theres no . in the path
                if ( ! ( fd_dirent->d_name[0] == 46 ) )
                {
                    fdpath[0] = 0;
                    strcat ( fdpath, path );
                    strcat ( fdpath, "/" );
                    strcat ( fdpath, fd_dirent->d_name );
                    memset ( socketbuf, 0, SOCKETBUFSIZE );
                    readlink ( fdpath, socketbuf, SOCKETBUFSIZE ); //no trailing 0
                    if ( strcmp ( find_socket, socketbuf ) == 0 ) //we found our socket!!!!
                    {
                        //immediately get starttime
                        *stime  = starttimeGet ( atoi ( proc_dirent->d_name ) );

                        //return link /proc/<pid>/exe
                        strcpy ( path, "/proc/" );
                        strcat ( path, proc_dirent->d_name );
                        strcat ( path, "/exe" );
                        memset ( exepathbuf, 0, PATHSIZE );
                        readlink ( path, exepathbuf, PATHSIZE - 1 );

                        closedir ( fd_DIR );
                        closedir ( proc_DIR );
                        strcpy ( m_path, exepathbuf );
                        strcpy ( m_pid, proc_dirent->d_name );
                        return SOCKET_FOUND_IN_PROCPIDFD;
                    }
                }
            }
            while ( fd_dirent );
        }
    }
    while ( proc_dirent );
    closedir ( proc_DIR );
    return SOCKET_NOT_FOUND_IN_PROCPIDFD;
}

//if there are more than one entry in /proc/net/raw for icmp then it's impossible to tell which app is sending the packet
int icmp_check_only_one_socket ( long *socket )
{
    int loop = 0;
    int readbytes = 1;

    char socket_str[32];

    while ( 1 )
    {
        lseek ( procnetrawfd, 206 + 110 * loop, SEEK_SET );
        readbytes = read (procnetrawfd, socket_str, 8 );
        //in case there was icmp packet but no /proc/net/raw entry - report
        if ( ( loop == 0 ) && ( readbytes == 0 ) )
        {
            M_PRINTF ( MLOG_INFO, "ICMP packet without /proc/net/raw entry" );
            return ICMP_NO_ENTRY;
        }
        //if there are two lines in the file, we drop the packet
        if ( loop > 0 )
        {
            if ( readbytes == 0 ) break; //break while loop
            //else the are more than one line
            return ICMP_MORE_THAN_ONE_ENTRY;
        }
        int i;
        for ( i = 0; i < 32; ++i )
        {
            if ( socket_str[i] == 32 )
            {
                socket_str[i] = 0; // 0x20 space, see /proc/net/ucp
                break;
            }
        }
        *socket = atol ( socket_str );
        ++loop;
    }
    M_PRINTF ( MLOG_DEBUG, "(icmp)socket %ld", *socket );
    return ICMP_ONLY_ONE_ENTRY;
}

int inkernel_check_udp(const int *port)
{
//The only way to distinguish kernel sockets is that they have inode=0 and uid=0
//But regular process's sockets sometimes also have inode=0 (I don't know why)
//+ root's sockets have uid == 0
//So we just assume that if inode==0 and uid==0 - it's a kernel socket

    int bytesread_udp,bytesread_udp6;
    char newline[2] = {'\n','\0'};
    char uid[2] = {'0','\0'};
    long socket_next;
    int port_next;
    char *token, *lasts;
    FILE *m_udpinfo, *m_udp6info;
    int m_udpinfo_fd, m_udp6info_fd;
    char m_udp_smallbuf[4096], m_udp6_smallbuf[4096];

    if ( ( m_udpinfo = fopen ( UDPINFO, "r" ) ) == NULL )
    {
        M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        exit (PROCFS_ERROR);
    }
    m_udpinfo_fd = fileno(m_udpinfo);

    memset(m_udp_smallbuf,0, 4096);
    while ((bytesread_udp = read(m_udpinfo_fd, m_udp_smallbuf, 4060)) > 0)
    {
        if (bytesread_udp == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(m_udp_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*8s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
            if (port_next != *port ) continue;
            else {
                if (socket_next != 0) {
                    fclose(m_udpinfo);
                    return SOCKET_CHANGED_FROM_ZERO;
                }
                else if (!strcmp (uid, "0")) {
                    fclose(m_udpinfo);
                    return INKERNEL_SOCKET_FOUND;
                }
                else {
                    fclose(m_udpinfo);
                    return SOCKET_ZERO_BUT_UID_NOT_ZERO;
                }
            }
        }
    }
    fclose(m_udpinfo);

//not found in /proc/net/udp, search in /proc/net/udp6

    if ( ( m_udp6info = fopen ( UDP6INFO, "r" ) ) == NULL )
    {
        M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        exit (PROCFS_ERROR);
    }
    m_udp6info_fd = fileno(m_udp6info);

    memset(m_udp6_smallbuf,0, 4096);
    while ((bytesread_udp6 = read(m_udp6info_fd, m_udp6_smallbuf, 4060)) > 0)
    {
        if (bytesread_udp6 == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(m_udp6_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*32s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
            if (port_next != *port ) continue;
            else {
                if (socket_next != 0) {
                    fclose(m_udp6info);
                    return SOCKET_CHANGED_FROM_ZERO;
                }
                else if (!strcmp (uid, "0")) {
                    fclose(m_udp6info);
                    return INKERNEL_SOCKET_FOUND;
                }
                else {
                    fclose(m_udp6info);
                    return SOCKET_ZERO_BUT_UID_NOT_ZERO;
                }
            }
        }
    }
    fclose(m_udp6info);
    return INKERNEL_SOCKET_NOT_FOUND;
}

int inkernel_check_tcp(const int *port)
{
//The only way to distinguish kernel sockets is that they have inode=0 and uid=0
//But regular process's sockets sometimes also have inode=0 (I don't know why)
//+ root's sockets have uid == 0
//So we just assume that if inode==0 and uid==0 - it's a kernel socket

    int bytesread_tcp,bytesread_tcp6;
    char newline[2] = {'\n','\0'};
    char uid[2] = {'0','\0'};
    long socket_next;
    int port_next;
    char *token, *lasts;
    FILE *m_tcpinfo, *m_tcp6info;
    int m_tcpinfo_fd, m_tcp6info_fd;
    char m_tcp_smallbuf[4096], m_tcp6_smallbuf[4096];

    if ( ( m_tcpinfo = fopen ( TCPINFO, "r" ) ) == NULL )
    {
        M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        exit (PROCFS_ERROR);
    }
    m_tcpinfo_fd = fileno(m_tcpinfo);

    memset(m_tcp_smallbuf,0, 4096);
    while ((bytesread_tcp = read(m_tcpinfo_fd, m_tcp_smallbuf, 4060)) > 0)
    {
        if (bytesread_tcp == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(m_tcp_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*8s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
            if (port_next != *port ) continue;
            else {
                if (socket_next != 0) {
                    fclose(m_tcpinfo);
                    return SOCKET_CHANGED_FROM_ZERO;
                }
                else if (!strcmp (uid, "0")) {
                    fclose(m_tcpinfo);
                    return INKERNEL_SOCKET_FOUND;
                }
                else {
                    fclose(m_tcpinfo);
                    return SOCKET_ZERO_BUT_UID_NOT_ZERO;
                }
            }
        }
    }
    fclose(m_tcpinfo);

//not found in /proc/net/tcp, search in /proc/net/tcp6

    if ( ( m_tcp6info = fopen ( TCP6INFO, "r" ) ) == NULL )
    {
        M_PRINTF ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        exit (PROCFS_ERROR);
    }
    m_tcp6info_fd = fileno(m_tcp6info);

    memset(m_tcp6_smallbuf,0, 4096);
    while ((bytesread_tcp6 = read(m_tcp6info_fd, m_tcp6_smallbuf, 4060)) > 0)
    {
        if (bytesread_tcp6 == -1)
        {
            perror ("read");
            return -1;
        }
        token = strtok_r(m_tcp6_smallbuf, newline, &lasts); //skip the first line (column headers)
        while ((token = strtok_r(NULL, newline, &lasts)) != NULL)
        {
            //take a line until EOF
            sscanf(token, "%*s %*32s:%4X %*s %*s %*s %*s %*s %s %*s %ld", &port_next, uid, &socket_next);
            if (port_next != *port ) continue;
            else {
                if (socket_next != 0) {
                    fclose(m_tcp6info);
                    return SOCKET_CHANGED_FROM_ZERO;
                }
                else if (!strcmp (uid, "0")) {
                    fclose(m_tcp6info);
                    return INKERNEL_SOCKET_FOUND;
                }
                else {
                    fclose(m_tcp6info);
                    return SOCKET_ZERO_BUT_UID_NOT_ZERO;
                }
            }
        }
    }
    fclose(m_tcp6info);
    return INKERNEL_SOCKET_NOT_FOUND;
}

//NEEDED BY THE TEST SUITE, don't comment out yetfind in procfs which socket corresponds to source port
int port2socket_udp ( int *portint, int *socketint )
{
    char *udp_membuf, *udp6_membuf;
    char buffer[5];
    char procport[12];
    char socketstr[12];
    long m_socketint;
    int not_found_once=0;
    int bytesread_udp = 0;
    int bytesread_udp6 = 0;
    int i = 0;

    struct timespec timer,dummy;
    timer.tv_sec=0;
    timer.tv_nsec=1000000000/4;
    //convert portint to a hex string of 4 all-caps chars with leading zeroes if necessary
    char porthex[5];
    sprintf (porthex, "%04X", *portint );

    goto dont_fread;

do_fread:
    memset(udp_membuf,0, MEMBUF_SIZE);
    fseek(udpinfo,0,SEEK_SET);
    errno = 0;
    if (bytesread_udp = fread(udp_membuf, sizeof(char), MEMBUF_SIZE , udpinfo))
    {
        if (errno != 0) perror("READERORRRRRRR");
    }
    M_PRINTF (MLOG_DEBUG2, "udp bytes read: %d\n", bytesread_udp);

    memset(udp6_membuf, 0, MEMBUF_SIZE);
    fseek(udp6info,0,SEEK_SET);
    errno = 0;
    if (bytesread_udp6 = fread(udp6_membuf, sizeof(char), MEMBUF_SIZE , udp6info))
    {
        if (errno != 0) perror("6READERORRRRRRR");
    }
    M_PRINTF (MLOG_DEBUG2, "udp6 bytes read: %d\n", bytesread_udp6);

dont_fread:
    ;
    char newline[2] = {'\n','\0'};
    char *token, *lasts;
    token = strtok_r(udp_membuf, newline, &lasts); //skip the first line (column headers)
    while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
        sscanf(token, "%*s %*8s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer, &m_socketint);
        if (!strcmp (porthex, buffer))
            goto endloop;
    }
    // else EOF reached with no match, check if it was IPv6 socket

    token = strtok_r(udp6_membuf, newline, &lasts); //skip the first line (column headers)
    while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
        sscanf(token, "%*s %*32s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer, &m_socketint);
        if (!strcmp (porthex, buffer))
            goto endloop;
    }

    //else EOF reached with no match, if it was 1st iteration then reread proc file
    if (not_found_once)
    {
        return SRCPORT_NOT_FOUND_IN_PROC;
    }
    //else
    nanosleep(&timer, &dummy);
    not_found_once=1;
    goto do_fread;

endloop:
    *socketint = m_socketint;
    if (*socketint == 0) return INKERNEL_SOCKET_FOUND;
    //else
    return 0;
}

//find in procfs which socket corresponds to source port
int  port2socket_tcp ( int *portint, int *socketint )
{
    char* tcp_membuf, *tcp6_membuf;
    char buffer[5];
    char procport[12];
    char socketstr[12];
    long m_socketint;
    int not_found_once=0;
    int bytesread_tcp = 0;
    int bytesread_tcp6 = 0;
    int i = 0;

    struct timespec timer,dummy;
    timer.tv_sec=0;
    timer.tv_nsec=1000000000/4;
    //convert portint to a hex string of 4 all-caps chars with leading zeroes if necessary
    char porthex[5];
    sprintf (porthex, "%04X", *portint );

    goto dont_fread;

do_fread:
    memset(tcp_membuf,0, MEMBUF_SIZE);
    fseek(tcpinfo,0,SEEK_SET);
    errno = 0;
    if (bytesread_tcp = fread(tcp_membuf, sizeof(char), MEMBUF_SIZE , tcpinfo))
    {
        if (errno != 0) perror("fread tcpinfo");
    }
    M_PRINTF (MLOG_DEBUG2, "tcp bytes read: %d\n", bytesread_tcp);

    memset(tcp6_membuf, 0, MEMBUF_SIZE);
    fseek(tcp6info,0,SEEK_SET);
    errno = 0;
    if (bytesread_tcp6 = fread(tcp6_membuf, sizeof(char), MEMBUF_SIZE , tcp6info))
    {
        if (errno != 0) perror("fread tcp6info");
    }
    M_PRINTF (MLOG_DEBUG2, "tcp6 bytes read: %d\n", bytesread_tcp6);

dont_fread:
    ;
    char newline[2] = {'\n','\0'};
    char *token, *lasts;
    token = strtok_r(tcp_membuf, newline, &lasts); //skip the first line (column headers)
    while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
        sscanf(token, "%*s %*8s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer, &m_socketint);
        if (!strcmp (porthex, buffer))
            goto endloop;
    }
    // else EOF reached with no match, check if it was IPv6 socket

    token = strtok_r(tcp6_membuf, newline, &lasts); //skip the first line (column headers)
    while ((token = strtok_r(NULL, newline, &lasts)) != NULL)  //take a line until EOF
    {
        sscanf(token, "%*s %*32s:%4s %*s %*s %*s %*s %*s %*s %*s %ld \n", buffer,& m_socketint);
        if (!strcmp (porthex, buffer))
            goto endloop;
    }

    //else EOF reached with no match, if it was 1st iteration then reread proc file
    if (not_found_once)
    {
        return SRCPORT_NOT_FOUND_IN_PROC;
    }
    //else
    nanosleep(&timer, &dummy);
    not_found_once=1;
    goto do_fread;

endloop:
    *socketint = m_socketint;
    if (*socketint == 0) return INKERNEL_SOCKET_FOUND;
    //else
    return 0;
}

//Handler for TCP packets for INPUT NFQUEUE
int socket_handle_tcp_in ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime)
{
    int retval;
    retval = search_pid_and_socket_cache_in(socket, path, pid, nfmark_to_set);
    if (retval != SOCKETS_CACHE_NOT_FOUND)
    {
        M_PRINTF (MLOG_DEBUG2, "(cache)");
        return retval;
    }
    retval = socket_active_processes_search ( socket, path, pid, nfmark_to_set );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND)
    {
        return retval;
    }
    retval = socket_procpidfd_search ( socket, path, pid, stime );
    if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD)
    {
        return retval;
    }
    else if (retval == SOCKET_FOUND_IN_PROCPIDFD)
    {
        retval = path_find_in_ruleslist ( nfmark_to_set, path, pid, stime);
        return retval;
    }
}

//Handler for TCP packets for OUTPUT NFQUEUE
int socket_handle_tcp_out ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime)
{
    int retval;
    retval = search_pid_and_socket_cache_out(socket, path, pid, nfmark_to_set);
    if (retval != SOCKETS_CACHE_NOT_FOUND) {
        M_PRINTF (MLOG_DEBUG2, "(cache)");
        return retval;
    }
    retval = socket_active_processes_search ( socket, path, pid, nfmark_to_set );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND ) {
        return retval;
    }
    retval = socket_procpidfd_search ( socket, path, pid, stime );
    if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD) {
        return retval;
    }
    else if (retval == SOCKET_FOUND_IN_PROCPIDFD) {
        retval = path_find_in_ruleslist ( nfmark_to_set, path, pid, stime);
        return retval;
    }
}

//Handler for UDP packets
int socket_handle_udp_in ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime)
{
    int retval;
    retval = search_pid_and_socket_cache_in(socket, path, pid, nfmark_to_set);
    if (retval != SOCKETS_CACHE_NOT_FOUND)
    {
        M_PRINTF (MLOG_DEBUG2, "(cache)");
        return retval;
    }
    retval = socket_active_processes_search ( socket, path, pid, nfmark_to_set );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND )
    {
        return retval;
    }
    retval = socket_procpidfd_search ( socket, path, pid, stime );
    if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD)
    {
        return retval;
    }
    else if (retval == SOCKET_FOUND_IN_PROCPIDFD)
    {
        retval = path_find_in_ruleslist ( nfmark_to_set, path, pid, stime);
        return retval;
    }
}

//Handler for UDP packets
int socket_handle_udp_out ( const long *socket, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime)
{
    int retval;
    retval = search_pid_and_socket_cache_out(socket, path, pid, nfmark_to_set);
    if (retval != SOCKETS_CACHE_NOT_FOUND)
    {
        M_PRINTF (MLOG_DEBUG2, "(cache)");
        return retval;
    }
    retval = socket_active_processes_search ( socket, path, pid, nfmark_to_set );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND )
    {
        return retval;
    }
    retval = socket_procpidfd_search ( socket, path, pid, stime );
    if (retval == SOCKET_NOT_FOUND_IN_PROCPIDFD)
    {
        return retval;
    }
    else if (retval == SOCKET_FOUND_IN_PROCPIDFD)
    {
        retval = path_find_in_ruleslist ( nfmark_to_set, path, pid, stime);
        return retval;
    }
}

long is_tcp_port_in_cache (const int *port)
{
    int i = 0;

    while (tcp_port_and_socket_cache[i*2] != (long)MAGIC_NO)
    {
        if (i >= (MEMBUF_SIZE / (sizeof(long)*2)) - 1) break;
        if (tcp_port_and_socket_cache[i*2] != (long)*port)
        {
            i++;
            continue;
        }
        else
        {
            int retval;
            retval = tcp_port_and_socket_cache[i*2+1];
            return retval;
        }
    }

    i = 0;
    while (tcp6_port_and_socket_cache[i*2] != (long)MAGIC_NO)
    {
        if (i >= (MEMBUF_SIZE / (sizeof(long)*2)) - 1) break;
        if (tcp6_port_and_socket_cache[i*2] != *port)
        {
            i++;
            continue;
        }
        else
        {
            int retval2;
            retval2 = tcp6_port_and_socket_cache[i*2+1];
            return retval2;
        }
    }
    //it wasn't found reinject it into the NFQUEUE again
    return -1;
}

long is_udp_port_in_cache (const int *port)
{
    int i = 0;
    while (udp_port_and_socket_cache[i*2] != (long)MAGIC_NO)
    {
        if (i >= (MEMBUF_SIZE / (sizeof(long)*2)) - 1) break;
        if (udp_port_and_socket_cache[i*2] !=(long) *port)
        {
            i++;
            continue;
        }
        else
        {
            return udp_port_and_socket_cache[i*2+1];
        }
    }

    i = 0;
    while (udp6_port_and_socket_cache[i*2] != (long)MAGIC_NO)
    {
        if (i >= (MEMBUF_SIZE / (sizeof(long)*2)) - 1) break;
        if (udp6_port_and_socket_cache[i*2] != (long)*port)
        {
            i++;
            continue;
        }
        else
        {
            int retval2;
            retval2 = udp6_port_and_socket_cache[i*2+1];
            return retval2;
        }
    }
    //it wasn't found reinject it into the NFQUEUE again
    return -1;
}

void print_traffic_log(const int proto, const int direction, const char *ip, const int srcport,
                       const int dstport, const char *path, const char *pid, const int verdict)
{
    char m_logstring[PATHSIZE];
    if (direction == DIRECTION_IN)
    {
        strcpy(m_logstring,">");
        if (proto == PROTO_TCP)
        {
            strcat(m_logstring,"TCP ");
        }
        else if (proto == PROTO_UDP)
        {
            strcat (m_logstring, "UDP ");
        }
        else if (proto == PROTO_ICMP)
        {
            strcat (m_logstring, "ICMP ");
        }
        char port[8];
        sprintf (port,"%d",dstport);
        strcat (m_logstring, "dst ");
        strcat (m_logstring, port);
        strcat (m_logstring, " src ");
        strcat (m_logstring, ip);
        strcat (m_logstring,":");
        sprintf(port, "%d", srcport);
        strcat (m_logstring, port);
        strcat (m_logstring, " ");
    }
    else if (direction == DIRECTION_OUT)
    {
        strcpy(m_logstring,"<");
        if (proto == PROTO_TCP)
        {
            strcat(m_logstring,"TCP ");
        }
        else if (proto == PROTO_UDP)
        {
            strcat (m_logstring, "UDP ");
        }
        else if (proto == PROTO_ICMP)
        {
            strcat (m_logstring, "ICMP ");
        }
        char port[8];
        sprintf (port,"%d",srcport);
        strcat (m_logstring, "src ");
        strcat (m_logstring, port);
        strcat (m_logstring, " dst ");
        strcat (m_logstring, ip);
        strcat (m_logstring,":");
        sprintf(port, "%d", dstport);
        strcat (m_logstring, port);
        strcat (m_logstring, " ");
    }
    strcat (m_logstring, path);
    strcat (m_logstring, " ");
    strcat (m_logstring, pid);
    strcat (m_logstring, " ");

    switch ( verdict )
    {
    case SOCKET_FOUND_IN_DLIST_ALLOW:
    case PATH_FOUND_IN_DLIST_ALLOW:
    case NEW_INSTANCE_ALLOW:
    case FORKED_CHILD_ALLOW:
    case CACHE_TRIGGERED_ALLOW:
    case INKERNEL_RULE_ALLOW:

        strcat (m_logstring, "allow\n");
        break;

    case GLOBAL_RULE_ALLOW:
        strcat (m_logstring, "(global rule) allow\n");
        break;


    case CANT_READ_EXE:
        strcat (m_logstring, "(can't read executable file) drop\n");
        break;
    case SENT_TO_FRONTEND:
        strcat (m_logstring,  "(asking frontend) drop\n" );
        break;
    case SOCKET_FOUND_IN_DLIST_DENY:
    case PATH_FOUND_IN_DLIST_DENY:
    case NEW_INSTANCE_DENY:
    case FORKED_CHILD_DENY:
    case CACHE_TRIGGERED_DENY:
    case INKERNEL_RULE_DENY:
        strcat (m_logstring,  "deny\n" );
        break;
    case GLOBAL_RULE_DENY:
        strcat (m_logstring, "(global rule) deny \n");
        break;
    case SOCKET_NOT_FOUND_IN_PROCPIDFD:
        strcat (m_logstring,  "(no process associated with packet) drop\n" );
        break;
    case DSTPORT_NOT_FOUND_IN_PROC:
    case PORT_NOT_FOUND_IN_PROCNET:
        strcat (m_logstring,  "(no process associated with port) drop\n" );
        break;
    case FRONTEND_NOT_LAUNCHED:
        strcat (m_logstring, "(frontend not active) drop\n" );
        break;
    case FRONTEND_BUSY:
        strcat (m_logstring, "(frontend busy) drop\n" );
        break;
    case UNSUPPORTED_PROTOCOL:
        strcat (m_logstring, "(unsupported protocol) drop\n" );
        break;
    case ICMP_MORE_THAN_ONE_ENTRY:
        strcat (m_logstring, "More than one program is using icmp, dropping\n" );
        break;
    case ICMP_NO_ENTRY:
        strcat (m_logstring, "icmp packet received by there is no icmp entry in /proc. Very unusual. Please report\n" );
        break;
    case SHA_DONT_MATCH:
        strcat (m_logstring, "Red alert. Some app is trying to impersonate another\n" );
        break;
    case SPOOFED_PID:
        strcat (m_logstring, "Attempt to spoof PID detected\n" );
        break;
    case EXESIZE_DONT_MATCH:
        strcat (m_logstring, "Red alert. Executable's size don't match the records\n" );
        break;
    case EXE_HAS_BEEN_CHANGED:
        strcat (m_logstring, "While process was running, someone changed his binary file on disk. Definitely an attempt to compromise the firewall\n" );
        break;
    case SRCPORT_NOT_FOUND_IN_PROC:
        strcat (m_logstring, "(source port not found in procfs) drop\n" );
        break;
    case INKERNEL_SOCKET_NOT_FOUND:
        strcat (m_logstring, "(no process associated with socket) drop\n" );
        break;
    case INKERNEL_IPADDRESS_NOT_IN_DLIST:
        strcat (m_logstring, "(kernel process without a rule) drop\n" );
        break;
    case SOCKET_ZERO_BUT_UID_NOT_ZERO:
        strcat (m_logstring, "(socket==0 but uid!=0) drop\n" );
        break;
    case SOCKET_CHANGED_FROM_ZERO:
        strcat (m_logstring, "(socket changed from zero while we were scanning) drop\n" );
        break;
    default:
        strcat (m_logstring, "unknown verdict detected \n" );
        printf ("verdict No %d \n", verdict);
        break;
    }
    M_PRINTF(MLOG_TRAFFIC, "%s", m_logstring);
}

int socket_handle_icmp(int *nfmark_to_set, char *path, char *pid, unsigned long long *stime)
{
    int retval;
    long socket;
    retval = icmp_check_only_one_socket ( &socket );
    if (retval != ICMP_ONLY_ONE_ENTRY) {
        return retval;
    }
    retval = socket_active_processes_search ( &socket, path, pid, nfmark_to_set );
    if (retval != SOCKET_ACTIVE_PROCESSES_NOT_FOUND) {
        return retval;
    }
    retval = socket_procpidfd_search ( &socket, path, pid, stime );
    if (retval != SOCKET_FOUND_IN_PROCPIDFD) {
        return retval;
    }
    retval = path_find_in_ruleslist (nfmark_to_set, path, pid, stime);
    return retval;
}

int inkernel_get_verdict(const char *ipaddr, int *nfmark)
{
    pthread_mutex_lock(&dlist_mutex);
    ruleslist *rule = first_rule;
    while(rule->next != NULL)
    {
        rule = rule->next;
        if (strcmp(rule->path, KERNEL_PROCESS)) continue;
        else if (!strcmp(rule->pid, ipaddr))
        {
            if (!strcmp(rule->perms, ALLOW_ALWAYS) || !strcmp(rule->perms, ALLOW_ONCE))
            {
                rule->is_active = TRUE;
                *nfmark = rule->nfmark_out;
                pthread_mutex_unlock(&dlist_mutex);
                return INKERNEL_RULE_ALLOW;
            }
            else if (!strcmp(rule->perms, DENY_ALWAYS) || !strcmp(rule->perms, DENY_ONCE))
            {
                pthread_mutex_unlock(&dlist_mutex);
                return INKERNEL_RULE_DENY;
            }
        }
    }
    pthread_mutex_unlock(&dlist_mutex);
    //not found in in-kernel list
    return INKERNEL_IPADDRESS_NOT_IN_DLIST;
}

int  nfq_handle_gid ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
    struct iphdr *ip;
    int id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( ph ) id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );

    char daddr[INET_ADDRSTRLEN], saddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->saddr), saddr, INET_ADDRSTRLEN);

    //source and destination ports in host and net byte order
    int sport_netbo, dport_netbo, sport_hostbo, dport_hostbo;
    int proto;
    int verdict;
    switch ( ip->protocol )
    {
    case IPPROTO_TCP:
        proto = PROTO_TCP;
        // ihl is IP header length in 32bit words, multiply a word by 4 to get length in bytes
        struct tcphdr *tcp;
        tcp = ( struct tcphdr* ) ( (char*)ip + ( 4 * ip->ihl ) );
        sport_netbo = tcp->source;
        dport_netbo = tcp->dest;
        sport_hostbo = ntohs ( tcp->source );
        dport_hostbo = ntohs ( tcp->dest );
        break;

    case IPPROTO_UDP:
        proto = PROTO_UDP;
        struct udphdr *udp;
        udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
        sport_netbo = udp->source;
        dport_netbo = udp->dest;
        sport_hostbo = ntohs ( udp->source );
        dport_hostbo = ntohs ( udp->dest );
        break;

    default:
        M_PRINTF ( MLOG_INFO, "IN unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
        M_PRINTF ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet \n" );
    }

    verdict = GID_MATCH_ALLOW;
    //print_traffic_log(proto, DIRECTION_IN, saddr, sport_hostbo, dport_hostbo, path, pid, verdict);
    if (verdict == GID_MATCH_ALLOW)
    {
        printf ("allowed gid match /n");
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

        nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_DST, ip->daddr);
        nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_SRC, ip->saddr);
        nfct_set_attr_u8 (ct_in, ATTR_L4PROTO, ip->protocol);
        nfct_set_attr_u8 (ct_in, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u16(ct_in, ATTR_PORT_SRC, sport_netbo);
        nfct_set_attr_u16(ct_in, ATTR_PORT_DST, dport_netbo) ;

        nfmark_to_set_in = 22222;
        //EBUSY returned, when there's too much activity in conntrack. Requery the packet
        while (nfct_query(setmark_handle_in, NFCT_Q_GET, ct_in) == -1)
        {
            if (errno == EBUSY)
            {
                M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            if (errno == EILSEQ)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            else
            {
                M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
        }
        return 0;
    }
    else if (verdict == GID_MATCH_DENY)
    {
        printf ("denied gid match /n");
        denied_traffic_add(DIRECTION_IN, 22222, ip->tot_len );
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
    else
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
}

int  nfq_handle_in ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
    pthread_mutex_lock(&lastpacket_mutex);
    gettimeofday(&lastpacket, NULL);
    pthread_mutex_unlock(&lastpacket_mutex);

    struct iphdr *ip;
    int id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( ph ) id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );

    char daddr[INET_ADDRSTRLEN], saddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->saddr), saddr, INET_ADDRSTRLEN);

    int verdict;
    //source and destination ports in host and net byte order
    int sport_netbo, dport_netbo, sport_hostbo, dport_hostbo;
    char path[PATHSIZE] = {0}, pid[PIDLENGTH] = {0};
    unsigned long long starttime;
    int proto;
    long socket;
    switch ( ip->protocol )
    {
    case IPPROTO_TCP:
        proto = PROTO_TCP;
        // ihl is IP header length in 32bit words, multiply a word by 4 to get length in bytes
        struct tcphdr *tcp;
        tcp = ( struct tcphdr* ) ( (char*)ip + ( 4 * ip->ihl ) );
        sport_netbo = tcp->source;
        dport_netbo = tcp->dest;
        sport_hostbo = ntohs ( tcp->source );
        dport_hostbo = ntohs ( tcp->dest );

        if ((socket = is_tcp_port_in_cache(& dport_hostbo)) == -1) //not found in cache
        {
            //No need to rebuild the cache b/c likelihood is very high that port is not there
			// NEW: Rebuild cache to allow us to SSH back in
			// TODO: Does this need to be for UDP so that DNS masquarade daemon works?

			if (build_tcp_port_and_socket_cache(&socket, &dport_hostbo) == -1)
			{
				if (build_tcp6_port_and_socket_cache(&socket, &dport_hostbo) == -1)
				{
					//the packet has no inode associated with it
					verdict = DSTPORT_NOT_FOUND_IN_PROC;
					break;
				}
			}
        }
        if (socket == 0) {
            verdict = inkernel_check_tcp(&dport_hostbo);
            if (verdict == INKERNEL_SOCKET_FOUND) {
                verdict = inkernel_get_verdict(saddr, &nfmark_to_set_in);
            }
            else break;
        }
        else {
            fe_was_busy_in = awaiting_reply_from_fe? TRUE: FALSE;
            verdict = socket_handle_tcp_in ( &socket, &nfmark_to_set_in, path, pid, &starttime );
        }
        verdict = global_rules_filter(DIRECTION_IN, PROTO_TCP, dport_hostbo, verdict);
        if (verdict == PATH_IN_DLIST_NOT_FOUND)
        {
            if (fe_was_busy_in)
            {
                verdict = FRONTEND_BUSY;
            }
            else
            {
                verdict = fe_active_flag_get() ? fe_ask_in(path,pid,&starttime, saddr, &sport_hostbo, &dport_hostbo ) : FRONTEND_NOT_LAUNCHED;
            }
        }
        break;

    case IPPROTO_UDP:
        proto = PROTO_UDP;
        struct udphdr *udp;
        udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
        sport_netbo = udp->source;
        dport_netbo = udp->dest;
        sport_hostbo = ntohs ( udp->source );
        dport_hostbo = ntohs ( udp->dest );

        if ((socket = is_udp_port_in_cache(& dport_hostbo)) == -1) //not found in cache
        {
            verdict = DSTPORT_NOT_FOUND_IN_PROC;
            break;
        }
        if (socket == 0) {
            verdict = inkernel_check_tcp(&dport_hostbo);
            if (verdict == INKERNEL_SOCKET_FOUND) {
                verdict = inkernel_get_verdict(daddr, &nfmark_to_set_in);
            }
            else break;
        }
        else {
            fe_was_busy_in = awaiting_reply_from_fe? TRUE: FALSE;
            verdict = socket_handle_udp_in ( &socket, &nfmark_to_set_in, path, pid, &starttime );
        }
        verdict = global_rules_filter(DIRECTION_IN, PROTO_UDP, dport_hostbo, verdict);

        if (verdict == PATH_IN_DLIST_NOT_FOUND)
        {
            if (fe_was_busy_in)
            {
                verdict = FRONTEND_BUSY;
            }
            else
            {
                verdict = fe_active_flag_get() ? fe_ask_in(path,pid,&starttime, saddr, &sport_hostbo, &dport_hostbo ) : FRONTEND_NOT_LAUNCHED;
            }
        }
        break;

    /* Receiving incoming icmp connections should be done on the kernel level
        case IPPROTO_ICMP:
          M_PRINTF ( MLOG_TRAFFIC, ">ICMP src %s ", saddr);
          fe_was_busy_in = awaiting_reply_from_fe? TRUE: FALSE;
          if ((verdict = packet_handle_icmp (&nfmark_to_set_in, path, pid, &starttime )) == GOTO_NEXT_STEP)
            {
              if (fe_was_busy_in)
                {
                  verdict = FRONTEND_BUSY;
                  break;
                }
    	  else verdict = fe_active_flag_get() ? fe_ask_in(path,pid,&starttime, saddr, sport_hostbo, dport_hostbo) : FRONTEND_NOT_LAUNCHED;
            }
          break;
     */
    default:
        M_PRINTF ( MLOG_INFO, "IN unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
        M_PRINTF ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet \n" );
        verdict = UNSUPPORTED_PROTOCOL;
    }

    print_traffic_log(proto, DIRECTION_IN, saddr, sport_hostbo, dport_hostbo, path, pid, verdict);
    if (verdict < ALLOW_VERDICT_MAX)
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

        nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_DST, ip->daddr);
        nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_SRC, ip->saddr);
        nfct_set_attr_u8 (ct_in, ATTR_L4PROTO, ip->protocol);
        nfct_set_attr_u8 (ct_in, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u16(ct_in, ATTR_PORT_SRC, sport_netbo);
        nfct_set_attr_u16(ct_in, ATTR_PORT_DST, dport_netbo) ;

        //EBUSY returned, when there's too much activity in conntrack. Requery the packet
        while (nfct_query(setmark_handle_in, NFCT_Q_GET, ct_in) == -1)
        {
            if (errno == EBUSY)
            {
                M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            if (errno == EILSEQ)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            else
            {
                M_PRINTF ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
        }
        return 0;
    }
    else if (verdict < DENY_VERDICT_MAX)
    {
        denied_traffic_add(DIRECTION_IN, nfmark_to_set_in, ip->tot_len );
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
    else
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
}

void check_address_rules(const int proto, int* verdict, char* path, char* daddr) {
	// do nothing if were we
	//if(strcmp(path, "/home/after/leopardflower-code/lpfw") == 0)
	//	return;

	// Do address-specific filtering
	//M_PRINTF(MLOG_DEBUG, "Checking for %s in addr rules\n", path);
	if(g_key_file_has_group(addressRules, path)) {
		M_PRINTF(MLOG_INFO, "==> %d %s Found rules for \"%s\" in address rules\n", proto, daddr, path);

		if(g_key_file_has_key(addressRules, path, "Rules", NULL)) {
			M_PRINTF(MLOG_INFO, "=> Checking Allow rules...\n");

			gsize strings_length = 0;
			gchar** addr_strings = g_key_file_get_string_list(addressRules, path, "Rules",
				&strings_length, NULL);
			int string_cnt;
			int matched = 0;

			for(string_cnt = 0; string_cnt < strings_length; string_cnt++) {
				int dest_verdict = 0;
				char* verdict_name = NULL;

				if(addr_strings[string_cnt][0] == '!') {
					// deny
					addr_strings[string_cnt]++;
					dest_verdict = PATH_FOUND_IN_DLIST_DENY;
					verdict_name = "DENY";

					M_PRINTF(MLOG_INFO, "checking: deny %s\n", addr_strings[string_cnt]);
				} else {
					// allow
					M_PRINTF(MLOG_INFO, "checking: allow %s\n", addr_strings[string_cnt]);
					dest_verdict = PATH_FOUND_IN_DLIST_ALLOW;
					verdict_name = "ALLOW";
				}

				if(g_hostname_is_ip_address(addr_strings[string_cnt])) {
					if(strcmp(daddr, addr_strings[string_cnt]) == 0) {
						M_PRINTF(MLOG_INFO, "Destination address \"%s\" matches rule address \"%s\" - %s\n",
							daddr, addr_strings[string_cnt], verdict_name);
						*verdict = dest_verdict;
						matched = 1;
						break;
					}
				} else {
					// TODO: The bellow commented out crud can be removed
					/*
					gchar* argv[4];
					argv[0] = "/usr/bin/dig";
					argv[1] = "+short";
					argv[2] = addr_strings[string_cnt];
					argv[3] = NULL;
					gboolean ret;
					gchar *rebind_stdout = NULL;
					gint exit_status = 0;
					GError* error = NULL;

					ret = g_spawn_sync(NULL, argv, NULL,  G_SPAWN_STDERR_TO_DEV_NULL,
						 NULL, NULL, &rebind_stdout, NULL, &exit_status, &error);

					M_PRINTF(MLOG_DEBUG, "OUTPUT: %s\n", rebind_stdout);
					*/


					// get ip from hostname
					// TODO: This is set up for IPv4 for now.. coult be expanded to work with ipv6
					struct addrinfo hints, *result = NULL;
					struct addrinfo *res = NULL;
					memset (&hints, 0, sizeof (hints));
					hints.ai_family = AF_INET;
					//hints.ai_socktype = SOCK_DGRAM;
					if(proto == PROTO_TCP)
						hints.ai_protocol = IPPROTO_TCP;
					else if(proto == PROTO_UDP)
						hints.ai_protocol = IPPROTO_UDP;
					//hints.ai_flags = AI_ADDRCONFIG;

/*
					struct hostent * he;
					he = gethostbyname("google.com");
					M_PRINTF(MLOG_DEBUG, "After GHHHHHH\n");
					*/


					//pthread_mutex_lock(&lastpacket_mutex);
					if(getaddrinfo(addr_strings[string_cnt], NULL, &hints, &result) == 0) {
						for (res = result; res != NULL; res = res->ai_next) {
							struct sockaddr_in  *sockaddr_ipv4;
							sockaddr_ipv4 = (struct sockaddr_in *)res->ai_addr;
							char ipaddr[32];
							sprintf(ipaddr, "%s", inet_ntoa(sockaddr_ipv4->sin_addr));
							if(strcmp(daddr, ipaddr) == 0) {
								M_PRINTF(MLOG_INFO, "Destination address \"%s\" matches rule address \"%s\" (hostname %s) - %s\n",
									daddr, ipaddr, addr_strings[string_cnt], verdict_name);
								*verdict = dest_verdict;
								matched = 1;
								break;
							} else {
								M_PRINTF(MLOG_INFO, "Checked dest %s against rule address %s\n", daddr, ipaddr);
							}
						}
					}
					//pthread_mutex_unlock(&lastpacket_mutex);
				}

				if(matched)
					break;
			}

			if(!matched) {
				M_PRINTF(MLOG_INFO, "Tested all rules, no match - deny\n");
				*verdict = PATH_FOUND_IN_DLIST_DENY;
			}
		}
	}
}

int  nfq_handle_out_rest ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
    pthread_mutex_lock(&lastpacket_mutex);
    gettimeofday(&lastpacket, NULL);
    pthread_mutex_unlock(&lastpacket_mutex);

    struct iphdr *ip;
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( !ph )
    {
        printf ("ph == NULL, should never happen, please report");
        return 0;
    }
    id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
    char daddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
    int verdict;
    char path[PATHSIZE], pid[PIDLENGTH];
    unsigned long long stime;
    switch (ip->protocol)
    {
    case IPPROTO_ICMP:
        fe_was_busy_out = awaiting_reply_from_fe? TRUE: FALSE;
        verdict = socket_handle_icmp (&nfmark_to_set_out_icmp, path, pid, &stime );
        if (verdict  == PATH_IN_DLIST_NOT_FOUND)
        {
            if (fe_was_busy_out)
            {
                verdict = FRONTEND_BUSY;
                break;
            }
            else {
                if (fe_active_flag_get()) {
                    int zero = 0;
                    verdict = fe_ask_out(path,pid,&stime, daddr, &zero, &zero);
                }
                else {
                    verdict = FRONTEND_NOT_LAUNCHED;
                }
            }
        }
        break;
    default:
        M_PRINTF ( MLOG_INFO, "OUT unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
        M_PRINTF ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet \n" );
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }

    if (verdict < ALLOW_VERDICT_MAX)
		check_address_rules(PROTO_ICMP, &verdict, &path, &daddr);

    print_traffic_log(PROTO_ICMP, DIRECTION_OUT, daddr, 0, 0, path, pid, verdict);
    if (verdict < ALLOW_VERDICT_MAX)
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        return 0;

//Fix assigning icmp mark when Netfilter devs reply to my mailing list post
        nfct_set_attr_u32(ct_out_icmp, ATTR_ORIG_IPV4_DST, ip->daddr);
        nfct_set_attr_u32(ct_out_icmp, ATTR_ORIG_IPV4_SRC, ip->saddr);
        nfct_set_attr_u8 (ct_out_icmp, ATTR_L4PROTO, ip->protocol);
        nfct_set_attr_u8 (ct_out_icmp, ATTR_L3PROTO, AF_INET);
        // nfct_set_attr_u16(ct_out_icmp, ATTR_PORT_SRC, sport_netbyteorder);
        // nfct_set_attr_u16(ct_out_icmp, ATTR_PORT_DST, dport_netbyteorder) ;

        //EBUSY returned, when there's too much activity in conntrack. Requery the packet
        while (nfct_query(setmark_handle_out_icmp, NFCT_Q_GET, ct_out_icmp) == -1)
        {
            if (errno == EBUSY)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            if (errno == EILSEQ)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            else
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
        }


    }
    //else if verdict > ALLOW_VERDICT_MAX
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
    return 0;
}

int  nfq_handle_out_udp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
    pthread_mutex_lock(&lastpacket_mutex);
    gettimeofday(&lastpacket, NULL);
    pthread_mutex_unlock(&lastpacket_mutex);

    struct iphdr *ip;
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( !ph )
    {
        printf ("ph == NULL, should never happen, please report");
        return 0;
    }
    id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
    char daddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
    int verdict;
    u_int16_t sport_netbyteorder, dport_netbyteorder;
    char path[PATHSIZE]= {0}, pid[PIDLENGTH]= {0};
    unsigned long long starttime;

    struct udphdr *udp;
    udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
    sport_netbyteorder = udp->source;
    dport_netbyteorder = udp->dest;
    int srcudp = ntohs ( udp->source );
    int dstudp = ntohs ( udp->dest );

    long socket_found;
    if ((socket_found = is_udp_port_in_cache(&srcudp)) == -1) //not found in cache
    {
        struct timespec timer,dummy;
        timer.tv_sec=0;
        timer.tv_nsec=1000000000/2;
        nanosleep(&timer, &dummy);

        if (build_udp_port_and_socket_cache(&socket_found, &srcudp) == -1)
        {
            if (build_udp6_port_and_socket_cache(&socket_found, &srcudp) == -1)
            {
                //the packet has no inode associated with it
                verdict = PORT_NOT_FOUND_IN_PROCNET;
                goto execute_verdict;
            }
        }
    }

    if (socket_found == 0) {
        verdict = inkernel_check_udp(&srcudp);
        if (verdict == INKERNEL_SOCKET_FOUND) {
            verdict = inkernel_get_verdict(daddr, &nfmark_to_set_out_udp);
        }
        else {
            goto execute_verdict;
        }
    }
    else {
        //remember f/e's state before we process
        fe_was_busy_out = awaiting_reply_from_fe? TRUE: FALSE;
        verdict = socket_handle_udp_out ( &socket_found, &nfmark_to_set_out_udp, path, pid, &starttime );
    }

	// TODO: shouldnt PROTO_TCP say PROTO_UDP?
    verdict = global_rules_filter(DIRECTION_OUT, PROTO_TCP, dstudp, verdict);

    if (verdict == PATH_IN_DLIST_NOT_FOUND)
    {
        if (fe_was_busy_out)
        {
            verdict = FRONTEND_BUSY;
        }
        else
        {
            verdict = fe_active_flag_get() ? fe_ask_out(path,pid,&starttime, daddr, &srcudp, &dstudp)
                      : FRONTEND_NOT_LAUNCHED;
        }
    }

execute_verdict:
    if (verdict < ALLOW_VERDICT_MAX)
		check_address_rules(PROTO_UDP, &verdict, &path, &daddr);

    print_traffic_log(PROTO_UDP, DIRECTION_OUT, daddr, srcudp, dstudp, path, pid, verdict);
    if (verdict < ALLOW_VERDICT_MAX)
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

        nfct_set_attr_u32(ct_out_udp, ATTR_ORIG_IPV4_DST, ip->daddr);
        nfct_set_attr_u32(ct_out_udp, ATTR_ORIG_IPV4_SRC, ip->saddr);
        nfct_set_attr_u8 (ct_out_udp, ATTR_L4PROTO, ip->protocol);
        nfct_set_attr_u8 (ct_out_udp, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u16(ct_out_udp, ATTR_PORT_SRC, sport_netbyteorder);
        nfct_set_attr_u16(ct_out_udp, ATTR_PORT_DST, dport_netbyteorder) ;

        //EBUSY returned, when there's too much activity in conntrack. Requery the packet
        while (nfct_query(setmark_handle_out_udp, NFCT_Q_GET, ct_out_udp) == -1)
        {
            if (errno == EBUSY)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            if (errno == EILSEQ)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            else
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
        }

        return 0;
    }
    else if (verdict < DENY_VERDICT_MAX)
    {
        denied_traffic_add(DIRECTION_OUT, nfmark_to_set_out_udp, ip->tot_len );
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
    else
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
}

int  nfq_handle_out_tcp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
    pthread_mutex_lock(&lastpacket_mutex);
    gettimeofday(&lastpacket, NULL);
    pthread_mutex_unlock(&lastpacket_mutex);

    struct iphdr *ip;
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( !ph )
    {
        printf ("ph == NULL, should never happen, please report");
        return 0;
    }
    id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
    char daddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
    int verdict;
    u_int16_t sport_netbyteorder, dport_netbyteorder;
    char path[PATHSIZE]= {0}, pid[PIDLENGTH]= {0};
    unsigned long long starttime;

    // ihl field is IP header length in 32-bit words, multiply by 4 to get length in bytes
    struct tcphdr *tcp;
    tcp = ( struct tcphdr* ) ((char*)ip + ( 4 * ip->ihl ) );
    sport_netbyteorder = tcp->source;
    dport_netbyteorder = tcp->dest;
    int srctcp = ntohs ( tcp->source );
    int dsttcp = ntohs ( tcp->dest );

    long socket_found;
    if ((socket_found = is_tcp_port_in_cache(&srctcp)) == -1) //not found in cache
    {
        struct timespec timer,dummy;
        timer.tv_sec=0;
        timer.tv_nsec=1000000000/2;
        nanosleep(&timer, &dummy);

        if (build_tcp_port_and_socket_cache(&socket_found, &srctcp) == -1)
        {
            if (build_tcp6_port_and_socket_cache(&socket_found, &srctcp) == -1)
            {
                //the packet has no inode associated with it
                verdict = PORT_NOT_FOUND_IN_PROCNET;
                goto execute_verdict;
            }
        }
    }
    if (socket_found == 0) {
        verdict = inkernel_check_tcp(&srctcp);
        if (verdict == INKERNEL_SOCKET_FOUND) {
            verdict = inkernel_get_verdict(daddr, &nfmark_to_set_out_tcp);
        }
        else {
            goto execute_verdict;
        }
    }
    else {
        //remember f/e's state before we process
        fe_was_busy_out = awaiting_reply_from_fe? TRUE: FALSE;
        verdict = socket_handle_tcp_out ( &socket_found, &nfmark_to_set_out_tcp, path, pid, &starttime );
    }

    verdict = global_rules_filter(DIRECTION_OUT, PROTO_TCP, dsttcp, verdict);

    if (verdict == PATH_IN_DLIST_NOT_FOUND)
    {
        if (fe_was_busy_out)
        {
            verdict = FRONTEND_BUSY;
        }
        else
        {
            verdict = fe_active_flag_get() ? fe_ask_out(path,pid,&starttime, daddr, &srctcp, &dsttcp)
                      : FRONTEND_NOT_LAUNCHED;
        }
    }

execute_verdict:
    if (verdict < ALLOW_VERDICT_MAX)
		check_address_rules(PROTO_TCP, &verdict, &path, &daddr);

    print_traffic_log(PROTO_TCP, DIRECTION_OUT, daddr, srctcp, dsttcp, path, pid, verdict);

    if (verdict < ALLOW_VERDICT_MAX)
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );

        nfct_set_attr_u32(ct_out_tcp, ATTR_ORIG_IPV4_DST, ip->daddr);
        nfct_set_attr_u32(ct_out_tcp, ATTR_ORIG_IPV4_SRC, ip->saddr);
        nfct_set_attr_u8 (ct_out_tcp, ATTR_L4PROTO, ip->protocol);
        nfct_set_attr_u8 (ct_out_tcp, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u16(ct_out_tcp, ATTR_PORT_SRC, sport_netbyteorder);
        nfct_set_attr_u16(ct_out_tcp, ATTR_PORT_DST, dport_netbyteorder) ;

        //EBUSY returned, when there's too much activity in conntrack. Requery the packet
        while (nfct_query(setmark_handle_out_tcp, NFCT_Q_GET, ct_out_tcp) == -1)
        {
            if (errno == EBUSY)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            if (errno == EILSEQ)
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
            else
            {
                M_PRINTF ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
            }
        }

        return 0;
    }
    else if (verdict < DENY_VERDICT_MAX)
    {
        denied_traffic_add(DIRECTION_OUT, nfmark_to_set_out_tcp, ip->tot_len );
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
    else
    {
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
    }
}

void init_log()
{

    if ( !strcmp ( logging_facility->sval[0], "file" ) )
    {
//         if (log_info->ival) {
//             if ((fileloginfofd = fopen(log_file->filename[0], "w")) == 0) perror("fopen");
//         }
//         if (log_traffic->ival) {
//             if ((filelogtrafficfd = fopen(log_file->filename[0], "w")) == 0) perror("fopen");
//         }
//         if (log_debug->ival) {
//             if ((filelogdebugfd = fopen(log_file->filename[0], "w")) == 0) perror("fopen");
//         };

//all chennels log to the same file, if need be the commented section above can be used to specify separate files
        fileloginfo_stream = fopen (log_file->filename[0], "w" );
        filelogtraffic_stream = fileloginfo_stream;
        filelogdebug_stream = fileloginfo_stream;
        m_printf = &m_printf_file;
        return;
    }
    else if ( !strcmp ( logging_facility->sval[0], "stdout" ) )
    {
        m_printf = &m_printf_stdout;
        return;
    }
#ifndef WITHOUT_SYSLOG
    else if ( !strcmp ( logging_facility->sval[0], "syslog" ) )
    {
        openlog ( "lpfw", 0, 0 );
        m_printf = &m_printf_syslog;
    }
#endif
}

void pidfile_check()
{
    FILE *pidfd , *procfd, *newpid;
    char pidbuf[8], procstring[20], procbuf[20], pid2str[8], *ptr;
    const char srchstr[2] = {0x0A, 0};
    int pid, newpidfd;
    ssize_t size;

    if (access ( pid_file->filename[0], F_OK ) == 0) {
        pidfd = fopen (pid_file->filename[0], "r");
        fgets (pidbuf, 8, pidfd);
        fclose (pidfd);
        pidbuf[7] = 0;
        pid = atoi ( pidbuf );
        if ( pid > 0 )
        {
            if ( kill ( pid, 0 ) == 0 ) //PID is running
            {
                // check that this pid belongs to lpfw
                strcpy ( procstring, "/proc/" );
                strcat ( procstring, pidbuf );
                strcat ( procstring, "/comm" );
                procfd = fopen (procstring, "r");
                //let's replace 0x0A with 0x00
                fgets (procbuf, 19, procfd);
                fclose (procfd);
                ptr = strstr ( procbuf, srchstr );
                *ptr = 0;
                //compare the actual string, if found => carry on
                if ( !strcmp ( "lpfw", procbuf ) )
                {
                    //make sure that the running instance is NOT our instance
                    //(can happen when PID of previously crashed lpfw coincides with ours)
                    if ( ( pid_t ) pid != getpid() )
                    {
                        M_PRINTF ( MLOG_INFO, "lpfw is already running\n" );
                        exit(0);
                    }
                }
            }
        }
    }

    //else if pidfile doesn't exist/contains dead PID, create/truncate it and write our pid into it
    newpid = fopen (pid_file->filename[0], "w");

    sprintf ( pid2str, "%d", ( int ) getpid() );
    newpidfd = fileno(newpid);
    size = write (newpidfd, pid2str, 8);
    fclose (newpid);
}

//initiate message queue and send to first lpfw instance, our pid, tty and display and quit.
//Obsolete because frontend now starts independently
int frontend_mode ( int argc, char *argv[] )
{
    key_t ipckey;
    int mqd;
    msg_struct_creds msg;
    //remove memory garbage
    memset (&msg, 0, sizeof(msg_struct_creds));
    msg.type = 1;


    ipckey = ftok (TMPFILE, FTOKID_CREDS );
    mqd = msgget (ipckey, 0 );

    if ( ( msg.item.uid = getuid() ) == 0 )
    {
#ifndef DEBUG
        printf ( "You are trying to run lpfw's frontend as root. Such possibility is disabled due to securitty reasons. Please rerun as a non-priviledged user\n" );
        return -1;
#endif
    }

    strncpy ( msg.item.tty, ttyname ( 0 ), TTYNAME - 1 );
    if ( !strncmp ( msg.item.tty, "/dev/tty", 8 ) )
    {
        printf ( "You are trying to run lpfw's frontend from a tty terminal. Such possibility is disabled in this version of lpfw due to security reasons. Try to rerun this command from within an X terminal\n" );
        return -1;
    }

    char *display;
    display = getenv ("DISPLAY" );
    strncpy ( msg.item.display, display, DISPLAYNAME - 1 );

    int cli_args; //number of arguments that need to be passed to frontend
    cli_args = argc-2; //first two parms are path and --cli/--gui/--guipy
    strncpy (msg.item.params[0], argv[1], 16);

    int i =0;
    if ( cli_args > 0 && cli_args < 5 ) //4 parms max - the last parm should be 0
    {
        msg.item.params[1][0] = cli_args; //first parm has the total number of parms for lpfwcli (itself excluding)
        for ( i=0; i<cli_args; ++i )
        {
            strncpy ( msg.item.params[i+2], argv[2+i], 16 );
        }
    }
    msg.item.params[i+2][0] = 0; //the last parm should be 0

    msgsnd ( mqd, &msg, sizeof ( msg.item ), 0);

    //we need to sleep a little because lpfw is extracting out path from /proc/PID/exe
    //if we quit immediately, this information won't be available
    sleep ( 3 );
    return 0;
}

void SIGTERM_handler ( int signal )
{
    remove ( pid_file->filename[0] );
    rulesfileWrite();
    //release netfilter_queue resources
    nfq_close ( globalh_out_tcp );
    nfq_close ( globalh_out_udp );
}

/*command line parsing contributed by Ramon Fried*/
int parse_command_line(int argc, char* argv[])
{
    // if the parsing of the arguments was unsuccessful
    int nerrors;

    // Define argument table structs
    logging_facility = arg_str0 ( NULL, "logging-facility",
#ifndef WITHOUT_SYSLOG
                                  "<file>,<stdout>,<syslog>"
#else
                                  "<file>,<stdout>"
#endif
                                  , "Divert logging to..." );
    rules_file = arg_file0 ( NULL, "rules-file", "<path to file>", "Rules output file" );
    pid_file = arg_file0 ( NULL, "pid-file", "<path to file>", "PID output file" );
    log_file = arg_file0 ( NULL, "log-file", "<path to file>", "Log output file" );
    allow_rule = arg_file0 ( NULL, "addrule", "<path to executable>", "Add executable to rulesfile as ALLOW ALWAYS" );


#ifndef WITHOUT_SYSVIPC
    cli_path = arg_file0 ( NULL, "cli-path", "<path to file>", "Path to CLI frontend" );
    pygui_path = arg_file0 ( NULL, "pygui-path", "<path to file>", "Path to Python-based GUI frontend" );
#endif

    log_info = arg_int0 ( NULL, "log-info", "<1/0 for yes/no>", "Info messages logging" );
    log_traffic = arg_int0 ( NULL, "log-traffic", "<1/0 for yes/no>", "Traffic logging" );
    log_debug = arg_int0 ( NULL, "log-debug", "<1/0 for yes/no>", "Debug messages logging" );
    test = arg_lit0 ( NULL, "test", "Run unit test" );

    struct arg_lit *help = arg_lit0 ( NULL, "help", "Display help screen" );
    struct arg_lit *version = arg_lit0 ( NULL, "version", "Display the current version" );
    struct arg_end *end = arg_end ( 30 );
    void *argtable[] = {logging_facility, rules_file, pid_file, log_file, cli_path,
                        pygui_path, log_info, log_traffic, log_debug, allow_rule, help, version,
                        test, end
                       };

    // Set default values
    char *stdout_pointer;
    stdout_pointer = malloc(strlen("stdout")+1);
    strcpy (stdout_pointer, "stdout");
    logging_facility->sval[0] = stdout_pointer;

    char *rulesfile_pointer;
    rulesfile_pointer = malloc(strlen(RULESFILE)+1);
    strcpy (rulesfile_pointer, RULESFILE);
    rules_file->filename[0] = rulesfile_pointer;

    char *pidfile_pointer;
    pidfile_pointer = malloc(strlen(PIDFILE)+1);
    strcpy (pidfile_pointer, PIDFILE);
    pid_file->filename[0] = pidfile_pointer;

    char *lpfw_logfile_pointer;
    lpfw_logfile_pointer = malloc(strlen(LPFW_LOGFILE)+1);
    strcpy (lpfw_logfile_pointer, LPFW_LOGFILE);
    log_file->filename[0] = lpfw_logfile_pointer;

    cli_path->filename[0] = CLI_FILE;
    pygui_path->filename[0] = GUI_FILE;

    * ( log_info->ival ) = 1;
    * ( log_traffic->ival ) = 1;
#ifdef DEBUG
    * ( log_debug->ival ) = 1;
#else
    * ( log_debug->ival ) = 0;
#endif

    if ( arg_nullcheck ( argtable ) != 0 )
    {
        printf ( "Error: insufficient memory\n" );
        exit(0);
    }

    nerrors = arg_parse ( argc, argv, argtable );

    if ( nerrors == 0 )
    {
        if ( help->count == 1 )
        {
            printf ( "Leopard Flower:\n Syntax and help:\n" );
            arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
            exit (0);
        }
        else if ( version->count == 1 )
        {
            printf ( "%s\n", VERSION );
            exit (0);
        }
        else if (allow_rule->count == 1)
        {
            add_to_rulesfile(allow_rule->filename[0]);
            exit(0);
        }
        else if (test->count == 1) //log traffic to a separate file
        {
            char *file_pointer = malloc(strlen("file")+1);
            strcpy (file_pointer, "file");
            logging_facility->sval[0] = file_pointer;

            * ( log_traffic->ival ) = 1;

            char *log_file_pointer = malloc(strlen(TEST_TRAFFIC_LOG)+1);
            strcpy (log_file_pointer, TEST_TRAFFIC_LOG);
            log_file->filename[0] = TEST_TRAFFIC_LOG;
        }
    }
    else if ( nerrors > 0 )
    {
        arg_print_errors ( stdout, end, "Leopard Flower" );
        printf ( "Leopard Flower:\n Syntax and help:\n" );
        arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
        exit (1);
    }

    // Free memory - don't do this cause args needed later on
    //  arg_freetable(argtable, sizeof (argtable) / sizeof (argtable[0]));
}

//add an executable (from command line) with ALLOW ALWAYS permissions
void add_to_rulesfile(const char *exefile_path)
{
    FILE *exefile_stream, *rulesfile_stream;
    unsigned char sha[DIGEST_SIZE];
    struct stat exestat;
    char size[16];
    unsigned char shastring[DIGEST_SIZE * 2 + 1] = "";
    unsigned char shachar[3] = "";
    int i;

    access (exefile_path, R_OK);
    exefile_stream = fopen (exefile_path, "r");
    sha512_stream ( exefile_stream, ( void * ) sha );
    fclose (exefile_stream);

    stat (exefile_path, &exestat);
    sprintf(size, "%d", (int)exestat.st_size);

    //Open rules file and add to the bottom of it
    if ( access ( rules_file->filename[0], F_OK ) == -1 ) {
        printf ( "CONFIG doesnt exist..creating" );
        rulesfile_stream = fopen (rules_file->filename[0], "w");
    }
    else {
        rulesfile_stream = fopen (rules_file->filename[0], "a");
    }

    fseek (rulesfile_stream, 0, SEEK_END);
    fputs (exefile_path, rulesfile_stream);
    fputc ('\n', rulesfile_stream);
    fputs (ALLOW_ALWAYS, rulesfile_stream);
    fputc ('\n', rulesfile_stream);
    fputs (size, rulesfile_stream);
    fputc ('\n', rulesfile_stream);

    for ( i = 0; i < DIGEST_SIZE; ++i ) {
        //pad single digits with a leading zero
        sprintf ( shachar, "%02x", sha[i] );
        strcat ( shastring, shachar );
    }
    shastring[DIGEST_SIZE * 2] = 0;

    fputs (shastring, rulesfile_stream);
    fputc ('\n', rulesfile_stream);
    fputc ('\n', rulesfile_stream);
    fclose (rulesfile_stream);
}


void capabilities_setup()
{
    //=======  Capabilities check
    cap_t cap_current;
    cap_flag_value_t value;

    cap_current = cap_get_proc();

    cap_get_flag(cap_current, CAP_SYS_PTRACE, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_SYS_PTRACE is not permitted \n");
        exit(0);
    }
    cap_get_flag(cap_current, CAP_NET_ADMIN, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_NET_ADMIN is not permitted \n");
        exit(0);
    }
    cap_get_flag(cap_current, CAP_DAC_READ_SEARCH, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_DAC_READ_SEARCH is not permitted \n");
        exit(0);
    }
    cap_get_flag(cap_current, CAP_SETUID, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_SETUID is not permitted \n");
        exit(0);
    }
    cap_get_flag(cap_current, CAP_SETGID, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_SETGID is not permitted \n");
        exit(0);
    }
    cap_get_flag(cap_current, CAP_CHOWN, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_CHOWN is not permitted \n");
        exit(0);
    }
    cap_get_flag(cap_current, CAP_FSETID, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_FSETID is not permitted \n");
        exit(0);
    }
    cap_get_flag(cap_current, CAP_KILL, CAP_PERMITTED, &value);
    if (value == CAP_CLEAR)
    {
        printf ("CAP_KILL is not permitted \n");
        exit(0);
    }

    cap_clear(cap_current);
    const cap_value_t caps_list[] = {CAP_SYS_PTRACE, CAP_NET_ADMIN, CAP_DAC_READ_SEARCH, CAP_SETUID, CAP_SETGID, CAP_CHOWN, CAP_FSETID, CAP_KILL};
    cap_set_flag(cap_current, CAP_PERMITTED, 8, caps_list, CAP_SET);
    cap_set_proc(cap_current);

#ifdef DEBUG
    cap_t cap;
    cap = cap_get_proc();
    printf("Running with capabilities: %s\n", cap_to_text(cap, NULL));
    cap_free(cap);
#endif
}

void setgid_lpfwuser()
{
    gid_t lpfwuser_gid;
    //First we need to create/(check existence of) lpfwuser group and add ourselves to it
    errno = 0;
    struct group *m_group;
    m_group = getgrnam("lpfwuser");
    if (!m_group)
    {
        if (errno == 0)
        {
            printf("lpfwuser group does not exist, creating...\n");
            if (system("groupadd lpfwuser") == -1)
            {
                printf("error in system(groupadd)\n");
                return;
            }
            //get group id again after group creation
            errno = 0;
            m_group = getgrnam("lpfwuser");
            if(!m_group)
            {
                if (errno == 0)
                {
                    printf ("lpfwuser group still doesn't exist even though we've just created it");
                }
                else
                {
                    perror ("getgrnam");
                }
            }
            lpfwuser_gid = m_group->gr_gid;
        }
        else
        {
            printf("Error in getgrnam\n");
            perror ("getgrnam");
        }
        return;
    }
    //when debugging, we add user who launches frontend to lpfwuser group, hence disable this check
#ifndef DEBUG
    if (!(m_group->gr_mem[0] == NULL))
    {
        printf ("lpfwuser group contains users. This group should not contain any users. This is a security issue. Please remove all user from that group and restart application. Exitting\n");
        exit(0);
    }
#endif
    lpfwuser_gid = m_group->gr_gid;

    capabilities_modify(CAP_SETGID, CAP_EFFECTIVE, CAP_SET);

    //setgid and immediately remove CAP_SETGID from both perm. and eff. sets
    if (setgid(lpfwuser_gid) == -1)
    {
        printf("setgid: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        return;
    }

    capabilities_modify(CAP_SETGID, CAP_EFFECTIVE, CAP_CLEAR);
    capabilities_modify(CAP_SETGID, CAP_PERMITTED, CAP_CLEAR);
}

void setuid_root()
{
    capabilities_modify(CAP_SETUID, CAP_EFFECTIVE, CAP_SET);

    //setuid and immediately remove CAP_SETUID from both perm. and eff. sets
    if (setuid(0) == -1)
    {
        perror ("setuid ");
        return;
    }
    //we still neet to setuid in fe_reg_thread so leave this CAP in permitted set
    //cap_set_flag(cap_current,  CAP_PERMITTED, 1, caps_list, CAP_CLEAR);
    capabilities_modify(CAP_SETUID, CAP_EFFECTIVE, CAP_CLEAR);
}

void setup_signal_handlers()
{
    //install SIGTERM handler
    struct sigaction sa;
    sa.sa_handler = SIGTERM_handler;
    sigemptyset ( &sa.sa_mask );
    if ( sigaction ( SIGTERM, &sa, NULL ) == -1 )
    {
        perror ( "sigaction" );
    }
}

#if 0
//OBSOLETE - frontend starts standalone and there is no need to track its path
void save_own_path()
{
    int ownpid = getpid();
    char ownpidstr[16];
    sprintf(ownpidstr, "%d", ownpid );
    char exepath[PATHSIZE] = "/proc/";
    strcat(exepath, ownpidstr);
    strcat(exepath, "/exe");
    memset(ownpath,0,PATHSIZE);
    readlink(exepath,ownpath,PATHSIZE-1);

    int basenamelength;
    basenamelength = strlen ( strrchr ( ownpath, '/' ) +1 );
    strncpy ( owndir, ownpath, strlen ( ownpath )-basenamelength );
}
#endif

//check periodically if iptables rules were changed by another process
void* iptables_check_thread (void *ptr)
{
    struct stat mstat;
    int fd_output, fd_input, fd_newoutput, fd_newinput;
    char *addr_output, *addr_input, *addr_newoutput, *addr_newinput;
    int size_output, size_input, size_newoutput, size_newinput;
    char save_output[MAX_LINE_LENGTH] = "iptables -L OUTPUT > ";
    char save_input[MAX_LINE_LENGTH] = "iptables -L INPUT >";
    strcat (save_output, SAVE_IPTABLES_OUTPUT_FILE);
    strcat (save_input, SAVE_IPTABLES_INPUT_FILE);

    //commit to memory the contents of the files
    fd_output = open(SAVE_IPTABLES_OUTPUT_FILE, O_RDONLY);
    stat (SAVE_IPTABLES_OUTPUT_FILE , &mstat);
    size_output = mstat.st_size;
    addr_output = mmap (0, size_output, PROT_READ, MAP_PRIVATE, fd_output, 0);
    close (fd_output);

    fd_input = open(SAVE_IPTABLES_INPUT_FILE, O_RDONLY);
    stat (SAVE_IPTABLES_INPUT_FILE , &mstat);
    size_input = mstat.st_size;
    addr_input = mmap (0, size_input, PROT_READ, MAP_PRIVATE, fd_input, 0);
    close (fd_input);

    while (1)
    {
        sleep(3);
        system (save_output);
        system (save_input);

        fd_newoutput = open(SAVE_IPTABLES_OUTPUT_FILE, O_RDONLY);
        stat (SAVE_IPTABLES_OUTPUT_FILE , &mstat);
        size_newoutput = mstat.st_size;
        addr_newoutput = mmap (0, size_newoutput, PROT_READ, MAP_PRIVATE, fd_newoutput, 0);
        close (fd_newoutput);

        fd_newinput = open(SAVE_IPTABLES_INPUT_FILE, O_RDONLY);
        stat (SAVE_IPTABLES_INPUT_FILE , &mstat);
        size_newinput = mstat.st_size;
        addr_newinput = mmap (0, size_newinput, PROT_READ, MAP_PRIVATE, fd_newinput, 0);
        close (fd_newinput);

        int i,j;
        if (size_output != size_newoutput) goto alarm;
        if (size_input != size_newinput) goto alarm;
        if (i = memcmp(addr_output, addr_newoutput, size_output)) goto alarm;
        if (j = memcmp(addr_input, addr_newinput, size_input)) goto alarm;

        munmap (addr_newoutput, size_newoutput);
        munmap (addr_newinput, size_newinput);
    }
alarm:
    printf ("IPTABLES RULES CHANGE DETECTED\n");
    printf ("Leopard Flower (LF) has detected that some other process has changed\n");
    printf ("iptables rules. Applications like Firestarter and NetworkManager\n");
    printf ("are known to change iptables rules. Since LF relies heavily on iptables,\n");
    printf ("most likely LF will not work correctly until it is restarted.\n");
    printf ("It is advised that you terminate LF.\n");
}

void init_iptables()
{
    pthread_t iptables_check;
    char save_output[MAX_LINE_LENGTH] = "iptables -L OUTPUT > ";
    char save_input[MAX_LINE_LENGTH] = "iptables -L INPUT >";

    //system("iptables -F INPUT");
    //system ("iptables -F OUTPUT");
    system ("iptables -I OUTPUT 1 -m state --state NEW -j NFQUEUE --queue-num 11223");
    system ("iptables -I OUTPUT 1 -p tcp -m state --state NEW -j NFQUEUE --queue-num 11220");
    system ("iptables -I OUTPUT 1 -p udp -m state --state NEW -j NFQUEUE --queue-num 11222");
    system ("iptables -I INPUT 1 -m state --state NEW -j NFQUEUE --queue-num 11221");
    //_system ("iptables -I OUTPUT 1 -m state --state NEW -m owner --gid-owner lpfwuser2 -j NFQUEUE --queue-num 22222");
    system ("iptables -I OUTPUT 1 -d localhost -j ACCEPT");
    system ("iptables -I INPUT 1 -d localhost -j ACCEPT");
    //save and start checking if iptables rules altered
    strcat (save_output, SAVE_IPTABLES_OUTPUT_FILE);
    strcat (save_input, SAVE_IPTABLES_INPUT_FILE);
    system (save_output);
    system (save_input);
    pthread_create ( &iptables_check, NULL, iptables_check_thread, NULL);
}

void init_nfq_handlers()
{
    struct nfq_q_handle * globalqh_tcp, * globalqh_udp, * globalqh_rest, * globalqh_input, * globalqh_gid;
    //-----------------Register OUT TCP queue handler-------------
    globalh_out_tcp = nfq_open ();
    nfq_unbind_pf (globalh_out_tcp, AF_INET );
    nfq_bind_pf (globalh_out_tcp, AF_INET );
    globalqh_tcp = nfq_create_queue (globalh_out_tcp, NFQNUM_OUTPUT_TCP,
                                     &nfq_handle_out_tcp, NULL );
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    nfq_set_mode (globalqh_tcp, NFQNL_COPY_PACKET, 40 );
    nfq_set_queue_maxlen (globalqh_tcp, 200 );
    nfqfd_tcp = nfq_fd ( globalh_out_tcp);
    M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------

    //-----------------Register OUT UDP queue handler-------------
    globalh_out_udp = nfq_open ();
    nfq_unbind_pf (globalh_out_udp, AF_INET );
    nfq_bind_pf (globalh_out_udp, AF_INET );
    globalqh_udp = nfq_create_queue (globalh_out_udp, NFQNUM_OUTPUT_UDP,
                                     &nfq_handle_out_udp, NULL );
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    nfq_set_mode (globalqh_udp, NFQNL_COPY_PACKET, 40 );
    nfq_set_queue_maxlen (globalqh_udp, 200 );
    nfqfd_udp = nfq_fd ( globalh_out_udp);
    M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------

    //-----------------Register OUT REST queue handler-------------
    globalh_out_rest = nfq_open ();
    nfq_unbind_pf (globalh_out_rest, AF_INET );
    nfq_bind_pf (globalh_out_rest, AF_INET );
    globalqh_rest = nfq_create_queue (globalh_out_rest, NFQNUM_OUTPUT_REST,
                                      &nfq_handle_out_rest, NULL );
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    nfq_set_mode (globalqh_rest, NFQNL_COPY_PACKET, 40 );
    nfq_set_queue_maxlen (globalqh_rest, 200 );
    nfqfd_rest = nfq_fd ( globalh_out_rest);
    M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------

    //-----------------Register IN queue handler-------------
    globalh_in = nfq_open ();
    nfq_unbind_pf (globalh_in, AF_INET );
    nfq_bind_pf (globalh_in, AF_INET );
    globalqh_input = nfq_create_queue (globalh_in, NFQNUM_INPUT,
                                       &nfq_handle_in, NULL );
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    nfq_set_mode (globalqh_input, NFQNL_COPY_PACKET, 40 );
    nfq_set_queue_maxlen (globalqh_input, 30 );
    nfqfd_input = nfq_fd ( globalh_in);
    M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------

    //-----------------Register GID queue handler-------------
    globalh_gid = nfq_open ();
    nfq_unbind_pf (globalh_gid, AF_INET );
    nfq_bind_pf (globalh_gid, AF_INET );
    globalqh_gid = nfq_create_queue (globalh_gid, NFQNUM_GID,
                                     &nfq_handle_gid, NULL );
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    nfq_set_mode (globalqh_gid, NFQNL_COPY_PACKET, 40 );
    nfq_set_queue_maxlen (globalqh_gid, 30 );
    nfqfd_gid = nfq_fd ( globalh_gid);
    M_PRINTF ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------
}

void init_ruleslist()
{
    //initialze dlist first(reference) element
    if ( ( first_rule = ( ruleslist * ) malloc ( sizeof ( ruleslist ) ) ) == NULL )
    {
        M_PRINTF ( MLOG_INFO, "malloc: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        exit(0);
    }
    first_rule->prev = NULL;
    first_rule->next = NULL;
    first_rule->rules_number = 1;
}

void open_proc_net_files()
{
    tcpinfo = fopen (TCPINFO, "r");
    tcp6info = fopen (TCP6INFO, "r");
    udpinfo = fopen (UDPINFO, "r");
    udp6info = fopen (UDP6INFO, "r");

    procnetrawfd = open ("/proc/net/raw", O_RDONLY );
    tcpinfo_fd = fileno(tcpinfo);
    tcp6info_fd = fileno(tcp6info);
    udpinfo_fd = fileno(udpinfo);
    udp6info_fd = fileno(udp6info);
}

void chown_and_setgid_frontend()
{
    char system_call_string[PATHSIZE];

    //TODO check if we really need those 2 caps, maybe _CHOWN is enough.
    capabilities_modify(CAP_CHOWN, CAP_EFFECTIVE, CAP_SET);
    capabilities_modify(CAP_FSETID, CAP_EFFECTIVE, CAP_SET);
    capabilities_modify(CAP_DAC_READ_SEARCH, CAP_EFFECTIVE, CAP_SET);

    strcpy (system_call_string, "chown :lpfwuser ");
    strncat (system_call_string, cli_path->filename[0], PATHSIZE-20);
    system (system_call_string);

    strcpy (system_call_string, "chmod g+s ");
    strncat (system_call_string, cli_path->filename[0], PATHSIZE-20);
    system (system_call_string);

    strcpy (system_call_string, "chown :lpfwuser ");
    strncat (system_call_string, pygui_path->filename[0], PATHSIZE-20);
    system (system_call_string);

    strcpy (system_call_string, "chmod g+s ");
    strncat (system_call_string, pygui_path->filename[0], PATHSIZE-20);
    system (system_call_string);

    capabilities_modify(CAP_CHOWN, CAP_EFFECTIVE, CAP_CLEAR);
    capabilities_modify(CAP_CHOWN, CAP_PERMITTED, CAP_CLEAR);
    capabilities_modify(CAP_FSETID, CAP_EFFECTIVE, CAP_CLEAR);
    capabilities_modify(CAP_FSETID, CAP_PERMITTED, CAP_CLEAR);
}


int main ( int argc, char *argv[] )
{
    struct rlimit core_limit;
    core_limit.rlim_cur = RLIM_INFINITY;
    core_limit.rlim_max = RLIM_INFINITY;
    if(setrlimit(RLIMIT_CORE, &core_limit) < 0) {
        printf("setrlimit: %s\nWarning: core dumps may be truncated or non-existant\n", strerror(errno));
    }


#ifndef WITHOUT_SYSVIPC
    //argv[0] is the  path of the executable
    if ( argc >= 2 ) {
        if (!strcmp (argv[1],"--cli")  || !strcmp(argv[1],"--gui") || !strcmp(argv[1],"--pygui")) {
            return frontend_mode ( argc, argv );
        }
    }
#endif

    if (argc == 2 && ( !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version"))) {
        parse_command_line(argc, argv);
        return 0;
    }

    capabilities_setup();
    setuid_root();
    setgid_lpfwuser();
    if (prctl(PR_SET_DUMPABLE, 1) == -1) {
        perror("prctl SET_DUMPABLE");
    }
    setup_signal_handlers();

    parse_command_line(argc, argv);
    chown_and_setgid_frontend();
    init_log();
    pidfile_check();
    capabilities_modify(CAP_NET_ADMIN, CAP_EFFECTIVE, CAP_SET);
    init_conntrack();
    init_iptables();

#ifdef DEBUG
    uid_t uid, euid;
    uid = getuid();
    euid = geteuid();
    printf (" orig uid euid %d %d \n", uid, euid);
#endif

    capabilities_modify(CAP_DAC_READ_SEARCH, CAP_EFFECTIVE, CAP_SET);
    capabilities_modify(CAP_SYS_PTRACE, CAP_EFFECTIVE, CAP_SET);


#ifndef WITHOUT_SYSVIPC
    init_msgq();
#endif

    init_nfq_handlers();
    init_ruleslist();
	init_address_rules();
    rules_load();
    open_proc_net_files();

    pthread_create ( &refresh_thr, NULL, refresh_thread, NULL );
    pthread_create ( &cache_build_thr, NULL, build_pid_and_socket_cache, NULL);
    pthread_create ( &ct_dump_thr, NULL, ct_dump_thread, NULL );
    pthread_create ( &ct_destroy_hook_thr, NULL, ct_destroy_thread, NULL);
    pthread_create ( &ct_delete_nfmark_thr, NULL, ct_delete_mark_thread, NULL);
    pthread_create ( &frontend_poll_thr, NULL, frontend_poll_thread, NULL);

    pthread_create ( &nfq_in_thr, NULL, nfq_in_thread, NULL);
    pthread_create ( &nfq_out_udp_thr, NULL, nfq_out_udp_thread, NULL);
    pthread_create ( &nfq_out_rest_thr, NULL, nfq_out_rest_thread, NULL);
    pthread_create ( &nfq_gid_thr, NULL, nfq_gid_thread, NULL);

#ifdef DEBUG
    pthread_create ( &rules_dump_thr, NULL, rules_dump_thread, NULL );
#endif

    if (test->count == 1) {
        pthread_create ( &unittest_thr, NULL, unittest_thread, NULL );
    }

    //endless loop of receiving packets and calling a handler on each packet
    int rv;
    char buf[4096] __attribute__ ( ( aligned ) );
    while ( ( rv = recv ( nfqfd_tcp, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
        nfq_handle_packet ( globalh_out_tcp, buf, rv );
    }
}

// kate: indent-mode cstyle; space-indent on; indent-width 4;
