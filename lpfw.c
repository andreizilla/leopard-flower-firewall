#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h> //required for netfilter.h
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h> //for malloc
#include <ctype.h> // for toupper
#include <unistd.h>
#include <signal.h>
#include <stdarg.h> //for dynamic arguments
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <arpa/inet.h> //for ntohl()
#include <linux/netfilter.h> //for NF_ACCEPT, NF_DROP etc
#include <assert.h>
#include "includes.h"
#include "defines.h"
#include "argtable/argtable2.h"
#include "version.h" //for version string during packaging

//should be available globally to call nfq_close from sigterm handler
struct nfq_handle *globalh_out, *globalh_in;

//command line arguments available globally
struct arg_str *ipc_method, *logging_facility, *frontend;
struct arg_file *rules_file, *pid_file, *log_file, *cli_path, *gui_path, *guipy_path;
struct arg_int *log_info, *log_traffic, *log_debug;

char ownpath[PATHSIZE]; //full path of lpfw executable
char owndir[PATHSIZE]; //full path to the dir lpfw executable is in (with trailing /)

FILE *fileloginfo_stream, *filelogtraffic_stream, *filelogdebug_stream;

//first element of dlist is an empty one,serves as reference to determine the start of dlist
dlist *first, *copy_first;

//first item of sockets cache list
char *first_cache;

//type has to be initialized to one, otherwise if it is 0 we'll get EINVAL on msgsnd
msg_struct msg_d2f = {1, 0};
msg_struct msg_f2d = {1, 0};   
msg_struct msg_d2fdel = {1, 0};
msg_struct msg_d2flist = {1, 0};
msg_struct_creds msg_creds = {1, 0};

extern int fe_ask_out ( char*, char*, unsigned long long* );
extern int fe_ask_in(char *path, char *pid, unsigned long long *stime, char *ipaddr, int sport, int dport);
extern int fe_list();
extern void msgq_init();
extern int sha512_stream ( FILE *stream, void *resblock );
extern int fe_awaiting_reply;

//Forward declarations to make code parser happy
void dlist_add ( char *path, char *pid, char *perms, mbool current, char *sha, unsigned long long stime, off_t size, int nfmark, unsigned char first_instance );
int ( *m_printf ) ( int loglevel, char *format, ... );

//mutex to access dlist
pthread_mutex_t dlist_mutex = PTHREAD_MUTEX_INITIALIZER;
//mutex to access nfmark_count from main thread and commandthread
pthread_mutex_t nfmark_count_mutex = PTHREAD_MUTEX_INITIALIZER;
//mutex to avoid fe_ask_* to send data simultaneously
pthread_mutex_t msgq_mutex = PTHREAD_MUTEX_INITIALIZER;
//mutex to lock fe_active_flag
pthread_mutex_t fe_active_flag_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

//thread which listens for command and thread which scans for rynning apps and removes them from the dlist
pthread_t refresh_thread, rulesdump_thread, nfqinput_thread, cachebuild_thread;
pthread_t ct_del_thread;

//flag which shows whether frontend is running
int fe_active_flag = 0;
//fe_was_busy is a flag to know whether frontend was processing some request
//Normally, if path is not found in dlist, we send a request to frontend
//But in case it was busy when we started iterating dlist, we assume FRONTEND_BUSY
//This prevents possible duplicate entries in dlist
int fe_was_busy_in, fe_was_busy_out;

//netfilter mark number for the packet (to be added to NF_MARK_BASE)
int nfmark_count = 0;
//netfilter mark to be put on an ALLOWed packet
int nfmark_to_set_out, nfmark_to_set_in, nfmark_to_delete;

char* tcp_membuf, *tcp6_membuf, *udp_membuf, *udp6_membuf; //MEMBUF_SIZE to fread /tcp/net/* in one swoop
FILE *tcpinfo, *tcp6info, *udpinfo, *udp6info;
int procnetrawfd;
struct nf_conntrack *ct_out, *ct_in;
struct nfct_handle *dummy_handle;
struct nfct_handle *setmark_handle_out, *setmark_handle_in;

int nfqfd_input;

pthread_cond_t condvar = PTHREAD_COND_INITIALIZER;
pthread_mutex_t condvar_mutex = PTHREAD_MUTEX_INITIALIZER;
char predicate = FALSE;

int delete_mark(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data){
    //while(1){printf("DELMARK");}
  if (nfct_get_attr_u32(mct, ATTR_MARK) == nfmark_to_delete){
      if (nfct_query(dummy_handle, NFCT_Q_DESTROY, mct) == -1){
	m_printf ( MLOG_DEBUG, "nfct_query DESTROY %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return NFCT_CB_CONTINUE;
      }
      m_printf ( MLOG_DEBUG, "deleted entry %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return NFCT_CB_CONTINUE;
  }
  return NFCT_CB_CONTINUE;
}

void* ct_delthread ( void* ptr )
{
    u_int8_t family = AF_INET; //used by conntrack
    struct nfct_handle *deletemark_handle;
    if ((deletemark_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL){perror("nfct_open");}
    if ((nfct_callback_register(deletemark_handle, NFCT_T_ALL, delete_mark, NULL) == -1)) {perror("cb_reg");}

    while(1){
	pthread_mutex_lock(&condvar_mutex);
	while(predicate == FALSE){
	    pthread_cond_wait(&condvar, &condvar_mutex);
	}
	predicate = FALSE;
	pthread_mutex_unlock(&condvar_mutex);
	if (nfct_query(deletemark_handle, NFCT_Q_DUMP, &family) == -1){perror("query-DELETE");}
    }
}



int setmark_out (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data){
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_out);
  nfct_query(setmark_handle_out, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

int setmark_in (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data){
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_in);
  nfct_query(setmark_handle_in, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

void  initialize_conntrack(){
   if ((ct_out = nfct_new()) == NULL){perror("new");}
   if ((ct_in = nfct_new()) == NULL){perror("new");}
   if ((dummy_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL){perror("nfct_open");}
   if ((setmark_handle_out = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL){ perror("nfct_open");}
   if ((setmark_handle_in = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL){ perror("nfct_open");}
   if ((nfct_callback_register(setmark_handle_out, NFCT_T_ALL, setmark_out, NULL) == -1)) {perror("cb_reg");}
   if ((nfct_callback_register(setmark_handle_in, NFCT_T_ALL, setmark_in, NULL) == -1)) {perror("cb_reg");}
   return;
}

void child_close_nfqueue()
{
    nfq_close( globalh_out )?
    m_printf ( MLOG_INFO,"error in nfq_close\n" ):
    m_printf ( MLOG_DEBUG, "Done closing nfqueue\n" );
    return;
}

void fe_active_flag_set ( int boolean )
{
    pthread_mutex_lock ( &fe_active_flag_mutex );
    fe_active_flag = boolean;
    pthread_mutex_unlock ( &fe_active_flag_mutex );
}

int fe_active_flag_get()
{
    int temp;
    pthread_mutex_lock ( &fe_active_flag_mutex );
    temp = fe_active_flag;
    pthread_mutex_unlock ( &fe_active_flag_mutex );
    return temp;
}

void die()
{
    exit ( 0 );
}

int m_printf_stdout ( int loglevel, char * format, ... )
{
    va_list args;
    switch ( loglevel )
    {
    case MLOG_INFO:
        // check if INFO logging enabled
        if ( !* ( log_info->ival ) ) return 0;
        va_start ( args, format );
        vprintf ( format, args );
        //fsync(filelogfd);
        return 0;
    case MLOG_TRAFFIC:
        // check if  logging enabled
        if ( !* ( log_traffic->ival ) ) return 0;
        va_start ( args, format );
        vprintf ( format, args );
        //fsync(filelogfd);
        return 0;
    case MLOG_DEBUG:
        // check if  logging enabled
        if ( !* ( log_debug->ival ) ) return 0;
        va_start ( args, format );
        vprintf ( format, args );
        //fsync(filelogfd);
        return 0;
    case MLOG_DEBUG2:
#ifdef DEBUG2
	// check if  logging enabled
	va_start ( args, format );
	vprintf ( format, args );
	//fsync(filelogfd);
#endif
	return 0;
    case MLOG_DEBUG3:
#ifdef DEBUG3
	// check if  logging enabled
	va_start ( args, format );
	vprintf ( format, args );
	//fsync(filelogfd);
#endif
	return 0;
    case MLOG_ALERT: //Alerts get logged unconditionally to all log channels
        va_start ( args, format );
        printf ( "ALERT: " );
        vprintf ( format, args );
        return 0;
    }
}

//technically vfprintf followed by fsync should be enough, but for some reason on my system it can take more than 1 minute before data gets actually written to disk. So until the mystery of such a huge delay is solved, we use write() so data gets written to dist immediately
int m_printf_file ( int loglevel, char * format, ... )
{
    va_list args;
    char logstring[PATHSIZE*2]; //shaould be enough for the longest line in log
    switch ( loglevel )
    {
    case MLOG_INFO:
        // check if INFO logging enabled
        if ( !* ( log_info->ival ) ) return 0;
        va_start ( args, format );
        vsprintf ( logstring, format, args );
        write ( fileno ( fileloginfo_stream ), logstring, strlen ( logstring ) );
        return 0;
    case MLOG_TRAFFIC:
        if ( !* ( log_traffic->ival ) ) return 0;
        va_start ( args, format );
        vsprintf ( logstring, format, args );
        write ( fileno ( filelogtraffic_stream ), logstring, strlen ( logstring ) );
        return 0;
    case MLOG_DEBUG:
        if ( !* ( log_debug->ival ) ) return 0;
        va_start ( args, format );
        vsprintf ( logstring, format, args );
        write ( fileno ( filelogdebug_stream ), logstring, strlen ( logstring ) );
        return 0;
    case MLOG_ALERT: //Alerts get logged unconditionally to all log channels
        va_start ( args, format );
        write ( fileno ( filelogdebug_stream ), "ALERT: ", strlen ( logstring ) );

//         vfprintf ( fileloginfofd, format, args );
//         fprintf ( filelogtrafficfd, "ALERT: " );
//         vfprintf ( filelogtrafficfd, format, args );
//         fprintf ( filelogdebugfd, "ALERT: " );
//         vfprintf ( filelogdebugfd, format, args );
        return 0;
    }
}

int m_printf_syslog ( int loglevel, char *format, ... )
{
    va_list args;
    switch ( loglevel )
    {
    case MLOG_INFO:
        // check if INFO logging enabled
        if ( !* ( log_info->ival ) ) return 0;
        va_start ( args, format );
        vsyslog ( LOG_INFO, format, args );
        //fsync(filelogfd);
        return 0;
    case MLOG_TRAFFIC:
        if ( !* ( log_traffic->ival ) ) return 0;
        va_start ( args, format );
        vsyslog ( LOG_INFO, format, args );
        //fsync(filelogfd);
        return 0;
    case MLOG_DEBUG:
        if ( !* ( log_debug->ival ) ) return 0;
        va_start ( args, format );
        vsyslog ( LOG_INFO, format, args );
        //fsync(filelogfd);
        return 0;
    case MLOG_ALERT: //Alerts get logget unconditionally to all log channels
        va_start ( args, format );
        syslog ( LOG_INFO, "ALERT: " );
        vsyslog ( LOG_INFO, format, args );
        return 0;
    }
}

unsigned long long starttimeGet ( int mypid )
{
    char pidstring[8];
    char path[32] = "/proc/";
    sprintf ( pidstring, "%d", mypid );
    strcat ( path, pidstring );
    strcat ( path, "/stat" );

    int pid;
    char comm[1000];
    char state;
    int ppid, pgrd, session, tty_nr, tpgid;
    unsigned flags;
    unsigned long minflt, majflt, cmajflt, utime, stime;
    long int cutime, cstime, priority, nice;
    int unknown1, unknown2, unknown3;
    unsigned long long starttime;
    FILE *stream;

    if ( ( stream = fopen ( path, "r" ) ) == 0 )
    {
        m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return 1;
    };

    fscanf ( stream, "%d %s %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %ld %ld %ld %ld %d %d %d %llu",
             &pid, comm, &state, &ppid, &pgrd, &session, &tty_nr, &tpgid, &flags, &minflt, &majflt, &cmajflt, &utime,
             &stime, &cutime, &cstime, &priority, &nice, &unknown1, &unknown2, &unknown3, &starttime );

    fclose ( stream );
    return starttime;
}

//make a copy of dlist for future iterations. We don't iterate through dlist itself because that would require to lock a mutex for too long
dlist * dlist_copy()
{
    pthread_mutex_lock ( &dlist_mutex );
    dlist* del;
    dlist *temp = first->next;
    dlist *copy_temp = copy_first;
    while ( temp != 0 )
    {

        if ( !copy_temp->next )
        {
            //grow copy of dlist
            if ( ( copy_temp->next = malloc ( sizeof ( dlist ) ) ) == NULL )
            {
                m_printf ( MLOG_INFO, "malloc: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
                die();
            }
            copy_temp->next->prev = copy_temp;
            copy_temp->next->next = NULL;
        }
        copy_temp = copy_temp->next;
        copy_temp->path[0] = 0;
        strcpy ( copy_temp->path, temp->path );
        strcpy ( copy_temp->perms, temp->perms );
        strcpy ( copy_temp->pid, temp->pid );
	copy_temp->is_active = temp->is_active;

        temp = temp->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );
    //lets see if copy dlist needs to be shrunk
    copy_temp = copy_temp->next;
    while ( copy_temp != 0 )
    {
        del = copy_temp;
        //prev element should point not to us but to the next element
        copy_temp->prev->next = copy_temp->next;
        copy_temp = copy_temp->next;
        free ( del );
    }
    return copy_first;
}

//Add new element to dlist
void dlist_add ( char *path, char *pid, char *perms, mbool active, char *sha, unsigned long long stime, off_t size, int nfmark, unsigned char first_instance)
{
    pthread_mutex_lock ( &dlist_mutex );
    dlist *temp = first;

    if (!strcmp(path, KERNEL_PROCESS)){ //make sure it is not a duplicate from the user
	while ( temp->next != NULL ) //find a KERNEL PROCESS entry
	{
	    temp = temp->next;
	    if (strcmp(temp->path, KERNEL_PROCESS)) continue;
	    if (!strcmp(temp->pid, pid)){ //same IP, quit
		pthread_mutex_unlock ( &dlist_mutex );
		return;
	    }
	}
    }
    temp = first;
    //find the last element in dlist i.e. the one that has .next == NULL...
    while ( temp->next != NULL )
    {
        temp = temp->next;
    }
    //last element's .next should point now to our newly created one
    if ( ( temp->next = malloc ( sizeof ( dlist ) ) ) == NULL )
    {
        m_printf ( MLOG_INFO, "malloc: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
        die();
    }
    // new element's prev field should point to the former last element...
    temp->next->prev = temp;
    // point temp to the newly added element...
    temp = temp->next;
    //initialize fields
    temp->next = NULL;
    strcpy ( temp->path, path );
    strcpy ( temp->pid, pid );
    strcpy ( temp->perms, perms );
    temp->is_active = active;
    temp->stime = stime;
    assert(sha != NULL);
    memcpy ( temp->sha, sha, DIGEST_SIZE );
    temp->exesize = size;
    temp->nfmark = nfmark;
    temp->first_instance = first_instance; //obsolete member,can be purged
    if (temp->is_active && strcmp(temp->path, KERNEL_PROCESS)){
	strcpy(temp->pidfdpath,"/proc/");
	strcat(temp->pidfdpath, temp->pid);
	strcat(temp->pidfdpath, "/fd/");
	if ((temp->dirstream = opendir ( temp->pidfdpath )) == NULL){
	    m_printf ( MLOG_DEBUG, "opendir: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
	    exit(0);
	}
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
//	cache_temp->sockets[0][0] = CACHE_EOL_MAGIC;
//	pthread_mutex_unlock(&cache_mutex);
//    }
    if ((temp->sockets_cache = (int*)malloc(sizeof(int)*MAX_CACHE)) == NULL){perror("malloc");}
     *temp->sockets_cache = CACHE_EOL_MAGIC;
    pthread_mutex_unlock ( &dlist_mutex );
}

//Remove element from dlist...
void dlist_del ( char *path, char *pid )
{
    mbool was_active;
    pthread_mutex_lock ( &dlist_mutex );
    dlist *temp = first->next;
    while ( temp != NULL )
    {
        if ( !strcmp ( temp->path, path ) && !strcmp ( temp->pid, pid ) )
        {
//	    //remove cache entry first
//	    pthread_mutex_lock(&cache_mutex);
//	    cache_item *temp_cache;
//	    temp_cache = first_cache;
//	    while (temp_cache->next != NULL){
//		temp_cache = temp_cache->next;
//		if ( !(!strcmp ( temp_cache->path, path ) && !strcmp ( temp_cache->pid, pid )) ) continue;
//		//else found entry, remove it
//		temp_cache->prev->next = temp_cache->next;
//		if (temp_cache->next != NULL)
//		    temp_cache->next->prev = temp_cache->prev;
//		free(temp_cache);
//		goto cache_removed;
//	    }
//	    m_printf ( MLOG_INFO, "cache entry for %s with PID %s was not found. Needs investigation\n", path, pid );

//	    cache_removed:
//	    pthread_mutex_unlock(&cache_mutex);

            //remove the item
            temp->prev->next = temp->next;
            if ( temp->next != NULL )
                temp->next->prev = temp->prev;
            nfmark_to_delete = temp->nfmark;
	    was_active = temp->is_active;
            free ( temp );

	    //remove tracking for this app's active connection only if this app was active
	    if (was_active){
		pthread_mutex_lock(&condvar_mutex);
		predicate = TRUE;
		pthread_mutex_unlock(&condvar_mutex);
		pthread_cond_signal(&condvar);
	    }
	    pthread_mutex_unlock ( &dlist_mutex );
	    return;
        }
        temp = temp->next;
    }
    m_printf ( MLOG_INFO, "%s with PID %s was not found in dlist\n", path, pid );
    pthread_mutex_unlock ( &dlist_mutex );
}

int parsecache(int socket, char *path, char *pid){
    int i;
    int retval;
    dlist *temp;
    pthread_mutex_lock(&dlist_mutex);
    temp = first;
    while (temp->next != NULL){
	temp = temp->next;
	if(!temp->is_active) continue;
	i = 0;
	while (temp->sockets_cache[i] != CACHE_EOL_MAGIC){
	    if (i >= MAX_CACHE-1) break;
	    if (temp->sockets_cache[i] == socket){ //found match
		if (!strcmp(temp->perms, ALLOW_ONCE) || !strcmp(temp->perms, ALLOW_ALWAYS)) retval = CACHE_TRIGGERED_ALLOW;
		else retval = CACHE_TRIGGERED_DENY;
		strcpy(path, temp->path);
		strcpy(pid, temp->pid);
		pthread_mutex_unlock(&dlist_mutex);
		return retval;
	    }
	    i++;
	}
    }
    pthread_mutex_unlock(&dlist_mutex);
    return GOTO_NEXT_STEP;
}

void* cachebuildthread ( void *pid ){
    DIR *mdir;
    struct dirent *mdirent;
    int pathlen;
    char mpath[32];
    char buf[32];
    struct timespec refresh_timer,dummy;
    refresh_timer.tv_sec=0;
    refresh_timer.tv_nsec=1000000000/4;
    int i;
    dlist *temp;

    while(1){
	nanosleep(&refresh_timer, &dummy);
	pthread_mutex_lock(&dlist_mutex);
	temp = first;
	//cache only running PIDs && not kernel processes
	while (temp->next != NULL){
	    temp = temp->next;
	    if (!temp->is_active || !strcmp(temp->path, KERNEL_PROCESS)) continue;
	    pathlen = strlen(temp->pidfdpath);
	    strcpy(mpath, temp->pidfdpath);
	    rewinddir(temp->dirstream);
	    i = 0;
	    errno=0;
	    while (mdirent = readdir ( temp->dirstream )){
		mpath[pathlen]=0;
		strcat(mpath, mdirent->d_name);
		memset (buf, 0 , sizeof(buf));
		if (readlink ( mpath, buf, SOCKETBUFSIZE ) == -1){ //not a symlink but . or ..
		    errno=0;
		    continue; //no trailing 0
		}
		if (buf[7] != '[') continue; //not a socket
		char *end;
		end = strrchr(&buf[8],']'); //put 0 instead of ]
		*end = 0;
		temp->sockets_cache[i] = atoi(&buf[8]);
		i++;
	    }
	    temp->sockets_cache[i] = CACHE_EOL_MAGIC;
	    if (errno==0) {
		continue; //readdir reached EOF, thus errno hasn't changed from 0
	    }
		//else
	    perror("procdirent");
	}
	pthread_mutex_unlock(&dlist_mutex);
    }
}





void* nfqinputthread ( void *ptr )
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

void* rulesdumpthread ( void *ptr )
{
    ptr = 0;
    mkfifo ( "/tmp/lpfwrulesdump.fifo", 0777 );
    int fifofd;
    if ( ( fifofd = open ( "/tmp/lpfwrulesdump.fifo", O_RDWR ) ) == -1 )
    {
        perror ( "open fifo" );
    }

    char buf;
    int retval;
    while ( 1 )
    {
        if ( ( retval = read ( fifofd, &buf, 1 ) ) > 0 ) goto dump;
        sleep ( 1 );
        continue;
    dump:
        ;
        FILE *fd;
        if ( ( fd = fopen ( "/tmp/lpfwrulesdump.txt", "w" ) ) == NULL )
        {
            perror ( "open text" );
            continue;
        }

        dlist *temp;
        pthread_mutex_lock ( &dlist_mutex );
        temp = first->next;
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
            fputc ( '\n', fd );

            temp = temp->next;
        }
        pthread_mutex_unlock ( &dlist_mutex );
        fclose ( fd );
    }
}

//periodically scan running apps and remove from dlist those that are not running(if they are set to ALLOW/DENY ONCE)
void* refreshthread ( void* ptr )
{
    dlist *temp, *prev, *temp2;
    ptr = 0;     //to prevent gcc warnings of unused variable
    char mypath[32] = "/proc/";
    char buf[PATHSIZE];

    while ( 1 )
    {
        sleep ( 3 );
        pthread_mutex_lock ( &dlist_mutex );
        temp = first->next;
        while ( temp != NULL )
        {
	    //check if we have the processes actual PID and it is not a kernel process(it doesnt have a procfs entry)
	    if (!temp->is_active || !strcmp(temp->path, KERNEL_PROCESS))
            {
                temp = temp->next;
                continue;
            }

            mypath[6]=0;
            strcat ( mypath, temp->pid );
            strcat ( mypath, "/exe" );

            memset ( buf, 0, PATHSIZE );
            //readlink fails if PID doesnt exist
            //TODO process readlink's return value gracefully
            if ( readlink ( mypath, buf, PATHSIZE ) == -1 ) goto delete;
            //else PID exists, check if it doesnt belong to our process, then delete rule
            if ( strcmp ( buf, temp->path ) )
            {
            delete:
                //don't delete *ALWAYS rule. If it's the only rule for this PATH - just toggle the current_pid flag, otherwise if there are other entries for this PATH, then remove our rule
                if ( !strcmp ( temp->perms, ALLOW_ALWAYS ) || !strcmp ( temp->perms, DENY_ALWAYS ) )
                {
                    temp2 = first->next;
                    while ( temp2 != NULL ) //scan the whole dlist again
                    {
                        if ( !strcmp ( temp2->path, temp->path ) && ( temp2 != temp ) ) //to find a rule with the same PATH but make sure we don't find our own rule :)
                        {
                            goto still_delete;     //and delete it
                        }
                        temp2=temp2->next;
                        continue;
                    }
                    //we get here only if there was no PATH match
                    strcpy ( temp->pid, "0" );
		    temp->is_active = FALSE;
                    fe_list();
                    break;
                }
            still_delete:
                // TODO dlist_del is redundant we could keep a pointer to self in each dlist element and simply free(temp->self)
                // is there really a need for dlistdel? apart from the fact that frontend deletes by path :(
                pthread_mutex_unlock ( &dlist_mutex );
                dlist_del ( temp->path, temp->pid );
                //restore pointer to continue iteration
                //temp = prev;
                fe_list();
                break;
            }
            temp = temp->next;
        }
        pthread_mutex_unlock ( &dlist_mutex );
    }
}

//Read RULESFILE into dlist
void rules_load()
{
    FILE *stream;
    char path[PATHSIZE];
    char laststring[PATHSIZE];
    char line[PATHSIZE];
    char *result;
    char perms[PERMSLENGTH];
    char ip[INET_ADDRSTRLEN+1];//plus trailing /n and 0
    unsigned long sizeint;
    char sizestring[16];
    char shastring[DIGEST_SIZE * 2 + 2];
    struct stat m_stat;
    unsigned char digest[DIGEST_SIZE];
    unsigned char hexchar[3] = "";


    if ( stat ( rules_file->filename[0], &m_stat ) == -1 )
    {
        m_printf ( MLOG_INFO, "CONFIG doesnt exist..creating" );
        if ( ( stream = fopen ( rules_file->filename[0], "w+" ) ) == NULL )
        {
            m_printf ( MLOG_INFO, "malloc: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
            return;
        }
    }
    if ( ( stream = fopen ( rules_file->filename[0], "r" ) ) == NULL )
    {
        m_printf ( MLOG_INFO, "fopen RULESFILE: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return;
    }

    while ( 1 )
    {
	//fgets reads <newline> into the string and terminates with /0
        if ( fgets ( path, PATHSIZE, stream ) == 0 ) break;
        path[strlen ( path ) - 1] = 0; //remove newline
	if (!strcmp(path, KERNEL_PROCESS)){//separate treatment for kernel process
	    if ( fgets ( ip, INET_ADDRSTRLEN+1, stream ) == 0 ) break; //read IP address
	    ip[strlen ( ip ) - 1] = 0;
	    if ( fgets ( perms, PERMSLENGTH, stream ) == 0 ) break;
	    perms[strlen ( perms ) - 1] = 0;
	    if ( fgets ( laststring, PATHSIZE, stream ) == 0 ) break; //read last newline
	    dlist_add( path, ip , perms, FALSE, digest, 0, 0, 0, TRUE);
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

	dlist_add ( path, "0", perms, FALSE, digest, 2, ( off_t ) sizeint, 0, TRUE);
    }
    if ( fclose ( stream ) == EOF )
        m_printf ( MLOG_INFO, "fclose: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
}

//Write to RULESFILE only entries that have ALLOW/DENY_ALWAYS permissions
void rulesfileWrite()
{
    FILE *fd;
    struct stat m_stat;
    FILE *stream;
    int i;
    unsigned char shastring[DIGEST_SIZE * 2 + 1] = "";
    unsigned char shachar[3] = "";
    char sizestring[16];

    //rewrite/create the file regardless of whether it already exists
    if ( ( fd = fopen ( rules_file->filename[0], "w" ) ) == NULL )
    {
        m_printf ( MLOG_INFO, "open: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return;
    }

    pthread_mutex_lock ( &dlist_mutex );
    dlist* temp = first->next;
    dlist* temp2;

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
	    if (!strcmp(temp->path, KERNEL_PROCESS)){
		if ( fputs ( temp->path, fd ) == EOF )
		    m_printf ( MLOG_INFO, "fputs: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
		fputc ( '\n', fd );
		if ( fputs ( temp->pid, fd ) == EOF )
		    m_printf ( MLOG_INFO, "fputs: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
		fputc ( '\n', fd );
		if ( fputs ( temp->perms, fd ) == EOF )
		    m_printf ( MLOG_INFO, "fputs: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
		fputc ( '\n', fd );
		fputc ( '\n', fd );
		fsync ( fileno ( fd ) );
		temp = temp->next;
		continue;
	    }

            if ( fputs ( temp->path, fd ) == EOF )
                m_printf ( MLOG_INFO, "fputs: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
            fputc ( '\n', fd );
            fputs ( temp->perms, fd );
            fputc ( '\n', fd );
            sprintf ( sizestring, "%ld", ( long ) temp->exesize );
            fputs ( sizestring, fd );
            fputc ( '\n', fd );

            shastring[0] = 0;
            for ( i = 0; i < DIGEST_SIZE; ++i )
            {
                //pad single digits with a leading zero
                sprintf ( shachar, "%02x", temp->sha[i] );
                //The next line causes gdb to go nutty
                strcat ( shastring, shachar );
            }
            shastring[DIGEST_SIZE * 2] = 0;

            fputs ( shastring, fd );
            fputc ( '\n', fd );
	    fputc ( '\n', fd );


            //don't proceed until data is written to disk
            fsync ( fileno ( fd ) );
        }
        temp = temp->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );
    fclose ( fd );
}

//if path is in dlist already, check if it is fork()ed or a new instance
int path_find_in_dlist ( int *nfmark_to_set, char *path, char *pid, unsigned long long *stime )
{
    pthread_mutex_lock ( &dlist_mutex );
    //first check if app is already in our dlist
    dlist* temp = first->next;

    while ( temp != NULL )
    {
        if ( !strcmp ( temp->path, path ) )
        {
	    if (!temp->is_active) //path is in dlist and has not a current PID. It was added to dlist from rulesfile. Exesize and shasum this app just once
            {
                struct stat exestat;
                if ( stat ( temp->path, &exestat ) == -1 )
                {
                    //TODO fopen(path) for shasum below should be invoked right here to avoid the possibility of faking the executable
                    m_printf ( MLOG_INFO, "stat: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                }
                if ( temp->exesize != exestat.st_size )
                {
                    m_printf ( MLOG_INFO, "Exe sizes dont match. Impersonation attempt detected by %s in %s, %d\n", temp->path, __FILE__, __LINE__ );
                    pthread_mutex_unlock ( &dlist_mutex );
                    return EXESIZE_DONT_MATCH;
                }

                //TODO mutex will be held for way too long here, find a way to decrease time
                char sha[DIGEST_SIZE];
                FILE *stream;
                memset ( sha, 0, DIGEST_SIZE );
                stream = fopen ( path, "r" );
                sha512_stream ( stream, ( void * ) sha );
                fclose ( stream );
                if ( memcmp ( temp->sha, sha, DIGEST_SIZE ) )
                {
                    m_printf ( MLOG_INFO, "Shasums dont match. Impersonation attempt detected by %s in %s, %d\n", temp->path, __FILE__, __LINE__ );
                    pthread_mutex_unlock ( &dlist_mutex );
                    return SHA_DONT_MATCH;
                }

                strcpy ( temp->pid, pid ); //update entry's PID and inode
		temp->is_active = TRUE;
                temp->stime = *stime;
		strcpy(temp->pidfdpath,"/proc/");
		strcat(temp->pidfdpath, temp->pid);
		strcat(temp->pidfdpath, "/fd/");
		if ((temp->dirstream = opendir ( temp->pidfdpath )) == NULL){
		    m_printf ( MLOG_DEBUG, "opendir: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
		    exit(0);
		}

                int retval;
                if ( !strcmp ( temp->perms, ALLOW_ONCE ) || !strcmp ( temp->perms, ALLOW_ALWAYS ) )
                {
                    pthread_mutex_lock ( &nfmark_count_mutex );
                    temp->nfmark = NFMARK_BASE + nfmark_count;
                    *nfmark_to_set = NFMARK_BASE + nfmark_count;
		    nfmark_count++;
                    pthread_mutex_unlock ( &nfmark_count_mutex );

                    retval = PATH_FOUND_IN_DLIST_ALLOW;

                }
                else if ( !strcmp ( temp->perms, DENY_ONCE ) || !strcmp ( temp->perms, DENY_ALWAYS ) ){
                    retval = PATH_FOUND_IN_DLIST_DENY;
                }
                else
                {
                    m_printf ( MLOG_INFO, "should never get here. Please report %s,%d\n", __FILE__, __LINE__ );
                }
                pthread_mutex_unlock ( &dlist_mutex );
                //notify fe that the rule has an active PID now
                fe_list();
                return retval;
            }
	    else if ( temp->is_active )
            {

//determine if this is new instance or fork()d child
// --------------------------
// Here is how to determine if a process with the same PATH is either a new instance or a fork()ed process.
//
// 1. Get new process's(NP) PPID.
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
                    m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                    return PROCFS_ERROR;
                };

                char dummy1[32];
                char dummy2[32];
                char dummy3[32];
                char ppid[16];

                fscanf ( stream, "%s %s %s %s", dummy1, dummy2, dummy3, ppid );

//first copy parent's attributes

                char tempperms[PERMSLENGTH];
                char tempsha [DIGEST_SIZE];
                char temppid [PIDLENGTH-1];
                off_t parent_size = temp->exesize;
                unsigned long long saved_stime = temp->stime;
                strcpy ( tempperms, temp->perms );
                strcpy ( temppid, temp->pid );
                memcpy ( tempsha, temp->sha, DIGEST_SIZE );
                int tempnfmark = temp->nfmark;

//is it a fork()ed child? the "parent" above may not be the actual parent of this fork, e.g. there may be two or three instances of an app running aka three "parents". We have to rescan dlist to ascertain

                dlist * temp = first->next;
                while ( temp != NULL )
                {
                    if ( !strcmp ( temp->path, path ) && !strcmp ( temp->pid, ppid ) ) //we have a fork()ed child
                    {
                        int retval;
                        if ( !strcmp ( temp->perms, ALLOW_ALWAYS ) || !strcmp ( temp->perms, ALLOW_ONCE ) )
                        {
                            pthread_mutex_lock ( &nfmark_count_mutex );
                            temp->nfmark = NFMARK_BASE + nfmark_count;
                            *nfmark_to_set = NFMARK_BASE + nfmark_count;
                            nfmark_count++;
                            pthread_mutex_unlock ( &nfmark_count_mutex );
                            retval = FORKED_CHILD_ALLOW;

                        }
                        else if ( !strcmp ( temp->perms, DENY_ALWAYS ) || !strcmp ( temp->perms, DENY_ONCE ) )
                        {
                            retval =  FORKED_CHILD_DENY;
                        }

                        char tempperms2[PERMSLENGTH];
                        char tempsha2 [DIGEST_SIZE];
                        off_t parent_size2 = temp->exesize;
                        strcpy ( tempperms2, temp->perms );
                        memcpy ( tempsha2, temp->sha, DIGEST_SIZE );

                        pthread_mutex_unlock ( &dlist_mutex );

                        unsigned long long stime;
                        stime = starttimeGet ( atoi ( pid ) );

			dlist_add ( path, pid, tempperms2, TRUE, tempsha2, stime, parent_size2, *nfmark_to_set, FALSE );
                        fe_list();
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
                                m_printf(MLOG_INFO, "Shasums dont match. Impersonation attempt detected by %s in %s, %d\n", path, __FILE__, __LINE__);
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
                    m_printf ( MLOG_ALERT, "Red alert!!!! Executable has been changed...  %s,%d\n",exepath, __FILE__, __LINE__ );
                    return EXE_HAS_BEEN_CHANGED;

                }

                //If exe hasnt been modified/deleted than taking its size is redundant, just use parent's size

                m_printf ( MLOG_DEBUG, "Adding to dlist: %s, %s, %s\n", path, pid, tempperms );

                //See if we need to query user or silently add to dlist
                pthread_mutex_lock ( &dlist_mutex );
                dlist * temp2 = first->next;

                // A1. Are there any entries in dlist with the same PATH as NP AND *ALWAYS perms? If yes, then create new entry in dlist copy parent's perms and all other attributes over to NP and continue;
// A2. If No, i.e. there either aren't any entries in dlist with the same PATH as NP OR there are entries with the same path as NP AND *ONCE perms, then query user.
//

                while ( temp2 != NULL )
                {
                    if ( !strcmp ( temp2->path, path ) )
                    {
                        if ( !strcmp ( temp2->perms, ALLOW_ALWAYS ) )
                        {
                            pthread_mutex_unlock ( &dlist_mutex );
			    dlist_add ( path, pid, tempperms, TRUE, tempsha, *stime, parent_size, tempnfmark ,FALSE);
                            fe_list();
                            
                            *nfmark_to_set = tempnfmark;
                            return NEW_INSTANCE_ALLOW;
                        }
                        else if ( !strcmp ( temp2->perms, DENY_ALWAYS ) )
                        {
                            pthread_mutex_unlock ( &dlist_mutex );
			    dlist_add ( path, pid, tempperms, TRUE, tempsha, *stime, parent_size, tempnfmark, FALSE );
                            fe_list();
                            return NEW_INSTANCE_DENY;
                        }
                    }
                    temp2 = temp2->next;
                }
                // we need to send new query to user
                goto quit;

            } // else if (temp->current_pid == '1')
        } //  if (!strcmp(temp->path, path)) {
        temp = temp->next;
    } //while (temp != NULL)

quit:
    pthread_mutex_unlock ( &dlist_mutex );
    //if the path is not in dlist or is a new instance of an *ONCE rule
    return GOTO_NEXT_STEP;
}

//scan only those /proc entries that are already in the dlist
// and only those that have a current PID (meaning the app has already sent a packet)
int socket_find_in_dlist ( int *mysocket, int *nfmark_to_set )
{
    char find_socket[32]; //contains the string we are searching in /proc/PID/fd/1,2,3 etc.  a-la socket:[1234]
    char path[32];
    char path2[32];
    char socketbuf[32];
    char exepathbuf[PATHSIZE];
    DIR * m_dir;
    struct dirent *m_dirent;
    char socketstr[16];

    sprintf ( socketstr, "%d", *mysocket );  //convert inode from int to string

    strcpy ( find_socket, "socket:[" );
    strcat ( find_socket, socketstr );
    strcat ( find_socket, "]" );

    pthread_mutex_lock ( &dlist_mutex );
    dlist * temp = first->next;

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
            m_printf ( MLOG_DEBUG, "opendir for %s %s: %s,%s,%d\n", temp->path, path, strerror ( errno ), __FILE__, __LINE__ );
            temp = temp->next;
            closedir ( m_dir );
            continue;
        }
        while ( m_dirent = readdir ( m_dir ) )
        {
            strcpy ( path2, path );
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
                m_printf ( MLOG_TRAFFIC, "%s %s ", exepathbuf, temp->pid );
                closedir ( m_dir );

                unsigned long long stime;
                stime = starttimeGet ( atoi ( temp->pid ) );
                if ( temp->stime != stime )
                {
                    m_printf ( MLOG_INFO, "Red alert!!!Start times don't match %s %s %d", temp->path,  __FILE__, __LINE__ );
                    return STIME_DONT_MATCH;
                }

                if ( !strcmp ( temp->perms, ALLOW_ONCE ) || !strcmp ( temp->perms, ALLOW_ALWAYS ) )
                {
                    *nfmark_to_set = temp->nfmark;
                    pthread_mutex_unlock ( &dlist_mutex );
                    return INODE_FOUND_IN_DLIST_ALLOW;
                }
                if ( !strcmp ( temp->perms, DENY_ONCE ) || !strcmp ( temp->perms, DENY_ALWAYS ) )
                {
                    pthread_mutex_unlock ( &dlist_mutex );
                    return INODE_FOUND_IN_DLIST_DENY;
                }
            }
        }
        closedir ( m_dir );
        temp = temp->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );
    return GOTO_NEXT_STEP;
}

//scan /proc to find which PID the socket belongs to
int socket_find_in_proc ( int *mysocket, char *m_path, char *m_pid, unsigned long long *stime )
{
    //vars for scanning through /proc dir
    struct dirent *proc_dirent, *fd_dirent;
    DIR *proc_DIR, *fd_DIR;
    // holds path to /proc/<pid>/fd/<number_of_inode_opened>
    char path[32];
    char fdpath[32];
    // buffers to hold readlink()ed values of /proc/<pid>/exe and /proc/<pid>/fd/<inode>
    char exepathbuf[PATHSIZE];
    char socketbuf[SOCKETBUFSIZE];

    //convert inode from int to string
    char socketstr[16];
    sprintf ( socketstr, "%d", *mysocket ); //convert int to char* for future use
    char find_socket[32] = "socket:[";
    strcat ( find_socket, socketstr );
    strcat ( find_socket, "]" );

    proc_DIR = opendir ( "/proc" );
    do
    {
        proc_dirent = readdir ( proc_DIR );
        if ( !proc_dirent )
        {
            //perror("procdirent");
            break;
        } //EOF reached or some error
        if ( ( 47 < proc_dirent->d_name[0] ) && ( proc_dirent->d_name[0] < 58 ) ) // starts with ASCII 1 through 9
        {
            path[0] = 0; //empty the path
            strcpy ( path, "/proc/" );
            strcat ( path, proc_dirent->d_name );
            strcat ( path, "/fd" );
            //we may get a NULL retval if process has exited since readdir(proc_DIR) call and path doesnt exist anymore
            fd_DIR = opendir ( path );
            if ( !fd_DIR )
            {
                m_printf ( MLOG_INFO, "PID quit while scanning /proc,opendir:%s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                continue;
            } // permission denied or some other error
            do
            {
                fd_dirent = readdir ( fd_DIR );
                if ( !fd_dirent ) //EOF
                {
                    //perror("fddirent");
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
                    if ( strcmp ( find_socket, socketbuf ) == 0 ) //strcmp return 0 when match
                        //we found our socket!!!!
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
                        m_printf ( MLOG_TRAFFIC, "%s %s ", m_path, m_pid );
                        return GOTO_NEXT_STEP;
                    }
                }
            }
            while ( fd_dirent );
        }
    }
    while ( proc_dirent );
    closedir ( proc_DIR );
    return SOCKET_NONE_PIDFD;
}

//if there are more than one entry in /proc/net/raw for icmp then it's impossible to tell which app is sending the packet
int icmp_check_only_one_inode ( int *m_inodeint )
{
    int loop = 0;
    int inodeint;
    int readbytes = 1;

    char inode[8];

    while ( 1 )
    {
        lseek ( procnetrawfd, 206 + 110 * loop, SEEK_SET );
        readbytes = read ( procnetrawfd, inode, 8 );
        //in case there was icmp packet but no /proc/net/raw entry - report
        if ( ( loop == 0 ) && ( readbytes == 0 ) )
        {
            m_printf ( MLOG_INFO, "ICMP packet without /proc/net/raw entry" );
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
        for ( i = 0; i < 8; ++i )
        {
            if ( inode[i] == 32 )
            {
                inode[i] = 0; // 0x20 space, see /proc/net/ucp
                break;
            }
        }
        *m_inodeint = atoi ( inode );
        ++loop;
    }
    m_printf ( MLOG_DEBUG, "(icmp)inode %d", inodeint );
    return 0;
}

int socket_check_kernel_udp(int *socket){
    //sometimes kernel sockets have inode numbers and are indistinguishable from user sockets.
    //The ony diffrnc is they have uid=0 (but so are root's)
    //rescan /proc/net to see if this socket might be kernel's or (root's)

    char sockstr[12];
    int sockstr_sz;

    sprintf(sockstr,"%d", *socket);
    //add space to the end of string for easier strcmp
    sockstr_sz = strlen(sockstr);
    sockstr[sockstr_sz] = 32;
    sockstr[sockstr_sz+1] = 0;

    char uid;
    FILE *mudpinfo, *mudp6info;
    char * membuf;
    int bytesread;

    if ((membuf=(char*)malloc(MEMBUF_SIZE)) == NULL) perror("malloc");
    memset(membuf,0, MEMBUF_SIZE);
    if ( ( mudpinfo = fopen ( UDPINFO, "r" ) ) == NULL ){
	m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	return PROCFS_ERROR;
    }
    fseek(mudpinfo,0,SEEK_SET);
    errno = 0;
    if (bytesread = fread(membuf, sizeof(char), MEMBUF_SIZE , mudpinfo)){
	    if (errno != 0) perror("fread udpinfo");
    }
    fclose(mudpinfo);
    int i = 0;
    char proc_sockstr[12];
    proc_sockstr[0] = 1; //initialize

    while(proc_sockstr[0] != 0){
	memcpy(proc_sockstr, &membuf[220+128*i], 12);
	if (strncmp(proc_sockstr, sockstr, sockstr_sz)){
	    i++;
	    continue;
	}
	//else match
	memcpy(&uid, &membuf[209+128*i],1);
	free(membuf);
	if (uid != '0') {
	    return SOCKET_NONE_PIDFD;
	}
	else return INKERNEL_SOCKET_FOUND;
    }
    //not found in /proc/net/tcp, search in /proc/net/tcp6

    memset(membuf,0, MEMBUF_SIZE);
    if ( ( mudp6info = fopen ( UDP6INFO, "r" ) ) == NULL ){
	m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	return PROCFS_ERROR;
    }
    fseek(mudp6info,0,SEEK_SET);
    errno = 0;
    if (bytesread = fread(membuf, sizeof(char), MEMBUF_SIZE , mudp6info)){
	    if (errno != 0) perror("fread tcpinfo");
    }
    fclose(mudp6info);
    i = 0;
    proc_sockstr[0] = 1;
    while(proc_sockstr[0] != 0){
	memcpy(proc_sockstr, &membuf[284+171*i], 12);
	if (strncmp(proc_sockstr, sockstr, sockstr_sz)){
	    i++;
	    continue;
	}
	//else match
	memcpy(&uid, &membuf[273+171*i],1);
	free(membuf);
	if (uid != '0') {
	    return SOCKET_NONE_PIDFD;
	}
	else return INKERNEL_SOCKET_FOUND;
    }
    return SOCKET_NONE_PIDFD;
}


int socket_check_kernel_tcp(int *socket){
    //sometimes kernel sockets have inode numbers and are indistinguishable from user sockets.
    //The ony diffrnc is they have uid=0 (but so are root's)
    //rescan /proc/net to see if this socket might be kernel's or (root's)

    char sockstr[12];
    int sockstr_sz;

    sprintf(sockstr,"%d", *socket);
    //add space to the end of string for easier strcmp
    sockstr_sz = strlen(sockstr);
    sockstr[sockstr_sz] = 32;
    sockstr[sockstr_sz+1] = 0;

    char uid;
    FILE *mtcpinfo, *mtcp6info;
    char * membuf;
    int bytesread;

    if ((membuf=(char*)malloc(MEMBUF_SIZE)) == NULL) perror("malloc");
    memset(membuf,0, MEMBUF_SIZE);
    if ( ( mtcpinfo = fopen ( TCPINFO, "r" ) ) == NULL ){
	m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	return PROCFS_ERROR;
    }
    fseek(mtcpinfo,0,SEEK_SET);
    errno = 0;
    if (bytesread = fread(membuf, sizeof(char), MEMBUF_SIZE , mtcpinfo)){
	    if (errno != 0) perror("fread tcpinfo");
    }
    fclose(mtcpinfo);
    int i = 0;
    char proc_sockstr[12];
    proc_sockstr[0] = 1; //initialize

    while(proc_sockstr[0] != 0){
	memcpy(proc_sockstr, &membuf[165+150*i+76], 12);
	if (strncmp(proc_sockstr, sockstr, sockstr_sz)){
	    i++;
	    continue;
	}
	//else match
	memcpy(&uid, &membuf[230+150*i],1);
	free(membuf);
	if (uid != '0') {
	    return SOCKET_NONE_PIDFD;
	}
	else return INKERNEL_SOCKET_FOUND;
    }
    //not found in /proc/net/tcp, search in /proc/net/tcp6

    memset(membuf,0, MEMBUF_SIZE);
    if ( ( mtcp6info = fopen ( TCP6INFO, "r" ) ) == NULL ){
	m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	return PROCFS_ERROR;
    }
    fseek(mtcp6info,0,SEEK_SET);
    errno = 0;
    if (bytesread = fread(membuf, sizeof(char), MEMBUF_SIZE , mtcp6info)){
	    if (errno != 0) perror("fread tcpinfo");
    }
    fclose(mtcp6info);
    i = 0;
    proc_sockstr[0] = 1;
    while(proc_sockstr[0] != 0){
	memcpy(proc_sockstr, &membuf[284+171*i], 12);
	if (strncmp(proc_sockstr, sockstr, sockstr_sz)){
	    i++;
	    continue;
	}
	//else match
	memcpy(&uid, &membuf[273+171*i],1);
	free(membuf);
	if (uid != '0') {
	    return SOCKET_NONE_PIDFD;
	}
	else return INKERNEL_SOCKET_FOUND;
    }
    return SOCKET_NONE_PIDFD;
}


//find in procfs which socket corresponds to source port
int port2socket_udp ( int *portint, int *socketint )
{
    char buffer[4];
    char procport[12];
    char socketstr[12];
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
    if (bytesread_udp = fread(udp_membuf, sizeof(char), MEMBUF_SIZE , udpinfo)){
            if (errno != 0) perror("READERORRRRRRR");
    }
    m_printf (MLOG_DEBUG2, "udp bytes read: %d\n", bytesread_udp);

    memset(udp6_membuf, 0, MEMBUF_SIZE);
    fseek(udp6info,0,SEEK_SET);
    errno = 0;
    if (bytesread_udp6 = fread(udp6_membuf, sizeof(char), MEMBUF_SIZE , udp6info)){
            if (errno != 0) perror("6READERORRRRRRR");
    }
    m_printf (MLOG_DEBUG2, "udp6 bytes read: %d\n", bytesread_udp6);

    dont_fread:
    while(1){
        memcpy(buffer, &udp_membuf[144+128*i], 4);
        if (!memcmp ( porthex, buffer, 4 ) ){//match!
            memcpy(socketstr, &udp_membuf[144+128*i+76], 12);
            goto endloop;
        }
        if (buffer[0] != 0){ //EOF not reached, reiterate
            i++;
            continue;
        }
        // else EOF reached with no match, check if it was IPv6 socket
        i = 0;
        while(1){
            memcpy(buffer,&udp6_membuf[184+171*i],4);
            if ( !memcmp ( porthex, buffer, 4 ) ){ //match!
                memcpy(socketstr, &udp6_membuf[184+171*i+100],12);
                goto endloop;
            }
            if (buffer[0] != 0){ //EOF not reached, reiterate
                i++;
                continue;
            }
            //else EOF reached with no match, if it was 1st iteration then reread proc file
	    if (not_found_once) return SRCPORT_NOT_FOUND_IN_PROC;
            //else
            nanosleep(&timer, &dummy);
            not_found_once=1;
            goto do_fread;
            }
    }
    endloop:
    i=1;
    while (socketstr[i] != 32){i++;}
    socketstr[i] = 0; // 0x20 == space, see /proc/net/tcp
    *socketint = atoi ( socketstr );
    if (*socketint == 0) return INKERNEL_SOCKET_FOUND;
        return GOTO_NEXT_STEP;
}



//find in procfs which socket corresponds to source port
int port2socket_tcp ( int *portint, int *socketint )
{
    char buffer[4];
    char procport[12];
    char socketstr[12];
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
    if (bytesread_tcp = fread(tcp_membuf, sizeof(char), MEMBUF_SIZE , tcpinfo)){
	    if (errno != 0) perror("fread tcpinfo");
    }
    m_printf (MLOG_DEBUG2, "tcp bytes read: %d\n", bytesread_tcp);

    memset(tcp6_membuf, 0, MEMBUF_SIZE);
    fseek(tcp6info,0,SEEK_SET);
    errno = 0;
    if (bytesread_tcp6 = fread(tcp6_membuf, sizeof(char), MEMBUF_SIZE , tcp6info)){
	    if (errno != 0) perror("fread tcp6info");
    }
    m_printf (MLOG_DEBUG2, "tcp6 bytes read: %d\n", bytesread_tcp6);

    dont_fread:
    while(1){
        memcpy(buffer, &tcp_membuf[165+150*i], 4);
        if (!memcmp ( porthex, buffer, 4 ) ){//match!
            memcpy(socketstr, &tcp_membuf[165+150*i+76], 12);
            goto endloop;
        }
        if (buffer[0] != 0){ //EOF not reached, reiterate
            i++;
            continue;
        }
        // else EOF reached with no match, check if it was IPv6 socket
        i = 0;
        while(1){
            memcpy(buffer,&tcp6_membuf[184+171*i],4);
            if ( !memcmp ( porthex, buffer, 4 ) ){ //match!
                memcpy(socketstr, &tcp6_membuf[184+171*i+100],12);
                goto endloop;
            }
            if (buffer[0] != 0){ //EOF not reached, reiterate
                i++;
                continue;
            }
            //else EOF reached with no match, if it was 1st iteration then reread proc file
	    if (not_found_once){
		return SRCPORT_NOT_FOUND_IN_PROC;
	    }
            //else
            nanosleep(&timer, &dummy);
            not_found_once=1;
            goto do_fread;
            }
    }
    endloop:
    i=1;
    while (socketstr[i] != 32){i++;}
    socketstr[i] = 0; // 0x20 == space, see /proc/net/tcp
    *socketint = atoi ( socketstr );
    if (*socketint == 0) return INKERNEL_SOCKET_FOUND;
    //else
    return GOTO_NEXT_STEP;
}

//Handler for TCP packets
int packet_handle_tcp ( int srctcp, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime){
    int retval, socketint;
    char cache_path[PATHSIZE];
    char cache_pid[PIDLENGTH];
    //returns GOTO_NEXT_STEP => OK to go to the next step, otherwise  it returns one of the verdict values
    if ( (retval = port2socket_tcp ( &srctcp, &socketint )) != GOTO_NEXT_STEP ) goto out;
    if ((retval = parsecache(socketint, cache_path, cache_pid)) != GOTO_NEXT_STEP){
	m_printf (MLOG_DEBUG2, "(cache)");
	m_printf ( MLOG_TRAFFIC, " %s %s ", cache_path, cache_pid );
	goto out;
    }
    if ( (retval = socket_find_in_dlist ( &socketint, nfmark_to_set ) ) != GOTO_NEXT_STEP ) goto out;
    retval = socket_find_in_proc ( &socketint, path, pid, stime );
    if (retval == SOCKET_NONE_PIDFD){
	retval = socket_check_kernel_tcp(&socketint);
	goto out;
    }
    else if (retval != GOTO_NEXT_STEP) goto out;

    if ( (retval = path_find_in_dlist ( nfmark_to_set, path, pid, stime ) ) != GOTO_NEXT_STEP) goto out;
out:
    return retval;
}

//Handler for UDP packets
int packet_handle_udp ( int srcudp, int *nfmark_to_set, char *path, char *pid, unsigned long long *stime)
{
    int retval, socketint;
    char cache_path[PATHSIZE];
    char cache_pid[PIDLENGTH];
    //returns GOTO_NEXT_STEP => OK to go to the next step, otherwise  it returns one of the verdict values
    if ( (retval = port2socket_udp ( &srcudp, &socketint ) ) != GOTO_NEXT_STEP) goto out;
    if ((retval = parsecache(socketint, cache_path, cache_pid)) != GOTO_NEXT_STEP){
	m_printf (MLOG_DEBUG2, "(cache)");
	m_printf ( MLOG_TRAFFIC, " %s %s ", cache_path, cache_pid );
	goto out;
    }
    if ( (retval = socket_find_in_dlist ( &socketint, nfmark_to_set )) != GOTO_NEXT_STEP) goto out;
    retval = socket_find_in_proc ( &socketint, path, pid, stime );
    if (retval == SOCKET_NONE_PIDFD){
	retval = socket_check_kernel_udp(&socketint);
	goto out;
    }
    else if (retval != GOTO_NEXT_STEP) goto out;



    if ( (retval = path_find_in_dlist ( nfmark_to_set, path, pid, stime ) ) != GOTO_NEXT_STEP) goto out;
out:
    return retval;
}

int packet_handle_icmp(int *nfmark_to_set, char *path, char *pid, unsigned long long *stime)
{
    int retval, socketint;

    if (( retval = icmp_check_only_one_inode ( &socketint ) ) != GOTO_NEXT_STEP)  goto out;
    if (( retval = socket_find_in_dlist ( &socketint, nfmark_to_set ) ) != GOTO_NEXT_STEP) goto out;
    if (( retval = socket_find_in_proc ( &socketint, path, pid, stime ) )!= GOTO_NEXT_STEP) goto out;
    if (( retval = path_find_in_dlist (nfmark_to_set, path, pid, stime ) )!= GOTO_NEXT_STEP) goto out;
    if ( !fe_active_flag_get() )
out:
    return retval;
}

int  nfq_handle_in ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata ){
#ifdef DEBUG
    static int is_strange_daddr = 0;
    static char strange_daddr[INET_ADDRSTRLEN];
#endif
    struct iphdr *ip;
    int id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( ph ) id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
        
    char daddr[INET_ADDRSTRLEN], saddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->saddr), saddr, INET_ADDRSTRLEN);

#ifdef DEBUG
    //works only on my machine :))
    if (strcmp(daddr, "192.168.0.2")){
        is_strange_daddr = 1;
        strcpy(strange_daddr, daddr);
    }
    m_printf ( MLOG_DEBUG, "\n %s INPUT \n ", is_strange_daddr?strange_daddr:"-");
# endif
    int verdict;
    u_int16_t sport_netbo, dport_netbo, sport_hostbo, dport_hostbo;
    char path[PATHSIZE], pid[PIDLENGTH];
    unsigned long long stime;
    switch ( ip->protocol )
    {
    case IPPROTO_TCP:
        ;
        // ihl field is IP header length in 32-bit words, multiply a word by 4 to get length in bytes
        struct tcphdr *tcp;
        tcp = ( struct tcphdr* ) ( (char*)ip + ( 4 * ip->ihl ) );
        sport_netbo = tcp->source;
        dport_netbo = tcp->dest;
        sport_hostbo = ntohs ( tcp->source );
        dport_hostbo = ntohs ( tcp->dest );
	m_printf ( MLOG_TRAFFIC, ">TCP dst %d src %s:%d ", dport_hostbo, saddr, sport_hostbo );

        fe_was_busy_in = fe_awaiting_reply? TRUE: FALSE;
	    if ((verdict = packet_handle_tcp ( dport_hostbo, &nfmark_to_set_in, path, pid, &stime )) == GOTO_NEXT_STEP || verdict == INKERNEL_SOCKET_FOUND){
		if (verdict == INKERNEL_SOCKET_FOUND){ //see if this is an inkernel rule
		    pthread_mutex_lock(&dlist_mutex);
		    dlist *temp = first;
		    while(temp->next != NULL){
			temp = temp->next;
			if (strcmp(temp->path, KERNEL_PROCESS)) continue;
			//else
			if (!strcmp(temp->pid, saddr)){
			    if (!strcmp(temp->perms, ALLOW_ALWAYS) || !strcmp(temp->perms, ALLOW_ONCE)){
				if (temp->is_active) nfmark_to_set_in = temp->nfmark;
				else { //the first time this rule triggered after being added from rulesfile
				    temp->nfmark = NFMARK_BASE + nfmark_count;
				    nfmark_to_set_in = NFMARK_BASE + nfmark_count;
				    nfmark_count++;
				    temp->is_active = TRUE;
				}
				verdict = INKERNEL_RULE_ALLOW;
				pthread_mutex_unlock(&dlist_mutex);
				goto kernel_verdict;
			    }
			    else if (!strcmp(temp->perms, DENY_ALWAYS) || !strcmp(temp->perms, DENY_ONCE)){
				verdict = INKERNEL_RULE_DENY;
				pthread_mutex_unlock(&dlist_mutex);
				goto kernel_verdict;
			    }
			}
		    }
		    pthread_mutex_unlock(&dlist_mutex);
		    //not found in in-kernel list, drop the bumb
		    verdict = SOCKET_NONE_PIDFD;
		    goto kernel_verdict;
		}
	    if (fe_was_busy_in){ verdict = FRONTEND_BUSY; break;}
	    else verdict = fe_active_flag_get() ? fe_ask_in(path,pid,&stime, saddr, sport_hostbo, dport_hostbo ) : FRONTEND_NOT_LAUNCHED;
        }
        break;
        
    case IPPROTO_UDP:
        ;
        struct udphdr *udp;
        udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
        sport_netbo = udp->source;
        dport_netbo = udp->dest;
        sport_hostbo = ntohs ( udp->source );
        dport_hostbo = ntohs ( udp->dest );     
	m_printf ( MLOG_TRAFFIC, ">UDP dst %d src %s:%d ", dport_hostbo, saddr, sport_hostbo );

        fe_was_busy_in = fe_awaiting_reply? TRUE: FALSE;            
	    if ((verdict = packet_handle_udp ( dport_hostbo, &nfmark_to_set_in, path, pid, &stime )) == GOTO_NEXT_STEP || verdict == INKERNEL_SOCKET_FOUND){
		if (verdict == INKERNEL_SOCKET_FOUND){ //see if this is an inkernel rule
		    pthread_mutex_lock(&dlist_mutex);
		    dlist *temp = first;
		    while(temp->next != NULL){
			temp = temp->next;
			if (strcmp(temp->path, KERNEL_PROCESS)) continue;
			//else
			if (!strcmp(temp->pid, saddr)){
			    if (!strcmp(temp->perms, ALLOW_ALWAYS) || !strcmp(temp->perms, ALLOW_ONCE)){
				if (temp->is_active) nfmark_to_set_in = temp->nfmark;
				else { //the first time this rule triggered after being added from rulesfile
				    temp->nfmark = NFMARK_BASE + nfmark_count;
				    nfmark_to_set_in = NFMARK_BASE + nfmark_count;
				    nfmark_count++;
				    temp->is_active = TRUE;
				}
				verdict = INKERNEL_RULE_ALLOW;
				pthread_mutex_unlock(&dlist_mutex);
				goto kernel_verdict;
			    }
			    else if (!strcmp(temp->perms, DENY_ALWAYS) || !strcmp(temp->perms, DENY_ONCE)){
				verdict = INKERNEL_RULE_DENY;
				pthread_mutex_unlock(&dlist_mutex);
				goto kernel_verdict;
			    }
			}
		    }
		    pthread_mutex_unlock(&dlist_mutex);
		    //not found in in-kernel list, ask user reuse struct's fields
		    strcpy(path, KERNEL_PROCESS);
		    strcpy(pid, saddr);
		    stime = sport_hostbo;
		}
	    if (fe_was_busy_in){ verdict = FRONTEND_BUSY; break;}
	    else verdict = fe_active_flag_get() ? fe_ask_in(path,pid,&stime, saddr, sport_hostbo, dport_hostbo) : FRONTEND_NOT_LAUNCHED;
        }
        break;
    case IPPROTO_ICMP:
        ;
	m_printf ( MLOG_TRAFFIC, ">ICMP src %s ", saddr);
        fe_was_busy_in = fe_awaiting_reply? TRUE: FALSE;
        if ((verdict = packet_handle_icmp (&nfmark_to_set_in, path, pid, &stime )) == GOTO_NEXT_STEP){
            if (fe_was_busy_in){ verdict = FRONTEND_BUSY; break;}
	    else verdict = fe_active_flag_get() ? fe_ask_in(path,pid,&stime, saddr, sport_hostbo, dport_hostbo) : FRONTEND_NOT_LAUNCHED;
        }
        break;
    default:
        m_printf ( MLOG_INFO, "IN unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
        m_printf ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet" );
        verdict = UNSUPPORTED_PROTOCOL;
    }

    kernel_verdict:
 switch ( verdict )
    {
    case ACCEPT:
    case INODE_FOUND_IN_DLIST_ALLOW:
    case PATH_FOUND_IN_DLIST_ALLOW:
    case NEW_INSTANCE_ALLOW:
    case FORKED_CHILD_ALLOW:
    case CACHE_TRIGGERED_ALLOW:
    case INKERNEL_RULE_ALLOW:

        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "allow\n" );
        
     nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_DST, ip->daddr);
     nfct_set_attr_u32(ct_in, ATTR_ORIG_IPV4_SRC, ip->saddr);
     nfct_set_attr_u8 (ct_in, ATTR_L4PROTO, ip->protocol);
     nfct_set_attr_u8 (ct_in, ATTR_L3PROTO, AF_INET);
     nfct_set_attr_u16(ct_in, ATTR_PORT_SRC, sport_netbo);
     nfct_set_attr_u16(ct_in, ATTR_PORT_DST, dport_netbo) ;
     
     //EBUSY returned, when there's too much activity in conntrack. Requery the packet
     while (nfct_query(setmark_handle_in, NFCT_Q_GET, ct_in) == -1){
         if (errno == EBUSY){
             m_printf ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
             continue;
         }
         if (errno == EILSEQ){
             m_printf ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
             continue;
         }
         else {
             m_printf ( MLOG_INFO, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
             break;
     }
     }
        return 0;

    case DROP:
        m_printf ( MLOG_TRAFFIC, "drop\n" ); goto DROPverdict;
    case PORT_NOT_FOUND:
        m_printf ( MLOG_TRAFFIC, "packet's source port not found in /proc/net/*. This means that the remote machine has probed our port\n" ); goto DROPverdict;
    case SENT_TO_FRONTEND:
        m_printf ( MLOG_TRAFFIC, "sent to frontend, dont block the nfqueue - silently drop it\n" ); goto DROPverdict;
    case INODE_FOUND_IN_DLIST_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case PATH_FOUND_IN_DLIST_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case NEW_INSTANCE_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case FRONTEND_NOT_LAUNCHED:
        m_printf ( MLOG_TRAFFIC, "frontend is not active, dropping\n" ); goto DROPverdict;
    case FRONTEND_BUSY:
        m_printf ( MLOG_TRAFFIC, "frontend is busy, dropping\n" ); goto DROPverdict;
    case UNSUPPORTED_PROTOCOL:
        m_printf ( MLOG_TRAFFIC, "Unsupported protocol, dropping\n" ); goto DROPverdict;;
    case ICMP_MORE_THAN_ONE_ENTRY:
        m_printf ( MLOG_TRAFFIC, "More than one program is using icmp, dropping\n" ); goto DROPverdict;
    case ICMP_NO_ENTRY:
        m_printf ( MLOG_TRAFFIC, "icmp packet received by there is no icmp entry in /proc. Very unusual. Please report\n" ); goto DROPverdict;
    case SHA_DONT_MATCH:
        m_printf ( MLOG_TRAFFIC, "Red alert. Some app is trying to impersonate another\n" ); goto DROPverdict;
    case STIME_DONT_MATCH:
        m_printf ( MLOG_TRAFFIC, "Red alert. Some app is trying to impersonate another\n" ); goto DROPverdict;
    case EXESIZE_DONT_MATCH:
        m_printf ( MLOG_TRAFFIC, "Red alert. Executable's size don't match the records\n" ); goto DROPverdict;
    case INODE_HAS_CHANGED:
        m_printf ( MLOG_TRAFFIC, "Process inode has changed, This means that a process was killed and another with the same PID was immediately started. Smacks of somebody trying to hack your system\n" ); goto DROPverdict;
    case EXE_HAS_BEEN_CHANGED:
        m_printf ( MLOG_TRAFFIC, "While process was running, someone changed his binary file on disk. Definitely an attempt to compromise the firewall\n" ); goto DROPverdict;
    case FORKED_CHILD_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case CACHE_TRIGGERED_DENY:
	 m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case SRCPORT_NOT_FOUND_IN_PROC:
	 m_printf ( MLOG_TRAFFIC, "source port not found in procfs\n" ); goto DROPverdict;
    case INKERNEL_RULE_DENY:
	 m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case SOCKET_NONE_PIDFD:
	 m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    }
    DROPverdict:
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;

}


//this function is invoked each time a packet arrives to OUTPUT NFQUEUE
int  nfq_handle_out ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
    struct iphdr *ip;
    u_int32_t id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( !ph ) {printf ("ph == NULL, should ever happen, please report"); return 0;}
    id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, (char**)&ip );
    char daddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->daddr), daddr, INET_ADDRSTRLEN);
    int verdict;
    u_int16_t sport_netbyteorder, dport_netbyteorder;
      char path[PATHSIZE], pid[PIDLENGTH];
        unsigned long long stime;
    switch ( ip->protocol )
    {
    case IPPROTO_TCP:
        ;
        // ihl field is IP header length in 32-bit words, multiply by 4 to get length in bytes
        struct tcphdr *tcp;
                
        tcp = ( struct tcphdr* ) ((char*)ip + ( 4 * ip->ihl ) );
        sport_netbyteorder = tcp->source;
        dport_netbyteorder = tcp->dest;
        int srctcp = ntohs ( tcp->source );     
	m_printf ( MLOG_TRAFFIC, "<TCP src %d dst %s:%d ", srctcp, daddr, ntohs ( tcp->dest ) );

	//remember fe's state before we process
        fe_was_busy_out = fe_awaiting_reply? TRUE: FALSE;
	if ((verdict = packet_handle_tcp ( srctcp, &nfmark_to_set_out, path, pid, &stime )) == GOTO_NEXT_STEP || verdict == INKERNEL_SOCKET_FOUND){
	    if (verdict == INKERNEL_SOCKET_FOUND){ //see if this is an inkernel rule

		pthread_mutex_lock(&dlist_mutex);
		dlist *temp = first;
		while(temp->next != NULL){
		    temp = temp->next;
		    if (strcmp(temp->path, KERNEL_PROCESS)) continue;
		    //else
		    if (!strcmp(temp->pid, daddr)){
			if (!strcmp(temp->perms, ALLOW_ALWAYS) || !strcmp(temp->perms, ALLOW_ONCE)){
			    if (temp->is_active) nfmark_to_set_out = temp->nfmark;
			    else { //the first time this rule triggered after being added from rulesfile
				temp->nfmark = NFMARK_BASE + nfmark_count;
				nfmark_to_set_out = NFMARK_BASE + nfmark_count;
				nfmark_count++;
				temp->is_active = TRUE;
			    }
			    verdict = INKERNEL_RULE_ALLOW;
			    pthread_mutex_unlock(&dlist_mutex);
			    goto kernel_verdict;
			}
			else if (!strcmp(temp->perms, DENY_ALWAYS) || !strcmp(temp->perms, DENY_ONCE)){
			    verdict = INKERNEL_RULE_DENY;
			    pthread_mutex_unlock(&dlist_mutex);
			    goto kernel_verdict;
			}
		    }
		}
		pthread_mutex_unlock(&dlist_mutex);
		//not found in in-kernel list, drop
		verdict = SOCKET_NONE_PIDFD;
		goto kernel_verdict;
	    }
	    //drop if fe was busy before we started processing
	    if (fe_was_busy_out){ verdict = FRONTEND_BUSY; break;}
	    else verdict = fe_active_flag_get() ? fe_ask_out(path,pid,&stime) : FRONTEND_NOT_LAUNCHED;
        }
        break;
    case IPPROTO_UDP:
        ;
        struct udphdr *udp;
        udp = ( struct udphdr * ) ( (char*)ip + ( 4 * ip->ihl ) );
        sport_netbyteorder = udp->source;
        dport_netbyteorder = udp->dest;
        int srcudp = ntohs ( udp->source );
	m_printf ( MLOG_TRAFFIC, "<UDP src %d dst %s:%d ", srcudp, daddr, ntohs ( udp->dest ) );
        
	fe_was_busy_out = fe_awaiting_reply? TRUE: FALSE;
	    if ((verdict = packet_handle_udp ( srcudp, &nfmark_to_set_out, path, pid, &stime )) == GOTO_NEXT_STEP || verdict == INKERNEL_SOCKET_FOUND){
		if (verdict == INKERNEL_SOCKET_FOUND){ //see if this is an inkernel rule
		    pthread_mutex_lock(&dlist_mutex);
		    dlist *temp = first;
		    while(temp->next != NULL){
			temp = temp->next;
			if (strcmp(temp->path, KERNEL_PROCESS)) continue;
			//else
			if (!strcmp(temp->pid, daddr)){
			    if (!strcmp(temp->perms, ALLOW_ALWAYS) || !strcmp(temp->perms, ALLOW_ONCE)){
				if (temp->is_active) nfmark_to_set_out = temp->nfmark;
				else {
				    temp->nfmark = NFMARK_BASE + nfmark_count;
				    nfmark_to_set_out = NFMARK_BASE + nfmark_count;
				    nfmark_count++;
				    temp->is_active = TRUE;
				}
				verdict = INKERNEL_RULE_ALLOW;
				pthread_mutex_unlock(&dlist_mutex);
				goto kernel_verdict;
			    }
			    else if (!strcmp(temp->perms, DENY_ALWAYS) || !strcmp(temp->perms, DENY_ONCE)){
				verdict = INKERNEL_RULE_DENY;
				pthread_mutex_unlock(&dlist_mutex);
				goto kernel_verdict;
			    }
			}
		    }
		    pthread_mutex_unlock(&dlist_mutex);
		    //not found in in-kernel list, ask user
		    strcpy(path, KERNEL_PROCESS);
		    strcpy(pid, daddr);
		    stime = ntohs (udp->dest);
		}
	    if (fe_was_busy_out){ verdict = FRONTEND_BUSY; break;}
	    else verdict = fe_active_flag_get() ? fe_ask_out(path,pid,&stime) : FRONTEND_NOT_LAUNCHED;
        }
        break;
    case IPPROTO_ICMP:
        ;
	m_printf ( MLOG_TRAFFIC, "<ICMP dst %d ", daddr);
        fe_was_busy_out = fe_awaiting_reply? TRUE: FALSE;
        if ((verdict = packet_handle_icmp (&nfmark_to_set_out, path, pid, &stime )) == GOTO_NEXT_STEP){
            if (fe_was_busy_out){ verdict = FRONTEND_BUSY; break;}
	    else verdict = fe_active_flag_get() ? fe_ask_out(path,pid,&stime) : FRONTEND_NOT_LAUNCHED;
        }
        break;
    default:
        m_printf ( MLOG_INFO, "unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
        m_printf ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet" );
        verdict = UNSUPPORTED_PROTOCOL;
    }

    kernel_verdict:
    switch ( verdict )
    {
    case ACCEPT:
    case INODE_FOUND_IN_DLIST_ALLOW:
    case PATH_FOUND_IN_DLIST_ALLOW:
    case NEW_INSTANCE_ALLOW:
    case FORKED_CHILD_ALLOW:
    case CACHE_TRIGGERED_ALLOW:
    case INKERNEL_RULE_ALLOW:

     nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
     m_printf ( MLOG_TRAFFIC, "allow\n" );
        
     nfct_set_attr_u32(ct_out, ATTR_ORIG_IPV4_DST, ip->daddr);
     nfct_set_attr_u32(ct_out, ATTR_ORIG_IPV4_SRC, ip->saddr);
     nfct_set_attr_u8 (ct_out, ATTR_L4PROTO, ip->protocol);
     nfct_set_attr_u8 (ct_out, ATTR_L3PROTO, AF_INET);
     nfct_set_attr_u16(ct_out, ATTR_PORT_SRC, sport_netbyteorder);
     nfct_set_attr_u16(ct_out, ATTR_PORT_DST, dport_netbyteorder) ;

	//EBUSY returned, when there's too much activity in conntrack. Requery the packet
        while (nfct_query(setmark_handle_out, NFCT_Q_GET, ct_out) == -1){
#ifdef DEBUG2
	    m_printf ( MLOG_DEBUG2, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
#endif
            if (errno == EBUSY){
                m_printf ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                continue;
            }
            if (errno == EILSEQ){
                m_printf ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                continue;
            }

            else {
                m_printf ( MLOG_DEBUG, "nfct_query GET %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                break;
        }
        }

return 0;


    case DROP:
        m_printf ( MLOG_TRAFFIC, "drop\n" ); goto DROPverdict;
    case PORT_NOT_FOUND:
        m_printf ( MLOG_TRAFFIC, "packet's source port not found in /proc/net/*. Very unusual, please report.\n" ); goto DROPverdict;
    case SENT_TO_FRONTEND:
        m_printf ( MLOG_TRAFFIC, "sent to frontend, dont block the nfqueue - silently drop it\n" ); goto DROPverdict;
    case INODE_FOUND_IN_DLIST_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case PATH_FOUND_IN_DLIST_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case NEW_INSTANCE_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case FRONTEND_NOT_LAUNCHED:
        m_printf ( MLOG_TRAFFIC, "frontend is not active, dropping\n" ); goto DROPverdict;
    case FRONTEND_BUSY:
        m_printf ( MLOG_TRAFFIC, "frontend is busy, dropping\n" ); goto DROPverdict;
    case UNSUPPORTED_PROTOCOL:
        m_printf ( MLOG_TRAFFIC, "Unsupported protocol, dropping\n" ); goto DROPverdict;;
    case ICMP_MORE_THAN_ONE_ENTRY:
        m_printf ( MLOG_TRAFFIC, "More than one program is using icmp, dropping\n" ); goto DROPverdict;
    case ICMP_NO_ENTRY:
        m_printf ( MLOG_TRAFFIC, "icmp packet received by there is no icmp entry in /proc. Very unusual. Please report\n" ); goto DROPverdict;
    case SHA_DONT_MATCH:
        m_printf ( MLOG_TRAFFIC, "Red alert. Some app is trying to impersonate another\n" ); goto DROPverdict;
    case STIME_DONT_MATCH:
        m_printf ( MLOG_TRAFFIC, "Red alert. Some app is trying to impersonate another\n" ); goto DROPverdict;
    case EXESIZE_DONT_MATCH:
        m_printf ( MLOG_TRAFFIC, "Red alert. Executable's size don't match the records\n" ); goto DROPverdict;
    case INODE_HAS_CHANGED:
        m_printf ( MLOG_TRAFFIC, "Process inode has changed, This means that a process was killed and another with the same PID was immediately started. Smacks of somebody trying to hack your system\n" ); goto DROPverdict;
    case EXE_HAS_BEEN_CHANGED:
        m_printf ( MLOG_TRAFFIC, "While process was running, someone changed his binary file on disk. Definitely an attempt to compromise the firewall\n" ); goto DROPverdict;
    case FORKED_CHILD_DENY:
        m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case CACHE_TRIGGERED_DENY:
	m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    case SRCPORT_NOT_FOUND_IN_PROC:
	 m_printf ( MLOG_TRAFFIC, "source port not found in procfs\n" ); goto DROPverdict;
    case INKERNEL_RULE_DENY:
	m_printf ( MLOG_TRAFFIC, "in-kernel rule, deny\n" ); goto DROPverdict;
    case SOCKET_NONE_PIDFD:
	m_printf ( MLOG_TRAFFIC, "deny\n" ); goto DROPverdict;
    }
    DROPverdict:
    nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        return 0;
}

void loggingInit()
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
        if ( ( fileloginfo_stream = fopen ( log_file->filename[0], "w" ) ) == 0 ) perror ( "fopen" );
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
    else if ( !strcmp ( logging_facility->sval[0], "syslog" ) )
    {
        openlog ( "lpfw", 0, 0 );
        m_printf = &m_printf_syslog;
    }
}

void pidFileCheck() {
    // use stat() to check if PIDFILE exists.
    //TODO The check is quick'n'dirty. Consider making more elaborate check later
    struct stat m_stat;
    FILE *pidfd;
    FILE *procfd;
    char pidbuf[8];
    char procstring[20];
    char procbuf[20];
    char srchstr[2] = {0x0A, 0};
    int pid;
    int newpidfd;
    char *ptr;
    char pid2str[8];
    //stat() returns 0 if file exists
    if ( stat ( pid_file->filename[0], &m_stat ) == 0 )
    {
        if ( ( pidfd = fopen ( pid_file->filename[0], "r" ) ) == NULL )
        {
            m_printf ( MLOG_INFO, "fopen PIDFILE: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
            die();
        };
        fgets ( pidbuf, 8, pidfd );
        fclose ( pidfd );
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
                procfd = fopen ( procstring, "r" );
                //let's replace 0x0A with 0x00
                fgets ( procbuf, 20, procfd );
                ptr = strstr ( procbuf, srchstr );
                *ptr = 0;
                //compare the actual string, if found = carry on
                if ( strcmp ( "lpfw", procbuf ) == 0 )
                {
                    //make sure that the running instant is NOT out instant
                    //(can happen when PID of previously crashed lpfw coincides with ours)
                    if ( ( pid_t ) pid != getpid() )
                    {
                        m_printf ( MLOG_INFO, "lpfw is already running\n" );
                        die();
                    }
                }
            }
        }
    }
    else 
        m_printf ( MLOG_DEBUG, "stat: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );


    //else if pidfile doesn't exist/contains dead PID, create/truncate it and write our pid into it
    if ( ( newpidfd = open ( pid_file->filename[0], O_CREAT | O_TRUNC | O_RDWR ) ) == -1 ) perror ( "creat PIDFILE" );
    sprintf ( pid2str, "%d", ( int ) getpid() );
    ssize_t size;
    if ( ( size = write ( newpidfd, pid2str, 8 ) == -1 ) )
        m_printf ( MLOG_INFO, "write: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    close ( newpidfd );
}

void checkRoot()
{
    uid_t pid;
    pid = getuid();
    if ( ( int ) pid != 0 )
    {
        printf ( "Leopard Flower should be run as root. Exiting...\n" );
        die();
    }
}

//initiate message queue and send to first lpfw instance, our pid, tty and display and quit.
int frontend_mode ( int argc, char *argv[] )
{
    key_t ipckey;
    int mqd;
    msg_struct_creds msg;
    //remove memory garbage
    memset (&msg, 0, sizeof(msg_struct_creds)); 
    msg.type = 1;

    
    if ( ( ipckey = ftok ( TMPFILE, FTOKID_CREDS ) ) == -1 )
    {
        printf ( "ftok: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    };
    if ( ( mqd = msgget ( ipckey, 0 ) ) == -1 )
    {
        printf ( "msgget: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        exit ( 0 );
    };

    if ( ( msg.creds.uid = getuid() ) == 0 )
    {
        #ifndef DEBUG
        printf ( "You are trying to run lpfw's frontend as root. Such possibility is disabled due to securitty reasons. Please rerun as a non-priviledged user\n" );
        return -1;
        #endif
    }

    strncpy ( msg.creds.tty, ttyname ( 0 ), TTYNAME - 1 );
    if ( !strncmp ( msg.creds.tty, "/dev/tty", 8 ) )
    {
        printf ( "You are trying to run lpfw's frontend from a tty terminal. Such possibility is disabled in this version of lpfw due to security reasons. Try to rerun this command from within an X terminal\n" );
        return -1;
    }

    char *display;
    if ( ( display = getenv ( "DISPLAY" ) ) == NULL )
    {
        printf ( "DISPLAY environment variable is not set (tip:usually it looks like  :0.0\n" );
        return -1;
    }
    strncpy ( msg.creds.display, display, DISPLAYNAME - 1 );

    int cli_args; //number of arguments that need to be passed to frontend
    cli_args = argc-2; //first two parms are path and --cli/--gui/--guipy
    strncpy (msg.creds.params[0], argv[1], 16);
    
    int i =0;
    if ( cli_args > 0 && cli_args < 5 ) //4 parms max - the last parm should be 0
    {
        msg.creds.params[1][0] = cli_args; //first parm has the total number of parms for lpfwcli (itself excluding)
        for ( i=0; i<cli_args; ++i )
        {
            strncpy ( msg.creds.params[i+2], argv[2+i], 16 );
        }
    }
    msg.creds.params[i+2][0] = 0; //the last parm should be 0

    if ( msgsnd ( mqd, &msg, sizeof ( msg_struct_creds ), 0 ) == -1 )
    {
        printf ( "msgsnd: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    };

    //we need to sleep a little because lpfw is extracting out path from /proc/PID/exe
    //if we quit immediately, this information won't be available
    sleep ( 3 );
    return 0;
}

void SIGTERM_handler ( int signal )
{

    if ( remove ( pid_file->filename[0] ) != 0 )
        m_printf ( MLOG_INFO, "remove PIDFILE: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );

    rulesfileWrite();
    //release netfilter_queue resources
    m_printf ( MLOG_INFO,"deallocating nfqueue resources...\n" );
    if ( nfq_close ( globalh_out ) == -1 )
    {
        m_printf ( MLOG_INFO,"error in nfq_close\n" );
    }
    return;
}

int main ( int argc, char *argv[] )
{
    //argv[0] is the  path of the executable
    if ( argc >= 2 )
    {
        if (!strcmp (argv[1],"--cli")  || !strcmp(argv[1],"--gui") || !strcmp(argv[1],"--guipy"))
        {
            return frontend_mode ( argc, argv );
        }
    }

    checkRoot();

    //install SIGTERM handler
    struct sigaction sa;
    sa.sa_handler = SIGTERM_handler;
    sigemptyset ( &sa.sa_mask );
    if ( sigaction ( SIGTERM, &sa, NULL ) == -1 )
    {
        perror ( "sigaction" );
    }

    //save own path
   int ownpid;
   char ownpidstr[16];
   ownpid = getpid();
   char exepath[PATHSIZE];
   strcpy(exepath,"/proc/");
   sprintf(ownpidstr, "%d", ownpid );
   strcat(exepath, ownpidstr);
   strcat(exepath, "/exe");
   memset(ownpath,0,PATHSIZE);
   readlink(exepath,ownpath,PATHSIZE-1);   
      
    int basenamelength;
    basenamelength = strlen ( strrchr ( ownpath, '/' ) +1 );
    strncpy ( owndir, ownpath, strlen ( ownpath )-basenamelength );



    //command line parsing contributed by Ramon Fried
    // if the parsing of the arguments was unsuccessful
    int nerrors;

    // Define argument table structs
    logging_facility = arg_str0 ( NULL, "logging-facility", "<file>,<stdout>,<syslog>", "Divert loggin to..." );
    rules_file = arg_file0 ( NULL, "rules-file", "<path to file>", "Rules output file" );
    pid_file = arg_file0 ( NULL, "pid-file", "<path to file>", "PID output file" );
    log_file = arg_file0 ( NULL, "log-file", "<path to file>", "Log output file" );
    
    cli_path = arg_file0 ( NULL, "cli-path", "<path to file>", "Path to CLI frontend" );
    gui_path = arg_file0 ( NULL, "gui-path", "<path to file>", "Path to GUI frontend" );
    guipy_path = arg_file0 ( NULL, "guipy-path", "<path to file>", "Path to Python-based GUI frontend" );
    
    log_info = arg_int0 ( NULL, "log-info", "<1/0 for yes/no>", "Info messages logging" );
    log_traffic = arg_int0 ( NULL, "log-traffic", "<1/0 for yes/no>", "Traffic logging" );
    log_debug = arg_int0 ( NULL, "log-debug", "<1/0 for yes/no>", "Debug messages logging" );
    
    struct arg_lit *help = arg_lit0 ( NULL, "help", "Display help screen" );
    struct arg_lit *version = arg_lit0 ( NULL, "version", "Display the current version" );
    struct arg_end *end = arg_end ( 20 );
    void *argtable[] = {logging_facility, rules_file, pid_file, log_file, cli_path, gui_path, guipy_path, log_info, log_traffic, log_debug, help, version, end};

    // Set default value to structs.
    logging_facility->sval[0] = "stdout";
    rules_file->filename[0] = "/etc/lpfw.rules";
    pid_file->filename[0] = "/var/log/lpfw.pid";
    log_file->filename[0] = "/tmp/lpfw.log";
    
    char clipath[PATHSIZE-16];
    strcpy (clipath, owndir);
    strcat(clipath, "lpfwcli");
    cli_path->filename[0] = clipath;
    
    char guipath[PATHSIZE-16];
    strcpy (guipath, owndir);
    strcat(guipath, "lpfwgui");
    gui_path->filename[0] = guipath;
    
    char guipypath[PATHSIZE -16];
    strcpy (guipypath, owndir);
    strcat(guipypath,"lpfwgui.py");
    guipy_path->filename[0] = guipypath;
    
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
        return 1;
    }

    nerrors = arg_parse ( argc, argv, argtable );

    if ( nerrors == 0 )
    {
        if ( help->count == 1 )
        {
            printf ( "Leopard Flower:\n Syntax and help:\n" );
            arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
            return 0;
        }
        else if ( version->count == 1 )
        {
            printf ( "%s\n", VERSION );
            return 0;
        }
    }/* --leave this for future debugging purposes
        printf("\nArguments detected:\n");
        printf("--ipc-method = %s \n", ipc_method->sval[0]);
        printf("--login-facility = %s \n", logging_facility->sval[0]);
        printf("--rules_file = %s \n", rules_file->filename[0]);
        printf("--pid-file = %s \n", pid_file->filename[0]);
        printf("--log-file = %s \n", log_file->filename[0]);
        printf("--log-info = %d \n", log_info->count);
        printf("--log-error = %d \n", log_error->count);
        printf("--log-debug = %d \n", log_debug->count);
        printf("--help = %d \n", help->count);
        printf("--version = %d \n", version->count);
*/
    else if ( nerrors > 0 )
    {
        arg_print_errors ( stdout, end, "Leopard Flower" );
        printf ( "Leopard Flower:\n Syntax and help:\n" );
        arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
        return 1;
    }

    // Free memory - don't do this cause args needed later on
    //  arg_freetable(argtable, sizeof (argtable) / sizeof (argtable[0]));

    loggingInit();
    pidFileCheck();
    msgq_init();
    initialize_conntrack();
   
    if ( system ( "iptables -I OUTPUT 1 -p all -m state --state NEW -j NFQUEUE --queue-num 11220" ) == -1 )
        m_printf ( MLOG_INFO, "system: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    if ( system ( "iptables -I INPUT 1 -p all -m state --state NEW -j NFQUEUE --queue-num 11221" ) == -1 )
        m_printf ( MLOG_INFO, "system: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    if ( system ( "iptables -I OUTPUT 1 -d localhost -j ACCEPT" ) == -1 )
	m_printf ( MLOG_INFO, "system: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
    if ( system ( "iptables -I INPUT 1 -d localhost -j ACCEPT" ) == -1 )
	m_printf ( MLOG_INFO, "system: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );


    //-----------------Register queue handler-------------
    int nfqfd;
    globalh_out = nfq_open();
    if ( !globalh_out ) m_printf ( MLOG_INFO, "error during nfq_open\n" );
    if ( nfq_unbind_pf ( globalh_out, AF_INET ) < 0 ) m_printf ( MLOG_INFO, "error during nfq_unbind\n" );
    if ( nfq_bind_pf ( globalh_out, AF_INET ) < 0 ) m_printf ( MLOG_INFO, "error during nfq_bind\n" );
    struct nfq_q_handle * globalqh = nfq_create_queue ( globalh_out, NFQNUM_OUTPUT, &nfq_handle_out, NULL );
    if ( !globalqh ){
        m_printf ( MLOG_INFO, "error in nfq_create_queue. Please make sure that any other instances of Leopard Flower are not running and restart the program. Exitting\n" );
        return 0;
    }
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    if ( nfq_set_mode ( globalqh, NFQNL_COPY_PACKET, 40 ) < 0 ) m_printf ( MLOG_INFO, "error in set_mode\n" );
    if ( nfq_set_queue_maxlen ( globalqh, 300 ) == -1 ) m_printf ( MLOG_INFO, "error in queue_maxlen\n" );
    nfqfd = nfq_fd ( globalh_out );
    m_printf ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------
    
    
    //-----------------Register queue handler for INPUT chain-----
    globalh_in = nfq_open();
    if ( !globalh_in ) m_printf ( MLOG_INFO, "error during nfq_open\n" );
    if ( nfq_unbind_pf ( globalh_in, AF_INET ) < 0 ) m_printf ( MLOG_INFO, "error during nfq_unbind\n" );
    if ( nfq_bind_pf ( globalh_in, AF_INET ) < 0 ) m_printf ( MLOG_INFO, "error during nfq_bind\n" );
    struct nfq_q_handle * globalqh_input = nfq_create_queue ( globalh_in, NFQNUM_INPUT, &nfq_handle_in, NULL );
    if ( !globalqh_input ){
        m_printf ( MLOG_INFO, "error in nfq_create_queue. Please make sure that any other instances of Leopard Flower are not running and restart the program. Exitting\n" );
        return 0;
    }
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    if ( nfq_set_mode ( globalqh_input, NFQNL_COPY_PACKET, 40 ) < 0 ) m_printf ( MLOG_INFO, "error in set_mode\n" );
    if ( nfq_set_queue_maxlen ( globalqh_input, 300 ) == -1 ) m_printf ( MLOG_INFO, "error in queue_maxlen\n" );
    nfqfd_input = nfq_fd ( globalh_in );
    m_printf ( MLOG_DEBUG, "nfqueue handler registered\n" );
    //--------Done registering------------------

    //initialze dlist first(reference) element
    if ( ( first = ( dlist * ) malloc ( sizeof ( dlist ) ) ) == NULL )
    {
        m_printf ( MLOG_INFO, "malloc: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        die();
    }
    first->prev = NULL;
    first->next = NULL;

    //initialze dlist copy's first(reference) element
    if ( ( copy_first = ( dlist * ) malloc ( sizeof ( dlist ) ) ) == NULL )
    {
        m_printf ( MLOG_INFO, "malloc: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        die();
    }
    copy_first->prev = NULL;
    copy_first->next = NULL;

    //initialize first item in cache
    if ( ( first_cache = malloc ( MAX_CACHE*32 )) == NULL ){perror("malloc");}
    memset(first_cache,0,MAX_CACHE*32);



    rules_load();
    pthread_create ( &refresh_thread, NULL, refreshthread, NULL );
#ifdef DEBUG
    pthread_create ( &rulesdump_thread, NULL, rulesdumpthread, NULL );
#endif
    pthread_create ( &nfqinput_thread, NULL, nfqinputthread, NULL);
    pthread_create ( &ct_del_thread, NULL, ct_delthread, NULL );
    pthread_create ( &cachebuild_thread, NULL, cachebuildthread, NULL );


    

    if ( ( tcpinfo = fopen ( TCPINFO, "r" ) ) == NULL ){
        m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return PROCFS_ERROR;
    }
    if ( ( tcp6info = fopen ( TCP6INFO, "r" ) ) == NULL ){
        m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return PROCFS_ERROR;
    }
    if ( ( udpinfo = fopen ( UDPINFO, "r" ) ) == NULL ){
        m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return PROCFS_ERROR;
    }
    if ( ( udp6info = fopen (UDP6INFO, "r" ) ) == NULL ){
        m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return PROCFS_ERROR;
    }
    procnetrawfd = open ( "/proc/net/raw", O_RDONLY );


    if ((tcp_membuf=(char*)malloc(MEMBUF_SIZE)) == NULL) perror("malloc");
    memset(tcp_membuf,0, MEMBUF_SIZE);

    if ((tcp6_membuf=(char*)malloc(MEMBUF_SIZE)) == NULL) perror("malloc");
    memset(tcp6_membuf,0, MEMBUF_SIZE);

    if ((udp_membuf=(char*)malloc(MEMBUF_SIZE)) == NULL) perror("malloc");
    memset(udp_membuf,0, MEMBUF_SIZE);

    if ((udp6_membuf=(char*)malloc(MEMBUF_SIZE)) == NULL) perror("malloc");
    memset(udp6_membuf,0, MEMBUF_SIZE);
    
    //endless loop of receiving packets and calling a handler on each packet
    int rv;
    char buf[4096] __attribute__ ( ( aligned ) );
    while ( ( rv = recv ( nfqfd, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
        nfq_handle_packet ( globalh_out, buf, rv );
    }
}
// kate: indent-mode cstyle; space-indent on; indent-width 4; 
