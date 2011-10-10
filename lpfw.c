#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h> //required for netfilter.h
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
#include <arpa/inet.h> //for ntohl()
#include <linux/netfilter.h> //for NF_ACCEPT, NF_DROP etc
#include <assert.h>
#include "includes.h"
#include "defines.h"
#include "argtable/argtable2.h"
#include "version.h" //for version string during packaging

//should be available globally to call nfq_close from sigterm handler
struct nfq_handle* globalh;

//command line arguments available globally
struct arg_str *ipc_method, *logging_facility, *frontend;
struct arg_file *rules_file, *pid_file, *log_file, *cli_path, *gui_path, *guipy_path;
struct arg_int *log_info, *log_traffic, *log_debug;

// holds path to /proc/<pid>/fd/<number_of_inode_opened>
char path[32];
char fdpath[32];
char ownpath[PATHSIZE]; //full path of lpfw executable
char owndir[PATHSIZE]; //full path to the dir lpfw executable is in (with trailing /)

//vars for scanning through /proc dir
struct dirent *proc_dirent, *fd_dirent;
DIR *proc_DIR, *fd_DIR;

// buffers to hold readlink()ed values of /proc/<pid>/exe and /proc/<pid>/fd/<inode>
char exepathbuf[PATHSIZE];
char socketbuf[SOCKETBUFSIZE];

//file descriptors for /proc/net/tcd & udp
int procnettcpfd, procnetudpfd, procnetrawfd;
FILE *fileloginfo_stream, *filelogtraffic_stream, *filelogdebug_stream;

//cryptic stuff that is required by netfilter_queue
struct nfq_q_handle *qh;
struct nfgenmsg *nfmsg;
struct nfq_data *nfad;
void *mdata;

//first element of dlist is an empty one,serves as reference to determine the start of dlist
dlist *first, *copy_first;

//type has to be initialized to one, otherwise if it is 0 we'll get EINVAL on msgsnd
msg_struct msg_d2f = {1, 0};
msg_struct msg_f2d = {1, 0};
msg_struct msg_d2fdel = {1, 0};
msg_struct msg_d2flist = {1, 0};
msg_struct_creds msg_creds = {1, 0};
int ( *m_printf ) ( int loglevel, char *format, ... );

extern int fe_ask ( char*, char*, unsigned long long* );
extern int fe_list();
extern void msgq_init();
extern int sha512_stream ( FILE *stream, void *resblock );
extern int fe_awaiting_reply;

//Forward declarations to make code parser happy
void dlist_add ( char*, char*, char*, char, char*, unsigned long long, off_t, unsigned char );


//mutex to lock threads
pthread_mutex_t dlist_mutex = PTHREAD_MUTEX_INITIALIZER;
//thread which listens for command and thread which scans for rynning apps and removes them from the dlist
pthread_t refresh_thread, rulesdump_thread;

//flag which shows whether frontend is running
int fe_active_flag = 0;

//in case if system's byte order is little-endian, use htonl() in nfq_set_verdict_mark due to libnetfiler_queue's bug which was fixed in v.1.0.0 but ubuntu 10.10 and 11.04 still uses old 0.17 version
int little_endian = 1;

//mutex to lock fe_active_flag
pthread_mutex_t fe_active_flag_mutex = PTHREAD_MUTEX_INITIALIZER;

//netfilter mark number for the packet (to be added to NF_MARK_BASE)
int nfmark_count = 0;
//netfilter mark to be put on an ALLOWed packet
int nfmark_verdict;

void child_close_nfqueue()
{
    if ( nfq_close ( globalh ) == -1 )
    {
        m_printf ( MLOG_INFO,"error in nfq_close\n" );
        return;
    }
    m_printf ( MLOG_DEBUG, "Done closing nfqueue\n" );
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

//obsolete func since we now use procfs inode to determine if the same instance is accessing network
//yet this may prove useful in the future for extra checking
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
    int strlen_int;
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
        strlen_int = strlen ( temp->path );
        strcpy ( copy_temp->path, temp->path );
        strcpy ( copy_temp->perms, temp->perms );
        strcpy ( copy_temp->pid, temp->pid );
        copy_temp->current_pid = temp->current_pid;

        temp = temp->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );
    //lets see if copy dlist needs to be shrunk
    copy_temp = copy_temp->next;
    while ( copy_temp != 0 )
    {
        del = copy_temp;
        //prev element should point not on us but on the next element
        copy_temp->prev->next = copy_temp->next;
        copy_temp = copy_temp->next;
        free ( del );
    }
    return copy_first;
}

//Add new element to dlist
void dlist_add ( char *path, char *pid, char *perms, char current, char *sha, unsigned long long stime, off_t size, unsigned char first_instance )
{
    pthread_mutex_lock ( &dlist_mutex );
    dlist *temp = first;
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
    temp->current_pid = current;
    temp->stime = stime;
    memcpy ( temp->sha, sha, DIGEST_SIZE );
    temp->exesize = size;
    temp->first_instance = first_instance; //obsolete member,can be purged
    pthread_mutex_unlock ( &dlist_mutex );
}

//Remove element from dlist...
void dlist_del ( char *path, char *pid )
{
    pthread_mutex_lock ( &dlist_mutex );
    dlist *temp = first->next;
    while ( temp != NULL )
    {
        if ( !strcmp ( temp->path, path ) && !strcmp ( temp->pid, pid ) )
        {
            //remove the item
            temp->prev->next = temp->next;
            if ( temp->next != NULL )
                temp->next->prev = temp->prev;
            free ( temp );
            pthread_mutex_unlock ( &dlist_mutex );
            return;
        }
        temp = temp->next;
    }
    m_printf ( MLOG_INFO, "%s with PID %s was not found in dlist\n", path, pid );
    pthread_mutex_unlock ( &dlist_mutex );
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
            fputc ( temp->current_pid, fd );
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
    char mypath[32];
    char buf[PATHSIZE];

    while ( 1 )
    {
        sleep ( 5 );
        pthread_mutex_lock ( &dlist_mutex );
        temp = first->next;
        while ( temp != NULL )
        {
            //check if we have the processes actual PID
            if ( temp->current_pid == '0' )
            {
                temp = temp->next;
                continue;
            }

            strcpy ( mypath, "/proc/" );
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
                //if it's an ALLOW/DENY ALWAYS rule, we don't delete it, see if it is the only rule for this PATH, if yes then just toggle the current_pid flag, otherwise if there are already entries for this path, then remove our rule
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
                    temp->current_pid = '0';
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
    char line[PATHSIZE];
    char *result;
    char perms[PERMSLENGTH];
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

        dlist_add ( path, "0", perms, '0', digest, 2, ( off_t ) sizeint, TRUE );
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

            //don't proceed until data is written to disk
            fsync ( fileno ( fd ) );
        }
        temp = temp->next;
    }
    pthread_mutex_unlock ( &dlist_mutex );
    fclose ( fd );
}

//if path is in dlist already, check if it is fork()ed or a new instance
int path_find_in_dlist ( char *path, char *pid, unsigned long long *stime )
{
    pthread_mutex_lock ( &dlist_mutex );
    //first check if app is already in our dlist
    dlist* temp = first->next;

    while ( temp != NULL )
    {
        if ( !strcmp ( temp->path, path ) )
        {
            if ( temp->current_pid == '0' ) //path is in dlist and has not a current PID. It was added to dlist from rulesfile. Exesize and shasum this app just once
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
                temp->current_pid = '1';
                temp->stime = *stime;

                int retval;
                if ( !strcmp ( temp->perms, ALLOW_ONCE ) || !strcmp ( temp->perms, ALLOW_ALWAYS ) )
                {
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
            else if ( temp->current_pid == '1' )
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
                    return -1;
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

//is it a fork()ed child? the "parent" above may not be the actual parent of this fork, e.g. there may be two or three instances of an app running aka three "parents". We have to rescan dlist to ascertain

                dlist * temp = first->next;
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
                        strcpy ( tempperms2, temp->perms );
                        memcpy ( tempsha2, temp->sha, DIGEST_SIZE );

                        pthread_mutex_unlock ( &dlist_mutex );

                        unsigned long long stime;
                        stime = starttimeGet ( atoi ( pid ) );

                        dlist_add ( path, pid, tempperms2, '1', tempsha2, stime, parent_size2, FALSE );
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
                            dlist_add ( path, pid, tempperms, '1', tempsha, *stime, parent_size, FALSE );
                            fe_list();
                            return NEW_INSTANCE_ALLOW;
                        }
                        else if ( !strcmp ( temp2->perms, DENY_ALWAYS ) )
                        {
                            pthread_mutex_unlock ( &dlist_mutex );
                            dlist_add ( path, pid, tempperms, '1', tempsha, *stime, parent_size, FALSE );
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
    return 0;
}

//scan only those /proc entries that are already in the dlist
// and only those that have a current PID (meaning the app has already sent a packet)
int socket_find_in_dlist ( int *mysocket )
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
        if ( temp->current_pid == '0' )
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
            m_printf ( MLOG_DEBUG, "opendir %s: %s,%s,%d\n", path, strerror ( errno ), __FILE__, __LINE__ );
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
    return 0;
}

//scan /proc to find which PID the socket belongs to
int socket_find_in_proc ( int *mysocket, char *m_path, char *m_pid, unsigned long long *stime )
{
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
                m_printf ( MLOG_INFO, "Unusual! PID exited while we were scanning /proc . opendir: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
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


                        m_printf ( MLOG_DEBUG, "%s %s ", exepathbuf, proc_dirent->d_name );
                        closedir ( fd_DIR );
                        closedir ( proc_DIR );
                        strcpy ( m_path, exepathbuf );
                        strcpy ( m_pid, proc_dirent->d_name );
                        m_printf ( MLOG_TRAFFIC, "%s %s ", m_path, m_pid );
                        return 0;
                    }
                }
            }
            while ( fd_dirent );
        }
    }
    while ( proc_dirent );
    closedir ( proc_DIR );
    return INODE_NOT_FOUND_IN_PROC;
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

//find in procfs which socket corresponds to source port
int port2socket_udp ( int *portint, int *socketint )
{
    //convert portint to a hex string of 4 chars with leading zeroes if necessary
    char porthex[5];
    sprintf ( porthex, "%x", *portint );
    //if hex string < 4 chars, we need to add leading zeroes, so e.g. AF looks 00AF
    int porthexsize;
    if ( ( porthexsize = strlen ( porthex ) ) < 4 )
    {
        char tempstring[5];
        strcpy ( tempstring,porthex );
        //empty the string
        porthex[0] = 0;
        int i;
        for ( i = 0; i < ( 4-porthexsize ); i++ )
        {
            strcat ( porthex, "0" );
        }
        //restore porthhex (now with leading zeroes)
        strcat ( porthex, tempstring );
    }
    //change all abcdef to ABCDEF
    int size;
    for ( size = 0; size < 4; ++size )
    {
        porthex[size] = toupper ( porthex[size] );
    }   

    FILE *udpinfo, *udp6info;
    char buffer[PATHSIZE];
    char procport[12];
    char socketstr[16];

    //read /proc/net/tcp line by line finding a line with porthex and extracting inode string
    if ( ( udpinfo = fopen ( UDPINFO, "r" ) ) == NULL )
    {
        m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return PROCFS_ERROR;
    }
    do
    {
        errno = 0;//because fgets returns NULL both on error and EOF
        if ( fgets ( buffer, sizeof ( buffer ), udpinfo ) == NULL )
        {
            if ( errno == 0 ) //NULL returned but errno not set => EOF reached
            {
                fclose ( udpinfo );
                //Let's see if we are dealing with an IPv4 packets over IPv6 socket
                if ( ( udp6info = fopen ( UDP6INFO, "r" ) ) == NULL )
                {
                    m_printf ( MLOG_INFO, "udpinfo: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                    return PROCFS_ERROR;
                }
                do
                {
                    errno = 0;//because fgets returns NULL both on error and EOF
                    if ( !fgets ( buffer, sizeof ( buffer ), udp6info ) )
                    {
                        if ( errno == 0 ) //NULL returned but errno not set => EOF reached
                        {
                            fclose ( udp6info );
                            return PORT_NOT_FOUND;
                        } //else
                        m_printf ( MLOG_INFO, "fgets: %s, errno:%d %s,%d\n", strerror ( errno ), errno, __FILE__, __LINE__ );
                    }
                    //else fgets returned no error
                    strncpy ( procport, &buffer[40],4 );
                    procport[4] = 0;
                    if ( strcmp ( porthex, procport ) ) continue;
                    fclose ( udp6info );
                    strncpy ( socketstr, &buffer[140], 8 );
                    m_printf ( MLOG_DEBUG, " IPv6 ");
                    goto socket_match;
                }
                while ( !feof ( udp6info ) );
                fclose ( udp6info );
                return PORT_NOT_FOUND;
            }
            //else there was an error int fgets for tcpinfo
            m_printf ( MLOG_INFO, "fgets: %s, errno:%d %s,%d\n", strerror ( errno ), errno, __FILE__, __LINE__ );
        }
        //else no error for fgets for tcpinfo
        strncpy ( procport, &buffer[16], 4 );
        procport[4] = 0;
        if ( strcmp ( porthex, procport ) ) continue;
        //else
        fclose ( udpinfo );
        strncpy ( socketstr, &buffer[92], 8 );

    socket_match:
        ;
        int i;
        for ( i = 0; i < 8; ++i )
        {
            if ( socketstr[i] == 32 )
            {
                socketstr[i] = 0; // 0x20 space, see /proc/net/tcp
                break;
            }
        }
        *socketint = atoi ( socketstr );
        return 0;
    }
    while ( !feof ( udpinfo ) );
    fclose ( udpinfo );
    return PORT_NOT_FOUND;
}



//find in procfs which socket corresponds to source port
int port2socket_tcp ( int *portint, int *socketint )
{
    //convert portint to a hex string of 4 chars with leading zeroes if necessary
    char porthex[5];
    sprintf ( porthex, "%x", *portint );
    //if hex string < 4 chars, we need to add leading zeroes, so e.g. AF looks 00AF
    int porthexsize;
    if ( ( porthexsize = strlen ( porthex ) ) < 4 )
    {
        char tempstring[5];
        strcpy ( tempstring,porthex );
        //empty the string
        porthex[0] = 0;
        int i;
        for ( i = 0; i < ( 4-porthexsize ); i++ )
        {
            strcat ( porthex, "0" );
        }
        //restore porthhex (now with leading zeroes)
        strcat ( porthex, tempstring );
    }
    //change all abcdef to ABCDEF
    int size;
    for ( size = 0; size < 4; ++size )
    {
        porthex[size] = toupper ( porthex[size] );
    }

    FILE *tcpinfo, *tcp6info;
    char buffer[PATHSIZE];
    char procport[12];
    char socketstr[16];

    //read /proc/net/tcp line by line finding a line with porthex and extracting inode string
    if ( ( tcpinfo = fopen ( TCPINFO, "r" ) ) == NULL )
    {
        m_printf ( MLOG_INFO, "fopen: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
        return PROCFS_ERROR;
    }
    do
    {
        errno = 0;//because fgets returns NULL both on error and EOF
        if ( fgets ( buffer, sizeof ( buffer ), tcpinfo ) == NULL )
        {
            if ( errno == 0 ) //NULL returned but errno not set => EOF reached
            {
                fclose ( tcpinfo );
                 //Let's see if we are dealing with an IPv4 packets over IPv6 socket
                    if ( ( tcp6info = fopen ( TCP6INFO, "r" ) ) == NULL )
                    {
                        m_printf ( MLOG_INFO, "tcpinfo: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
                        return PROCFS_ERROR;
                    }
                do
                {
                    errno = 0;//because fgets returns NULL both on error and EOF
                    if ( !fgets ( buffer, sizeof ( buffer ), tcp6info ) )
                    {
                        if ( errno == 0 ) //NULL returned but errno not set => EOF reached
                        {
                            fclose ( tcp6info );
                            return PORT_NOT_FOUND;
                        } //else
                        m_printf ( MLOG_INFO, "fgets: %s, errno:%d %s,%d\n", strerror ( errno ), errno, __FILE__, __LINE__ );
                    }
                    //else fgets returned no error
                    strncpy ( procport, &buffer[39],4 );
                    procport[4] = 0;
                    if ( strcmp ( porthex, procport ) ) continue;
                    fclose ( tcp6info );
                    strncpy ( socketstr, &buffer[139], 8 );
                    m_printf ( MLOG_DEBUG, " IPv6 ");
                    goto socket_match;
                }
                while ( !feof ( tcp6info ) );
                fclose ( tcp6info );
                return PORT_NOT_FOUND;
            }
            //else there was an error int fgets for tcpinfo
            m_printf ( MLOG_INFO, "fgets: %s, errno:%d %s,%d\n", strerror ( errno ), errno, __FILE__, __LINE__ );
        }
        //else no error for fgets for tcpinfo
        strncpy ( procport, &buffer[15], 4 );
        procport[4] = 0;
        if ( strcmp ( porthex, procport ) ) continue;
        //else
        fclose ( tcpinfo );
        strncpy ( socketstr, &buffer[91], 8 );

    socket_match:
        ;
        int i;
        for ( i = 0; i < 8; ++i )
        {
            if ( socketstr[i] == 32 )
            {
                socketstr[i] = 0; // 0x20 space, see /proc/net/tcp
                break;
            }
        }
        *socketint = atoi ( socketstr );
        return 0;
    }
    while ( !feof ( tcpinfo ) );
    fclose ( tcpinfo );
    return PORT_NOT_FOUND;
}

//Handler for TCP packets
int packet_handle_tcp ( int *srctcp )
{
    int retval;
    int socketint;

    //each function returns 0 when it is OK to go to the next step, otherwise  it returns one of the verdict values
    if ( retval = port2socket_tcp ( srctcp, &socketint ) ) goto out;
    if ( retval = socket_find_in_dlist ( &socketint ) ) goto out;
    char path[PATHSIZE];
    char pid[PIDLENGTH];
    unsigned long long stime;
    if ( retval = socket_find_in_proc ( &socketint, path, pid, &stime ) ) goto out;
    if ( retval = path_find_in_dlist ( path, pid, &stime ) ) goto out;

    if ( !fe_active_flag_get() )
    {
        retval = FRONTEND_NOT_ACTIVE;
        goto out;
    }
    if ( retval = fe_ask ( path, pid, &stime ) ) goto out;

out:
    return retval;

}



//Handler for UDP packets
int packet_handle_udp ( int *srcudp )
{
    int retval;
    int socketint;

    //each function returns 0 when it is OK to go to the next step, otherwise  it returns one of the verdict values
    if ( retval = port2socket_udp ( srcudp, &socketint ) ) goto out;
    if ( retval = socket_find_in_dlist ( &socketint ) ) goto out;
    char path[PATHSIZE];
    char pid[PIDLENGTH];
    unsigned long long stime;
    if ( retval = socket_find_in_proc ( &socketint, path, pid, &stime ) ) goto out;
    if ( retval = path_find_in_dlist ( path, pid, &stime ) ) goto out;

    if ( !fe_active_flag_get() )
    {
        retval = FRONTEND_NOT_ACTIVE;
        goto out;
    }
    if ( retval = fe_ask ( path, pid, &stime ) ) goto out;

out:
    return retval;

}

int packet_handle_icmp()
{
    int retval;
    int inodeint;

    if ( retval = icmp_check_only_one_inode ( &inodeint ) ) goto out;
    if ( retval = socket_find_in_dlist ( &inodeint ) ) goto out;
    char path[PATHSIZE];
    char pid[PIDLENGTH];
    unsigned long long stime;

    if ( retval = socket_find_in_proc ( &inodeint, path, pid, &stime ) ) goto out;
    if ( retval = path_find_in_dlist ( path, pid, &stime ) ) goto out;
    if ( !fe_active_flag_get() )
    {
        retval = FRONTEND_NOT_ACTIVE;
        goto out;
    }
    if ( retval = fe_ask ( path, pid, &stime ) ) goto out;

out:
    return retval;
}

//this function is invoked each time a packet arrives to NFQUEUE
int queueHandle ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata )
{
#ifdef DEBUG2
    struct timeval time_struct;
    gettimeofday ( &time_struct, NULL );
    m_printf ( MLOG_DEBUG, "%s.%d\n", ctime ( &time_struct.tv_sec ), ( int ) time_struct.tv_usec );
#endif

    char *data;
    int id;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr ( ( struct nfq_data * ) nfad );
    if ( ph ) id = ntohl ( ph->packet_id );
    nfq_get_payload ( ( struct nfq_data * ) nfad, &data );
    //struct iphdr takes care of endianness itself
    struct iphdr *ip = ( struct iphdr* ) data;
#ifdef DEBUG
    m_printf ( MLOG_TRAFFIC, "%d ", ip->version );
#endif
    unsigned char daddr[4];
    daddr[0] = ip->daddr & 0xFF;
    daddr[1] = ( ip->daddr >> 8 ) & 0xFF;
    daddr[2] = ( ip->daddr >> 16 ) & 0xFF;
    daddr[3] = ( ip->daddr >> 24 ) & 0xFF;
    int verdict;
    switch ( ip->protocol )
    {
    case IPPROTO_TCP:
        ;
        // ihl field is IP header length in 32-bit words, multiply by 4 to get length in bytes
        struct tcphdr *tcp;
        tcp = ( struct tcphdr* ) ( data + ( 4 * ip->ihl ) );
        int srctcp = ntohs ( tcp->source );
        int dsttcp = ntohs ( tcp->dest );
        m_printf ( MLOG_TRAFFIC, "TCP src %d dst %d.%d.%d.%d:%d ", srctcp, daddr[0], daddr[1], daddr[2], daddr[3], dsttcp );
        verdict = packet_handle_tcp ( &srctcp );
        break;
    case IPPROTO_UDP:
        ;
        struct udphdr *udp;
        udp = ( struct udphdr * ) ( data + ( 4 * ip->ihl ) );
        int srcudp = ntohs ( udp->source );
        int dstudp = ntohs ( udp->dest );
        m_printf ( MLOG_TRAFFIC, "UDP src %d dst %d.%d.%d.%d:%d ", srcudp, daddr[0], daddr[1], daddr[2], daddr[3], dstudp );
        verdict = packet_handle_udp ( &srcudp );
        break;
    case IPPROTO_ICMP:
        ;
        m_printf ( MLOG_TRAFFIC, "ICMP dst %d.%d.%d.%d ", daddr[0], daddr[1], daddr[2], daddr[3] );
        verdict = packet_handle_icmp();
        break;
    default:
        m_printf ( MLOG_INFO, "unsupported protocol detected No. %d (lookup in /usr/include/netinet/in.h)\n", ip->protocol );
        m_printf ( MLOG_INFO, "see FAQ on how to securely let this protocol use the internet" );
        verdict = UNSUPPORTED_PROTOCOL;
    }

    switch ( verdict )
    {
    case ACCEPT:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "allow\n" );
        return 0;

    case INODE_FOUND_IN_DLIST_ALLOW:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "allow\n" );
        return 0;

    case PATH_FOUND_IN_DLIST_ALLOW:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "allow\n" );
        return 0;

    case NEW_INSTANCE_ALLOW:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "allow\n" );
        return 0;

    case FORKED_CHILD_ALLOW:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "allow\n" );
        return 0;

    case DROP:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "drop\n" );
        return 0;

    case PORT_NOT_FOUND:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_ACCEPT, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "packet's source port not found in /proc. Very unusual, please report.\n" );
        return 0;
    case SENT_TO_FRONTEND:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "sent to frontend, dont block the nfqueue - silently drop it\n" );
        return 0;
    case INODE_NOT_FOUND_IN_PROC:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "socket associates with packet was not found in /proc. Very unusual, please report\n" );
        return 0;

    case INODE_FOUND_IN_DLIST_DENY:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "deny\n" );
        return 0;

    case PATH_FOUND_IN_DLIST_DENY:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "deny\n" );
        return 0;

    case NEW_INSTANCE_DENY:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "deny\n" );
        return 0;
    case FRONTEND_NOT_ACTIVE:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "frontend is not active, dropping\n" );
        return 0;
    case FRONTEND_BUSY:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "frontend is busy, dropping\n" );
        return 0;
    case UNSUPPORTED_PROTOCOL:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "Unsupported protocol, dropping\n" );
        return 0;
    case ICMP_MORE_THAN_ONE_ENTRY:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "More than one program is using icmp, dropping\n" );
        return 0;
    case ICMP_NO_ENTRY:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "icmp packet received by there is no icmp entry in /proc. Very unusual. Please report\n" );
        return 0;
    case SHA_DONT_MATCH:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "Red alert. Some app is trying to impersonate another\n" );
        return 0;
    case STIME_DONT_MATCH:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "Red alert. Some app is trying to impersonate another\n" );
        return 0;
    case EXESIZE_DONT_MATCH:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "Red alert. Executable's size don't match the records\n" );
        return 0;
    case INODE_HAS_CHANGED:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "Process inode has changed, This means that a process was killed and another with the same PID was immediately started. Smacks of somebody trying to hack your system\n" );
        return 0;
    case EXE_HAS_BEEN_CHANGED:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "While process was running, someone changed his binary file on disk. Definitely an attempt to compromise the firewall\n" );
        return 0;

    case FORKED_CHILD_DENY:
        nfq_set_verdict ( ( struct nfq_q_handle * ) qh, id, NF_DROP, 0, NULL );
        m_printf ( MLOG_TRAFFIC, "deny\n" );
        return 0;
    }
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

void pidFileCheck()
{
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
    if ( nfq_close ( globalh ) == -1 )
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
    * ( log_debug->ival ) = 0;

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
   
    if ( system ( "iptables -I OUTPUT 1 -p all -m state --state NEW -j NFQUEUE --queue-num 11220" ) == -1 )
        m_printf ( MLOG_INFO, "system: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );


    procnettcpfd = open ( "/proc/net/tcp", O_RDONLY );
    procnetudpfd = open ( "/proc/net/udp", O_RDONLY );
    procnetrawfd = open ( "/proc/net/raw", O_RDONLY );

    //-----------------Register queue handler-------------
    int nfqfd;
    globalh = nfq_open();
    if ( !globalh ) m_printf ( MLOG_INFO, "error during nfq_open\n" );
    if ( nfq_unbind_pf ( globalh, AF_INET ) < 0 ) m_printf ( MLOG_INFO, "error during nfq_unbind\n" );
    if ( nfq_bind_pf ( globalh, AF_INET ) < 0 ) m_printf ( MLOG_INFO, "error during nfq_bind\n" );
    struct nfq_q_handle * globalqh = nfq_create_queue ( globalh, NFQUEUE_NUMBER, &queueHandle, NULL );
    if ( !globalqh )
        m_printf ( MLOG_INFO, "error in nfq_create_queue\n" );
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    if ( nfq_set_mode ( globalqh, NFQNL_COPY_PACKET, 40 ) < 0 ) m_printf ( MLOG_INFO, "error in set_mode\n" );
    if ( nfq_set_queue_maxlen ( globalqh, 30 ) == -1 ) m_printf ( MLOG_INFO, "error in queue_maxlen\n" );
    nfqfd = nfq_fd ( globalh );
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

    rules_load();
    pthread_create ( &refresh_thread, NULL, refreshthread, NULL );
#ifdef DEBUG
    pthread_create ( &rulesdump_thread, NULL, rulesdumpthread, NULL );
#endif

    //endless loop of receiving packets and calling a handler on each packet
    int rv;
    char buf[4096] __attribute__ ( ( aligned ) );
    while ( ( rv = recv ( nfqfd, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
    {
        nfq_handle_packet ( globalh, buf, rv );
    }
}
// kate: indent-mode cstyle; space-indent on; indent-width 4; 
