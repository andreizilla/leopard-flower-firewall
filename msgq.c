#include "sys/ipc.h"
#include <syslog.h>
#include <string.h>
#include <stdlib.h> //for exit
#include <pthread.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <errno.h>
#include "defines.h"
#include "includes.h"
#include <malloc.h>
#include <dirent.h> //for ino_t
#include <sys/time.h>
#include <grp.h>
#include <sys/stat.h>
#include "argtable/argtable2.h" //for some externs

//Forward declarations needed for kdevelop to do code parsing correctly
int fe_ask_out(char*, char*, unsigned long long*);
int fe_ask_in(char *path, char *pid, unsigned long long *stime, char *ipaddr, int sport, int dport);

int fe_list();
void msgq_init();


//These externs are initialized in lpfw.c
extern char ownpath[PATHSIZE];
extern char owndir[PATHSIZE];
extern msg_struct msg_d2f;
extern msg_struct msg_f2d; // = {MSGQNUM_F2D_CHAR, " "};
extern msg_struct msg_d2flist; // = {MSGQNUM_F2D_CHAR, " "};
extern msg_struct msg_d2fdel; // = {MSGQNUM_F2D_CHAR, " "};
extern msg_struct_creds msg_creds;
extern int (*m_printf)(int loglevel, char *format, ...);
extern void dlist_add ( char *path, char *pid, char *perms, char current, char *sha, unsigned long long stime, off_t size, int nfmark, unsigned char first_instance );
extern unsigned long long starttimeGet(int mypid);
extern void fe_active_flag_set (int boolean);
extern void child_close_nfqueue();
extern int sha512_stream(FILE *stream, void *resblock);
extern dlist * dlist_copy();
extern struct arg_file *cli_path, *gui_path, *guipy_path;
extern pthread_mutex_t nfmark_count_mutex, msgq_mutex;
extern int nfmark_count;



//message queue id - communication link beteeen daemon and frontend
int mqd_d2f, mqd_f2d, mqd_d2flist, mqd_d2fdel, mqd_creds;
struct msqid_ds *msgqid_d2f, *msgqid_f2d, *msgqid_d2flist, *msgqid_d2fdel, *msgqid_creds;

    pthread_t command_thread, regfrontend_thread;

    gid_t lpfwuser_gid;

    //flag to show that fe is processing our query
    int fe_awaiting_reply = FALSE;
    //struct of what was sent to f.e.dd
    dlist sent_to_fe_struct;

 // register frontend when "lpfw --cli" is invoked.The thread is restarted by invoking phread_create towards the enf of it
 void* fe_reg_thread(void* ptr){
    ptr = 0;
    //TODO: Paranoid anti spoofing measures: only allow one msg_struct_creds packet on the queue first get the current struct
    
    //block until message is received
    if (msgrcv(mqd_creds, &msg_creds, sizeof (msg_struct_creds), 0, 0) == -1) {
        m_printf(MLOG_INFO, "msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    //extract last sender's PID and check the binary path is the same path as this lpfw instance
    msgctl(mqd_creds, IPC_STAT, msgqid_creds);
    pid_t pid;
    char procpath[32] = "/proc/";
    char exepath[PATHSIZE];
    char pidstring[8];
    pid = msgqid_creds->msg_lspid;
    sprintf(pidstring, "%d", (int)pid); //convert int to char*
    strcat(procpath, pidstring);
    strcat(procpath, "/exe");
    memset(exepath, 0, PATHSIZE);

    //lpfw --cli sleeps only 3 secs, after which procpath isnt available, so no breakpoints before the next line
    readlink(procpath, exepath, PATHSIZE - 1);
#ifdef DEBUG
    printf("%s, %s\n",  exepath, ownpath);
#endif
    if (strcmp(exepath, ownpath)){
        m_printf(LOG_ALERT, "Red alert!!! Some application is trying to impersonate the frontend\n");
        return ;
    }
    //The following checks are already performed by frontend_register(). This is redundant, but again, those hackers are unpredictable
#ifndef DEBUG
    if (msg_creds.creds.uid  == 0){
        m_printf (LOG_INFO, "You are trying to run lpfw's frontend as root. Such possibility is disabled due to security reasons. Please rerun as an unpriviledged user\n");
        return ;
    }
#endif

        if (!strncmp(msg_creds.creds.tty, "/dev/tty", 8)){
       m_printf (LOG_INFO, "You are trying to run lpfw's frontend from a tty terminal. Such possibility is disabled in this version of lpfw due to security reasons. Try to rerun this command from within an X terminal\n");
        return ;
    }

    //fork, setuid exec xterm and wait for its termination
    //probably some variables become unavailable in child
    pid_t child_pid;
    child_pid =  fork();
    if (child_pid == 0){ //child process
        child_close_nfqueue();
        setgid(lpfwuser_gid);
        setuid(msg_creds.creds.uid);
	
        //check that frontend file exists and launch it
	struct stat path_stat;
	if (!strcmp (msg_creds.creds.params[0], "--cli")){
	   if (stat(cli_path->filename[0], &path_stat) == -1 ){
            m_printf(MLOG_INFO, "stat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	    if (errno == ENOENT){
	    m_printf(MLOG_INFO, "Unable to find %s\n", cli_path->filename[0]); 
	    }
	    return;
	   }
	    
	   //6th arg here should be pathtofrontend
        execl("/usr/bin/xterm", "/usr/bin/xterm", "-display", msg_creds.creds.display,
	      "+hold",
	      "-e", cli_path->filename[0],"magic_number",  
	      msg_creds.creds.params[1][0]?msg_creds.creds.params[2]:(char*)0, //check if there are any parms and if yes,process the first one
	      msg_creds.creds.params[3][0]?msg_creds.creds.params[3]:(char*)0, //check if the parm is the last one
	      msg_creds.creds.params[4][0]?msg_creds.creds.params[4]:(char*)0,
	      msg_creds.creds.params[5][0]?msg_creds.creds.params[5]:(char*)0,
	      (char*)0);
	//if exec returns here it means there was an error
	m_printf(MLOG_INFO, "execl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);    
	}
	else if (!strcmp (msg_creds.creds.params[0], "--gui")){
	   if (stat(gui_path->filename[0], &path_stat) == -1 ){
            m_printf(MLOG_INFO, "stat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	    if (errno == ENOENT){
	    m_printf(MLOG_INFO, "Unable to find %s\n", gui_path->filename[0]); 
	    }
	    return;

	   }
	  execl (gui_path->filename[0], gui_path->filename[0], (char*)0);
	  //if exec returns here it means there was an error
	m_printf(MLOG_INFO, "execl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);    
	}
	else if (!strcmp (msg_creds.creds.params[0], "--guipy")){
	 if (stat(guipy_path->filename[0], &path_stat) == -1 ){
            m_printf(MLOG_INFO, "stat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	    if (errno == ENOENT){
	    m_printf(MLOG_INFO, "Unable to find %s\n", guipy_path->filename[0]); 
	    }
	    return;
	 }
	 execl ("/usr/bin/python", "python",guipy_path->filename[0], (char*)0);
	   //if exec returns here it means there was an error
	m_printf(MLOG_INFO, "execl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);    
     
    }
	}
    if (child_pid > 0){ //parent
        int status;
        //wait until chils terminates
       if (wait(&status) == (pid_t)-1){
           perror("wait");
       }
        //frontend should unregister itself upon exit, else it's crashed
        if (fe_active_flag_get()){
            m_printf(MLOG_INFO, "Frontend apparently crashed, unregistering...\n");
	    fe_awaiting_reply = FALSE;
            fe_active_flag_set(FALSE);
        }
        m_printf(MLOG_INFO, "frontend exited\n");
            pthread_create(&regfrontend_thread, NULL, fe_reg_thread, NULL);
            return;
        
    }
    if (child_pid == -1){
        perror("fork");
    }

}

// wait for commands from frontend
void* commandthread(void* ptr){
    ptr = 0;
    dlist *temp;
 
    // continue statement doesn't apply to switch it causes to jump to while()
    while (1) {
        //block until message is received from frontend:
        if (msgrcv(mqd_f2d, &msg_f2d, sizeof (msg_struct), 0, 0) == -1) {
            m_printf(MLOG_INFO, "msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        }
#ifdef DEBUG
    struct timeval time_struct;
        gettimeofday(&time_struct, NULL);
        m_printf(MLOG_DEBUG, "Received command %d @ %d %d\n", msg_f2d.item.command, (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif
	
        switch (msg_f2d.item.command) {
            case F2DCOMM_LIST:
                ;
		//TODO a memory leak here, because dlist_copy mallocs memory that is never freed
                temp = (dlist *) dlist_copy();

                temp = temp->next;
                //check if the list is empty and let frontend know
                if (temp == NULL) {
                    strcpy(msg_d2flist.item.path, "EOF");
                    if (msgsnd(mqd_d2flist, &msg_d2flist, sizeof (msg_struct), 0) == -1) {
                        m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                    }
                    m_printf(MLOG_DEBUG, "sent EOF\n");
                    continue;
                }
                while (temp != NULL) {
                    strcpy(msg_d2flist.item.path, temp->path);
                    strcpy(msg_d2flist.item.pid, temp->pid);
                    strcpy(msg_d2flist.item.perms, temp->perms);
                    msg_d2flist.item.current_pid = temp->current_pid;
                    if (msgsnd(mqd_d2flist, &msg_d2flist, sizeof (msg_struct), 0) == -1) {
                        m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                    }
                    if (temp->next == NULL) {
                        strcpy(msg_d2flist.item.path, "EOF");
                        if (msgsnd(mqd_d2flist, &msg_d2flist, sizeof (msg_struct), 0) == -1) {
                            m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                        }
                        break;
                    }
                    temp = temp->next;
                };
                continue;

            case F2DCOMM_DELANDACK:
                dlist_del(msg_f2d.item.path, msg_f2d.item.pid);
                if (msgsnd(mqd_d2fdel, &msg_d2fdel, sizeof (msg_struct), 0) == -1) {
                    m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                }
                continue;

            case F2DCOMM_WRT:
#ifdef DEBUG
                gettimeofday(&time_struct, NULL);
                m_printf(MLOG_DEBUG, "Before writing  @%d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif
                rulesfileWrite();
#ifdef DEBUG
                gettimeofday(&time_struct, NULL);
                m_printf(MLOG_DEBUG, "After  writing @ %d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif
                continue;

            case F2DCOMM_ADD:
	      ;
	      if (!strcmp(msg_f2d.item.perms,"IGNORED")){
		fe_awaiting_reply = FALSE;
		continue;  
	      }	
#ifdef DEBUG
	      gettimeofday(&time_struct, NULL);
              m_printf(MLOG_DEBUG, "Before adding  @%d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif

                //TODO come up with a way to calculate sha without having user to wait when the rule appears

	//if perms are *ALWAYS we need both exesize and sha512
	      	    char sha[DIGEST_SIZE] = "";
		    struct stat exestat;
        if (!strcmp(msg_f2d.item.perms,ALLOW_ALWAYS) || !strcmp(msg_f2d.item.perms,DENY_ALWAYS)){
               
        //Calculate the size of the executable       
	if (stat(sent_to_fe_struct.path, &exestat) == -1 ){
            m_printf(MLOG_INFO, "stat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	    }
			
		//Calculate sha of executable
            FILE *stream;
            memset(sha, 0, DIGEST_SIZE+1);
            stream = fopen(sent_to_fe_struct.path, "r");
            sha512_stream(stream, (void *) sha);
            fclose(stream);		
	       }
	       //check if we were really dealing with the correct process all along
	       unsigned long long stime;
                stime = starttimeGet ( atoi ( sent_to_fe_struct.pid ) );
                if ( sent_to_fe_struct.stime != stime )
                {
                    m_printf ( MLOG_INFO, "Red alert!!!Start times don't match %s %s %d", temp->path,  __FILE__, __LINE__ );
                    continue;
                }

//TODO SECURITY. We should check now that /proc/PID inode wasn't changed while we were shasumming and exesizing
		
		  int nfmark;
		   pthread_mutex_lock ( &nfmark_count_mutex );
                    nfmark = NFMARK_BASE + nfmark_count;
                    nfmark_count++;
                    pthread_mutex_unlock ( &nfmark_count_mutex );
		
                dlist_add(sent_to_fe_struct.path, sent_to_fe_struct.pid, msg_f2d.item.perms, '1', sha, sent_to_fe_struct.stime, exestat.st_size, nfmark ,TRUE);
#ifdef DEBUG
       gettimeofday(&time_struct, NULL);
	m_printf(MLOG_DEBUG,"After  adding @ %d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif
	fe_awaiting_reply = FALSE;
                continue;

                 case F2DCOMM_REG:
                if (fe_active_flag_get()) {
                    m_printf(MLOG_ALERT, "Red alert!!! There was an attempt to register a frontend when one is already active\n");
                    continue;
                }
                fe_active_flag_set(TRUE);
                m_printf(MLOG_INFO, "Registered frontend\n");
                continue;

            case F2DCOMM_UNREG:
                if (!fe_active_flag_get()) {
                    m_printf(MLOG_ALERT, "Red alert!!! There was an attempt to unregister a frontend when none is active\n");
                    continue;
                }
                 fe_active_flag_set(FALSE);
		 fe_awaiting_reply = FALSE;
                m_printf(MLOG_INFO, "Unregistered frontend\n");
                continue;

            default: m_printf(MLOG_INFO, "unknown command");
        }
    }
}

    void msgq_init() {

    //First we need to create/(check existence of) lpfwuser group and add ourselves to it
    errno = 0;
    struct group *m_group;
    m_group = getgrnam("lpfwuser");
    if (!m_group) {
        if (errno == 0) {
            m_printf(MLOG_INFO, "lpfwuser group does not exit, creating...\n");
            if (system("groupadd lpfwuser") == -1) {
                m_printf(MLOG_INFO, "error in system()\n");
                return;
            }
            //get group id again after group creation
            errno = 0;
            m_group = getgrnam("lpfwuser");
            if(!m_group){
                if (errno == 0){
                    m_printf (MLOG_INFO, "lpfwuser group still doesn't exist even though we've just created it");
                }
                else{
                    perror ("getgrnam");
                }
            }
            lpfwuser_gid = m_group->gr_gid;
        } else {
            printf("Error in getgrnam\n");
        perror ("getgrnam");
        }
        return;
    }
    //when debugging, we add user who launches frontend to lpfwuser group, hence disable this check
#ifndef DEBUG
    if (!(m_group->gr_mem[0] == NULL)){
        m_printf (MLOG_INFO, "lpfwuser group contains users. This group should not contain any users. This is a security issue. Please remove all user from that group and restart application. Exitting\n");
        exit(0);
    }
#endif
    lpfwuser_gid = m_group->gr_gid;
    if (setgid(lpfwuser_gid) == -1){
        perror ("setgid ");
        return;
    }

    msgqid_d2f = malloc(sizeof (struct msqid_ds));
    msgqid_f2d = malloc(sizeof (struct msqid_ds));
    msgqid_d2flist = malloc(sizeof (struct msqid_ds));
    msgqid_d2fdel = malloc(sizeof (struct msqid_ds));
    msgqid_creds = malloc(sizeof (struct msqid_ds));

    key_t ipckey_d2f, ipckey_f2d, ipckey_d2flist, ipckey_d2fdel, ipckey_creds;
    if (remove(TMPFILE) != 0)
        m_printf(MLOG_DEBUG, "remove: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    if (creat(TMPFILE,
      //make world readable to avoid permission cock-us during debugging
#ifdef DEBUG 
	      0666
#else
	      0004
#endif
    ) == 1)
        m_printf(MLOG_INFO, "creat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    //-----------------------------------
    if ((ipckey_d2f = ftok(TMPFILE, FTOKID_D2F)) == -1)
        m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    m_printf(MLOG_DEBUG, "Key: %d\n", ipckey_d2f);

    if ((ipckey_f2d = ftok(TMPFILE, FTOKID_F2D)) == -1)
        m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    m_printf(MLOG_DEBUG, "Key: %d\n", ipckey_f2d);

    if ((ipckey_d2flist = ftok(TMPFILE, FTOKID_D2FLIST)) == -1)
        m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    m_printf(MLOG_DEBUG, "Key: %d\n", ipckey_d2flist);

    if ((ipckey_d2fdel = ftok(TMPFILE, FTOKID_D2FDEL)) == -1)
        m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    m_printf(MLOG_DEBUG, "Key: %d\n", ipckey_d2fdel);

    if ((ipckey_creds = ftok(TMPFILE, FTOKID_CREDS)) == -1)
        m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    m_printf(MLOG_DEBUG, "Key: %d\n", ipckey_creds);

    /* Set up the message queue to communicate between daemon and GUI*/
    //we need to first get the Qid, then use this id to delete Q
    //then create it again, thus ensuring the Q is cleared

    //message queues D2F are only readable to group members 0040
    //whereas F2D are writable 0020
    //lpfw is run by root and it has read/write permissions anyway
    
#define GROUP_READABLE_ONLY 0040
#define GROUP_WRITABLE_ONLY 0020
#define OTHERS_WRITABLE_ONLY 0002
#define WORLD_ACCESS 0666

int read_bits, write_bits, creds_bits;

#ifdef DEBUG
read_bits = WORLD_ACCESS;
write_bits = WORLD_ACCESS;
creds_bits = WORLD_ACCESS;
#else
read_bits = GROUP_READABLE_ONLY;
write_bits = GROUP_WRITABLE_ONLY;
creds_bits = OTHERS_WRITABLE_ONLY;
#endif

    if ((mqd_d2f = msgget(ipckey_d2f, IPC_CREAT | read_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    //remove queue
    msgctl(mqd_d2f, IPC_RMID, 0);
    //create it again
    if ((mqd_d2f = msgget(ipckey_d2f, IPC_CREAT | read_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    m_printf(MLOG_DEBUG, "Message identifier %d\n", mqd_d2f);
    //----------------------------------------------------
    if ((mqd_d2flist = msgget(ipckey_d2flist, IPC_CREAT | read_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    //remove queue
    msgctl(mqd_d2flist, IPC_RMID, 0);
    //create it again
    if ((mqd_d2flist = msgget(ipckey_d2flist, IPC_CREAT | read_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    m_printf(MLOG_DEBUG, "Message identifier %d\n", mqd_d2flist);

    //---------------------------------------------------------

    if ((mqd_f2d = msgget(ipckey_f2d, IPC_CREAT | write_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    //remove queue
    msgctl(mqd_f2d, IPC_RMID, 0);
    //create it again
    if ((mqd_f2d = msgget(ipckey_f2d, IPC_CREAT | write_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    m_printf(MLOG_DEBUG, "Message identifier %d\n", mqd_f2d);

    //------------------------------------------------------
    if ((mqd_d2fdel = msgget(ipckey_d2fdel, IPC_CREAT | read_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    //remove queue
    msgctl(mqd_d2fdel, IPC_RMID, 0);
    //create it again
    if ((mqd_d2fdel = msgget(ipckey_d2fdel, IPC_CREAT | read_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    m_printf(MLOG_DEBUG, "Message identifier %d\n", mqd_d2fdel);

    //------------------------------------------------------
    //This particular message queue should be writable by anyone, hence permission 0002
    //because we don't know in advance what user will be invoking the frontend

    if ((mqd_creds = msgget(ipckey_creds, IPC_CREAT | creds_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    //remove queue
    msgctl(mqd_creds, IPC_RMID, 0);
    //create it again
    if ((mqd_creds = msgget(ipckey_creds, IPC_CREAT | creds_bits)) == -1) {
        m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    m_printf(MLOG_DEBUG, "Creds msgq id %d\n", mqd_creds);

    pthread_create(&command_thread, NULL, commandthread, NULL);
    pthread_create(&regfrontend_thread, NULL, fe_reg_thread, NULL);

}

    //obsolete func
int notify_frontend(int command, char *path, char *pid, unsigned long long stime) {

    switch (command) {
        case D2FCOMM_ASK_OUT:
            //prepare a msg and send it to frontend
            strcpy(msg_d2f.item.path, path);
            strcpy(msg_d2f.item.pid, pid);
            msg_d2f.item.stime = stime;
            msg_d2f.item.command = D2FCOMM_ASK_OUT;
            //pthread_mutex_lock(&mutex_msgq);
            if (msgsnd(mqd_d2f, &msg_d2f, sizeof (msg_struct), IPC_NOWAIT) == -1) {
                m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            }
            return 4;

        case D2FCOMM_LIST:
            msg_d2f.item.command = D2FCOMM_LIST;
            if (msgsnd(mqd_d2f, &msg_d2f, sizeof (msg_struct), IPC_NOWAIT) == -1)
                m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            return -1;
    }
}

//Ask frontend
int fe_ask_out(char *path, char *pid, unsigned long long *stime) {
    if (fe_awaiting_reply) return FRONTEND_BUSY;

    //first remember what we are sending
    strcpy(sent_to_fe_struct.path, path);
    strcpy(sent_to_fe_struct.pid, pid);
    sent_to_fe_struct.stime = *stime;

            //prepare a msg and send it to frontend
            strcpy(msg_d2f.item.path, path);
            strcpy(msg_d2f.item.pid, pid);
            msg_d2f.item.command = D2FCOMM_ASK_OUT;
            //pthread_mutex_lock(&mutex_msgq);
            if (msgsnd(mqd_d2f, &msg_d2f, sizeof (msg_struct), IPC_NOWAIT) == -1) {
                m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            }
            fe_awaiting_reply = TRUE;
            return SENT_TO_FRONTEND;
}

//Ask frontend if new incoming connection should be allowed
int fe_ask_in(char *path, char *pid, unsigned long long *stime, char *ipaddr, int sport, int dport) {
              return SENT_TO_FRONTEND;
    pthread_mutex_lock(&msgq_mutex); 
    if (fe_awaiting_reply) return FRONTEND_BUSY;

    //first remember what we are sending
    strcpy(sent_to_fe_struct.path, path);
    strcpy(sent_to_fe_struct.pid, pid);
    sent_to_fe_struct.stime = *stime;

    //prepare a msg and send it to frontend
    strcpy(msg_d2f.item.path, path);
    strcpy(msg_d2f.item.pid, pid);
    msg_d2f.item.command = D2FCOMM_ASK_IN;
    //next fields of struct will be simply re-used. Not nice, but what's wrong with re-cycling?
    strncpy(msg_d2f.item.perms, ipaddr, sizeof(msg_d2f.item.perms));
    msg_d2f.item.stime = sport;
    msg_d2f.item.inode = dport;
	    
	    
            if (msgsnd(mqd_d2f, &msg_d2f, sizeof (msg_struct), IPC_NOWAIT) == -1) {
                m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            }
            fe_awaiting_reply = TRUE;
	    pthread_mutex_unlock(&msgq_mutex);
            return SENT_TO_FRONTEND;
}

int fe_list() {
            msg_d2f.item.command = D2FCOMM_LIST;
            if (msgsnd(mqd_d2f, &msg_d2f, sizeof (msg_struct), IPC_NOWAIT) == -1)
                m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
