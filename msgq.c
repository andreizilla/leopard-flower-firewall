#include <sys/ipc.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h> //for exit
#include <pthread.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <errno.h>
#include <malloc.h>
#include <dirent.h> //for ino_t
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/capability.h>
#include "argtable/argtable2.h"

#include "common/defines.h"
#include "common/includes.h"
#include "main.h"
#include "msgq.h"

int awaiting_reply_from_fe;

//message queue id - communication link beteeen daemon and frontend
int mqd_d2f, mqd_f2d, mqd_d2flist, mqd_d2fdel, mqd_creds, mqd_d2ftraffic;
struct msqid_ds *msgqid_d2f, *msgqid_f2d, *msgqid_d2flist, *msgqid_d2fdel, *msgqid_creds, *msgqid_d2ftraffic;

//type has to be initialized to one, otherwise if it is 0 we'll get EINVAL on msgsnd
d2f_msg msg_f2d = {1, 0};
msg_struct msg_d2fdel = {1, 0};
msg_struct msg_d2flist = {1, 0};

pthread_t command_thread, regfrontend_thread;

//flag to show that frontend is already processing some "add" query
int awaiting_reply_from_fe = FALSE;
//struct of what was sent to f.e.dd
ruleslist sent_to_fe_struct;

//mutex to avoid fe_ask_* to send data simultaneously
pthread_mutex_t msgq_mutex;


// register frontend when "lpfw --cli" is invoked.The thread is restarted by invoking pthread_create
// towards the end of it
//OBSOLETE - frontend now starts standalone
#if 0
void*  fe_reg_thread(void* ptr)
{
  ptr = 0;
  //TODO: Paranoid anti spoofing measures: only allow one msg_struct_creds packet on the queue first get the current struct

  //block until message is received
interrupted:
  if (msgrcv(mqd_creds, &msg_creds, sizeof (msg_creds.item), 0, 0) == -1)
    {
      M_PRINTF(MLOG_DEBUG, "msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
      goto interrupted;
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

  //lpfw --cli sleeps only 3 secs, after which procpath isnt available, so no breakpoints before
  //the next line
  readlink(procpath, exepath, PATHSIZE - 1);

#ifdef DEBUG
  printf("%s, %s\n",  exepath, ownpath);
#endif
  if (strcmp(exepath, ownpath))
    {
      M_PRINTF(LOG_ALERT, "Can't start frontend because it's not located in the sane folder as lpfw\n");
      return ;
    }
  //The following checks are already performed by frontend_register(). This is redundant, but again, those hackers are unpredictable
#ifndef DEBUG
  if (msg_creds.item.uid  == 0)
    {
      M_PRINTF (LOG_INFO, "You are trying to run lpfw's frontend as root. Such possibility is disabled due to security reasons. Please rerun as an unpriviledged user\n");
      return ;
    }
#endif

  if (!strncmp(msg_creds.item.tty, "/dev/tty", 8))
    {
      M_PRINTF (LOG_INFO, "You are trying to run lpfw's frontend from a tty terminal. Such possibility is disabled in this version of lpfw due to security reasons. Try to rerun this command from within an X terminal\n");
      return ;
    }

  //fork, setuid exec xterm and wait for its termination
  //probably some variables become unavailable in child
  pid_t child_pid;
  child_pid =  fork();
  if (child_pid == 0)  //child process
    {
      child_close_nfqueue();

//      /* no need to setgid on child since gid==lpfwuser is inherited from parent
//      if (setgid(lpfwuser_gid) == -1)
//      {
//                M_PRINTF(MLOG_INFO, "setgid: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
//      }
//      */

      //enable CAP_SETUID in effective set
      cap_t cap_current;
      cap_current = cap_get_proc();
      const cap_value_t caps_list[] = {CAP_SETUID};
      cap_set_flag(cap_current,  CAP_EFFECTIVE, 1, caps_list, CAP_SET);
      cap_set_proc(cap_current);
      //setuid and immediately remove CAP_SETUID from both perm. and eff. sets
      if (setuid(msg_creds.item.uid) == -1)
        {
          M_PRINTF(MLOG_INFO, "setuid: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        }
      //no need to drop privs, they are all zeroed out upon setuid()

      struct stat path_stat;

      /* lpfwcli is now started independently, keep this just in case

      //check that frontend file exists and launch it
      if (!strcmp (msg_creds.creds.params[0], "--cli"))
        {
          if (stat(cli_path->filename[0], &path_stat) == -1 )
            {
              M_PRINTF(MLOG_INFO, "stat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
              if (errno == ENOENT)
                {
                  M_PRINTF(MLOG_INFO, "Unable to find %s\n", cli_path->filename[0]);
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
          M_PRINTF(MLOG_INFO, "execl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        }
	*/
      if (!strcmp (msg_creds.item.params[0], "--gui"))
        {
          if (stat(gui_path->filename[0], &path_stat) == -1 )
            {
              M_PRINTF(MLOG_INFO, "stat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
              if (errno == ENOENT)
                {
                  M_PRINTF(MLOG_INFO, "Unable to find %s\n", gui_path->filename[0]);
                }
              return;

            }
          execl (gui_path->filename[0], gui_path->filename[0], (char*)0);
          //if exec returns here it means there was an error
          M_PRINTF(MLOG_INFO, "execl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        }
      else if (!strcmp (msg_creds.item.params[0], "--pygui"))
        {
          if (stat(pygui_path->filename[0], &path_stat) == -1 )
            {
              M_PRINTF(MLOG_INFO, "stat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
              if (errno == ENOENT)
                {
                  M_PRINTF(MLOG_INFO, "Unable to find %s\n", pygui_path->filename[0]);
                }
              return;
            }
          execl ("/usr/bin/python", "python",pygui_path->filename[0], (char*)0);
          //if exec returns here it means there was an error
          M_PRINTF(MLOG_INFO, "execl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);

        }
    }
  if (child_pid > 0)  //parent
    {
      int status;
      //wait until chils terminates
      if (wait(&status) == (pid_t)-1)
        {
          perror("wait");
        }
      //frontend should unregister itself upon exit, else it's crashed
      if (fe_active_flag_get())
        {
          M_PRINTF(MLOG_INFO, "Frontend apparently crashed, unregistering...\n");
	  awaiting_reply_from_fe = FALSE;
          fe_active_flag_set(FALSE);
        }
      M_PRINTF(MLOG_INFO, "frontend exited\n");
      pthread_create(&regfrontend_thread, NULL, fe_reg_thread, NULL);
      return;

    }
  if (child_pid == -1)
    {
      perror("fork");
    }
}
#endif

// wait for commands from frontend
void* commandthread(void* ptr)
{
  ptr = 0;
  ruleslist *rule;

  // N.B. continue statement doesn't apply to switch it causes to jump to while()
  while (1)
    {
      //block until message is received from frontend:
interrupted:
      if (msgrcv(mqd_f2d, (void*) &msg_f2d, sizeof (msg_f2d.item), 0, 0) == -1)
        {
          M_PRINTF(MLOG_DEBUG	, "msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
          sleep(1); //avoid overwhelming the log
	  goto interrupted;
        }

#ifdef DEBUG
      struct timeval time_struct;
      gettimeofday(&time_struct, NULL);
      M_PRINTF(MLOG_DEBUG, "Received command %d @ %d %d\n", msg_f2d.item.command, (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif

      switch (msg_f2d.item.command)
        {
        case F2DCOMM_LIST:
          ;
	  rule = (ruleslist *) ruleslist_copy();
          //check if the list is empty and let frontend know
	  if (rule[0].rules_number == 1)
            {
              strcpy(msg_d2flist.item.path, "EOF");
	      if (msgsnd(mqd_d2flist, &msg_d2flist, sizeof (msg_d2flist.item), 0) == -1)
                {
                  M_PRINTF(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                }
              M_PRINTF(MLOG_DEBUG, "sent EOF\n");
	      free(rule);
              continue;
            }
	  int i = 1;
	  for (i; i < rule[0].rules_number; i++)
	  {
	      strncpy(msg_d2flist.item.path, rule[i].path, PATHSIZE);
	      strncpy(msg_d2flist.item.pid, rule[i].pid, PIDLENGTH);
	      strncpy(msg_d2flist.item.perms, rule[i].perms, PERMSLENGTH);
	      msg_d2flist.item.is_active = rule[i].is_active;
	      msg_d2flist.item.nfmark_out = rule[i].nfmark_out;
	      msgsnd(mqd_d2flist, &msg_d2flist, sizeof (msg_d2flist.item), 0);
	  };
	  strcpy(msg_d2flist.item.path, "EOF");
	  msgsnd(mqd_d2flist, &msg_d2flist, sizeof (msg_d2flist.item), 0);
	  free(rule);
          continue;

        case F2DCOMM_DELANDACK:
	  ruleslist_del(msg_f2d.item.path, msg_f2d.item.pid);
          continue;

        case F2DCOMM_WRT:
#ifdef DEBUG
          gettimeofday(&time_struct, NULL);
          M_PRINTF(MLOG_DEBUG, "Before writing  @%d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif
          rulesfileWrite();
#ifdef DEBUG
          gettimeofday(&time_struct, NULL);
          M_PRINTF(MLOG_DEBUG, "After  writing @ %d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif
          continue;

        case F2DCOMM_ADD:
          ;
          if (!strcmp(msg_f2d.item.perms,"IGNORED"))
            {
	      awaiting_reply_from_fe = FALSE;
              continue;
            }
#ifdef DEBUG
          gettimeofday(&time_struct, NULL);
          M_PRINTF(MLOG_DEBUG, "Before adding  @%d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif

          //TODO come up with a way to calculate sha without having user to wait when the rule appears
          //chaeck if the app is still running

          if (!strcmp(msg_f2d.item.path, KERNEL_PROCESS))  //don't set fe_awaiting_reply flags
            {
	      ruleslist_add(KERNEL_PROCESS, msg_f2d.item.pid, msg_f2d.item.perms, TRUE, "", 0, 0, 0 ,TRUE);
              continue;
            }

          char exepath[32] = "/proc/";
          strcat(exepath, sent_to_fe_struct.pid);
          strcat(exepath, "/exe");
          char exepathbuf[PATHSIZE];
          memset ( exepathbuf, 0, PATHSIZE );
	  readlink (exepath, exepathbuf, PATHSIZE-1 );
          if (strcmp(exepathbuf, sent_to_fe_struct.path))
            {
              M_PRINTF(MLOG_INFO, "Frontend asked to add a process that is no longer running,%s,%d\n", __FILE__, __LINE__);
	      awaiting_reply_from_fe = FALSE;
              continue;
            }

          //if perms are *ALWAYS we need both exesize and sha512
	  unsigned char sha[DIGEST_SIZE] = "";
          struct stat exestat;
          if (!strcmp(msg_f2d.item.perms,ALLOW_ALWAYS) || !strcmp(msg_f2d.item.perms,DENY_ALWAYS))
            {
              //Calculate the size of the executable
	      stat(sent_to_fe_struct.path, &exestat);

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
	      M_PRINTF ( MLOG_INFO, "Red alert!!!Start times don't match %s %s %d", rule->path,  __FILE__, __LINE__ );
	      awaiting_reply_from_fe = FALSE;
              continue;
            }

//TODO SECURITY. We should check now that /proc/PID inode wasn't changed while we were shasumming and exesizing

	  ruleslist_add(sent_to_fe_struct.path, sent_to_fe_struct.pid, msg_f2d.item.perms, TRUE, sha, sent_to_fe_struct.stime, exestat.st_size, 0 ,TRUE);
#ifdef DEBUG
          gettimeofday(&time_struct, NULL);
          M_PRINTF(MLOG_DEBUG,"After  adding @ %d %d\n", (int) time_struct.tv_sec, (int) time_struct.tv_usec);
#endif
	  awaiting_reply_from_fe = FALSE;
          continue;

        case F2DCOMM_REG:
          if (fe_active_flag_get())
            {
              M_PRINTF(MLOG_ALERT, "Red alert!!! There was an attempt to register a frontend when one is already active\n");
              continue;
            }
	  struct msqid_ds msqid_f2d;
	  if (msgctl(mqd_f2d, IPC_STAT, &msqid_f2d) == -1)
	  {
	      M_PRINTF(MLOG_DEBUG, "msgctl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	  }
	  fe_pid = msqid_f2d.msg_lspid;
	  fe_active_flag_set(TRUE);
          M_PRINTF(MLOG_INFO, "Registered frontend\n");
          continue;

        case F2DCOMM_UNREG:
          if (!fe_active_flag_get())
            {
              M_PRINTF(MLOG_ALERT, "Red alert!!! There was an attempt to unregister a frontend when none is active\n");
              continue;
            }
          fe_active_flag_set(FALSE);
	  awaiting_reply_from_fe = FALSE;
          M_PRINTF(MLOG_INFO, "Unregistered frontend\n");
          continue;

        default:
          M_PRINTF(MLOG_INFO, "unknown command in commandthread \n");
        }
    }
}

void init_msgq()
{
  msgqid_d2f = malloc(sizeof (struct msqid_ds));
  msgqid_f2d = malloc(sizeof (struct msqid_ds));
  msgqid_d2flist = malloc(sizeof (struct msqid_ds));
  //msgqid_d2fdel = malloc(sizeof (struct msqid_ds)); //not in use
  msgqid_creds = malloc(sizeof (struct msqid_ds));
  msgqid_d2ftraffic = malloc(sizeof (struct msqid_ds));

  //TODO some capabilities may be needed here, in cases when TMPFILE was created by a different user
  // or message queue with the same ID was created by a different user. Needs investigation.

  key_t ipckey_d2f, ipckey_f2d, ipckey_d2flist, ipckey_d2fdel, ipckey_creds, ipckey_d2ftraffic;
  if (remove(TMPFILE) != 0)
    {
      M_PRINTF(MLOG_DEBUG, "remove: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
  if (creat(TMPFILE,

#ifdef DEBUG       //make world readable to avoid permission cock-ups during debugging
            0666
#else
	    0660 //lpfwuser group members may RDWR
#endif

           ) == 1)
    {
      M_PRINTF(MLOG_INFO, "creat: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
  //-----------------------------------
  ipckey_d2f = ftok(TMPFILE, FTOKID_D2F);
  M_PRINTF(MLOG_DEBUG, "D2FKey: %d\n", ipckey_d2f);

  ipckey_f2d = ftok(TMPFILE, FTOKID_F2D);
  M_PRINTF(MLOG_DEBUG, "Key: %d\n", ipckey_f2d);

  ipckey_d2flist = ftok(TMPFILE, FTOKID_D2FLIST);
  M_PRINTF(MLOG_DEBUG, "Key: %d\n", ipckey_d2flist);

  ipckey_d2fdel = ftok(TMPFILE, FTOKID_D2FDEL);
  M_PRINTF(MLOG_DEBUG, "Key: %d\n", ipckey_d2fdel);

  ipckey_creds = ftok(TMPFILE, FTOKID_CREDS);
  M_PRINTF(MLOG_DEBUG, "Key: %d\n", ipckey_creds);

  ipckey_d2ftraffic = ftok(TMPFILE, FTOKID_D2FTRAFFIC);
  M_PRINTF(MLOG_DEBUG, "Key: %d\n", ipckey_d2ftraffic);

  /* Set up the message queue to communicate between daemon and GUI*/
  //we need to first get the Qid, then use this id to delete Q
  //then create it again, thus ensuring the Q is cleared

//WORLD_ACCESS perms on msgq to facilitate debugging
#define GROUP_ACCESS 0660
#define WORLD_ACCESS 0666
#define OTHERS_ACCESS 0662 //write to msgq

  int perm_bits, creds_bits;

#ifdef DEBUG
  perm_bits = WORLD_ACCESS;
  creds_bits = WORLD_ACCESS;
#else
  perm_bits = GROUP_ACCESS;
  creds_bits = OTHERS_ACCESS;
#endif

//creds_bits require special treatment b/c when user launches ./lpfw --gui, we don't know in advance
//what the user's UID is. So we allow any user to invoke the frontend.

  mqd_d2f = msgget(ipckey_d2f, IPC_CREAT | perm_bits);
  //remove queue
  msgctl(mqd_d2f, IPC_RMID, 0);
  //create it again
  mqd_d2f = msgget(ipckey_d2f, IPC_CREAT | perm_bits);
  M_PRINTF(MLOG_DEBUG, "Message identifier %d\n", mqd_d2f);
  //----------------------------------------------------
  mqd_d2flist = msgget(ipckey_d2flist, IPC_CREAT | perm_bits);
  //remove queue
  msgctl(mqd_d2flist, IPC_RMID, 0);
  //create it again
  mqd_d2flist = msgget(ipckey_d2flist, IPC_CREAT | perm_bits);
  M_PRINTF(MLOG_DEBUG, "Message identifier %d\n", mqd_d2flist);

  //---------------------------------------------------------

  mqd_f2d = msgget(ipckey_f2d, IPC_CREAT | perm_bits);
  //remove queue
  msgctl(mqd_f2d, IPC_RMID, 0);
  //create it again
  mqd_f2d = msgget(ipckey_f2d, IPC_CREAT | perm_bits);
  M_PRINTF(MLOG_DEBUG, "Message identifier %d\n", mqd_f2d);

  //------------------------------------------------------
  mqd_d2fdel = msgget(ipckey_d2fdel, IPC_CREAT | perm_bits);
  //remove queue
  msgctl(mqd_d2fdel, IPC_RMID, 0);
  //create it again
  mqd_d2fdel = msgget(ipckey_d2fdel, IPC_CREAT | perm_bits);
  M_PRINTF(MLOG_DEBUG, "Message identifier %d\n", mqd_d2fdel);

  //------------------------------------------------------
  //This particular message queue should be writable by anyone, hence permission 0002
  //because we don't know in advance what user will be invoking the frontend

  mqd_creds = msgget(ipckey_creds, IPC_CREAT | creds_bits);
  //remove queue
  msgctl(mqd_creds, IPC_RMID, 0);
  //create it again
  mqd_creds = msgget(ipckey_creds, IPC_CREAT | creds_bits);
  M_PRINTF(MLOG_DEBUG, "Creds msgq id %d\n", mqd_creds);

  //-------------------------------------------------

  mqd_d2ftraffic = msgget(ipckey_d2ftraffic, IPC_CREAT | perm_bits);
  //remove queue
  msgctl(mqd_d2ftraffic, IPC_RMID, 0);
  //create it again
  mqd_d2ftraffic = msgget(ipckey_d2ftraffic, IPC_CREAT | perm_bits);
  M_PRINTF(MLOG_DEBUG, "Traffic msgq id %d\n", mqd_d2ftraffic);

  //------------------------------------------------------------

  pthread_create(&command_thread, NULL, commandthread, NULL);
  //pthread_create(&regfrontend_thread, NULL, fe_reg_thread, NULL);

}

//obsolete func
/*
int notify_frontend(int command, char *path, char *pid, unsigned long long stime)
{

  switch (command)
    {
    case D2FCOMM_ASK_OUT:
      //prepare a msg and send it to frontend
      strcpy(msg_d2f.item.path, path);
      strcpy(msg_d2f.item.pid, pid);
      msg_d2f.item.stime = stime;
      msg_d2f.item.command = D2FCOMM_ASK_OUT;
      //pthread_mutex_lock(&mutex_msgq);
      if (msgsnd(mqd_d2f, &msg_d2f, sizeof (msg_struct), IPC_NOWAIT) == -1)
        {
          M_PRINTF(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        }
      return 4;

    case D2FCOMM_LIST:
      msg_d2f.item.command = D2FCOMM_LIST;
      if (msgsnd(mqd_d2f, &msg_d2f, sizeof (msg_struct), IPC_NOWAIT) == -1)
        {
          M_PRINTF(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        }
      return -1;
    }
}
*/

//Ask frontend
int   fe_ask_out(char *path, char *pid, unsigned long long *stime, char *daddr, int *sport, int*dport)
{
  if (pthread_mutex_trylock(&msgq_mutex) != 0) return FRONTEND_BUSY;
  if (awaiting_reply_from_fe)
    {
      pthread_mutex_unlock(&msgq_mutex);
      return FRONTEND_BUSY;
    }

  //first remember what we are sending
  strncpy(sent_to_fe_struct.path, path, PATHSIZE);
  strncpy(sent_to_fe_struct.pid, pid, PIDLENGTH);
  sent_to_fe_struct.stime = *stime;

  //prepare a msg and send it to frontend
  d2f_msg msg;
  strncpy(msg.item.path, path, PATHSIZE);
  strncpy(msg.item.pid, pid, PIDLENGTH);
  strncpy(msg.item.addr, daddr, INET_ADDRSTRLEN);
  msg.item.sport = *sport;
  msg.item.dport = *dport;
  msg.item.command = D2FCOMM_ASK_OUT;
  msg.type = 1;

  msgsnd(mqd_d2f, &msg, sizeof (msg.item), IPC_NOWAIT);
  awaiting_reply_from_fe = TRUE;
  pthread_mutex_unlock(&msgq_mutex);
  return SENT_TO_FRONTEND;
}

//Ask frontend if new incoming connection should be allowed
int fe_ask_in(const char *path, const char *pid, const unsigned long long *stime, const char *saddr,
	      const int *sport, const int *dport)
{
  if (pthread_mutex_trylock(&msgq_mutex) != 0) return FRONTEND_BUSY;
  if (awaiting_reply_from_fe)
    {
      pthread_mutex_unlock(&msgq_mutex);
      return FRONTEND_BUSY;
    }

  //first remember what we are sending
  strncpy(sent_to_fe_struct.path, path, PATHSIZE);
  strncpy(sent_to_fe_struct.pid, pid, PIDLENGTH);
  sent_to_fe_struct.stime = *stime;

  //prepare a msg and send it to frontend
  d2f_msg msg;
  strncpy(msg.item.path, path, PATHSIZE);
  strncpy(msg.item.pid, pid, PIDLENGTH);
  strncpy(msg.item.addr, saddr, INET_ADDRSTRLEN);
  msg.item.sport = *sport;
  msg.item.dport = *dport;
  msg.item.command = D2FCOMM_ASK_IN;
  msg.type = 1;

  msgsnd(mqd_d2f, &msg, sizeof (msg.item), IPC_NOWAIT);
  awaiting_reply_from_fe = TRUE;
  pthread_mutex_unlock(&msgq_mutex);
  return SENT_TO_FRONTEND;
}

int fe_list()
{
  d2f_msg msg;
  memset(&msg, 0, sizeof(msg));
  msg.item.command = D2FCOMM_LIST;
  msg.type = 1;
  msgsnd(mqd_d2f, &msg, sizeof (msg.item), IPC_NOWAIT);
}
