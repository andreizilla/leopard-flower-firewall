#include "common/includes.h"
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>


extern int ( *m_printf ) ( int loglevel, char *logstring);
extern int dlist_add ( char *path, char *pid, char *perms, mbool active, char *sha, unsigned long long stime, off_t size, int nfmark, unsigned char first_instance);
extern pthread_mutex_t dlist_mutex;
extern dlist *first_rule;
extern char logstring[PATHSIZE];
extern pthread_mutex_t logstring_mutex;


#define M_PRINTF(loglevel, ...) \
    pthread_mutex_lock(&logstring_mutex); \
    snprintf (logstring, PATHSIZE, __VA_ARGS__); \
    m_printf (loglevel, logstring); \
    pthread_mutex_unlock(&logstring_mutex); \
 



int test1()
{
  //	Test if refresh_thread is working:
  //1. create a new process
  //2. add it to dlist
  //3. check that it has been added to dlist successfully
  //4. terminate the process
  //5. make sure its entry in procfs doesnt exist anymore
  //6. sleep REFRESH_INTERVAL+1 sec
  //7. make sure the rule is not in dlist anymore(it should have been deleted by refresh_thread)

  pid_t childpid;
  pid_t parentpid;
  parentpid = getpid();
  char exepath[PATH_MAX];
  char pidstr[16];

  if ((childpid = fork()) == -1)
    {
      M_PRINTF ( MLOG_DEBUG, "fork: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return -1;
    }
  if (childpid == 0) //child
    {
      pid_t ownpid;
      ownpid = getpid();
      sprintf(pidstr, "%d", (int)ownpid);
      printf ("Forked a child with PID: %s\n", pidstr);
      //lookup own name
      char exelink[32] = "/proc/";
      strcat(exelink, pidstr);
      strcat(exelink, "/exe");
      memset ( exepath , 0, PATH_MAX);
      //readlink fails if PID isn't running
      if ( readlink ( exelink, exepath, PATH_MAX ) == -1 )
        {
          M_PRINTF ( MLOG_DEBUG, "readlink: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
          return -1;
        }
      printf ("Own path is %s\n", exepath);
      dlist_add(exepath, pidstr, DENY_ALWAYS, TRUE, "0", 0 , 0, 0, 0 );
      return;
    }
  if (childpid > 0) //parent
    {
      int stat_loc;
      wait(childpid, &stat_loc, 0); //wait for child to return
      sleep(REFRESH_INTERVAL+1);
      dlist *temp;
      pthread_mutex_lock(&dlist_mutex);
      temp = first_rule;
      while (temp->next != NULL)
        {
          temp = temp->next;
          if (!strcmp(temp->pid, pidstr))
            {
              printf("PID is still in dlist\n");
              pthread_mutex_unlock(&dlist_mutex);
              return -1;
            }
        }
      pthread_mutex_unlock(&dlist_mutex);
      return 1;
    }
}


int test2 ()
{

  //TEST No2 send a tcp out packet and check to see if it's pid&port is detected correctly
  int sock;
  struct sockaddr_in server;
  const struct sockaddr_in client = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY,
    .sin_port = htons(48879)
              };




  if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      strerror(errno);
      return -1;
    }
  if (bind(sock, ( const struct sockaddr *) &client, sizeof(client)) < 0)
    {
      strerror(errno);
      return -1;
    }

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr("1.1.1.1");
  server.sin_port = htons(1);
  fcntl(sock, F_SETFL, O_NONBLOCK);  //dont block on connect
  if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
      strerror(errno);
      return -1;
    }

  //now make sure it is our process who owns sport
  int socket;
  int port = 48879;
  if (port2socket_tcp(&port, &socket) != GOTO_NEXT_STEP)
    {
      return -1;
    }
  char path[PATHSIZE];
  char pid[PIDLENGTH];
  char perms[PERMSLENGTH];
  if (socket_find_in_proc(&socket, path, pid, perms) != GOTO_NEXT_STEP)
    {
      return -1;
    }
  int foundpid;
  foundpid = atoi(pid);
  if (getpid() != foundpid)
    {
      return -1;
    }
  else
    {
      return 1;
    }
  close(sock);
}


void * run_tests(void *ptr)
{
  int test1retval, test2retval;
  //let all other threads in main initialize
  sleep(1);
  test1retval = test1();
  if (test1retval == 1)
    {
      printf("Test 1 passed \n");
    }
  else
    {
      printf("Test 1 FAILED \n");
    }

  test2retval = test2();
  if (test2retval == 1)
    {
      printf("Test 2 passed \n");
    }
  else
    {
      printf("Test 2 FAILED \n");
    }
  exit(0);
}
