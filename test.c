#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include "argtable/argtable2.h"

#include "common/includes.h"
#include "test.h"

extern int ( *m_printf ) ( int loglevel, char *logstring);
extern int ruleslist_add ( char *path, char *pid, char *perms, mbool active, char *sha, unsigned long long stime, off_t size, int nfmark, unsigned char first_instance);
extern pthread_mutex_t dlist_mutex;
extern ruleslist *first_rule;
extern char logstring[PATHSIZE];
extern pthread_mutex_t logstring_mutex;
extern int socket_procpidfd_search ( const long *mysocket, char *m_path, char *m_pid, unsigned long long *stime );
extern long is_tcp_port_in_cache (const int *port);


FILE *test_log_stream;

int test_refresh_thread()
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
      fprintf ( test_log_stream, "fork: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return -1;
    }
  if (childpid == 0) //child
    {
      pid_t ownpid;
      ownpid = getpid();
      sprintf(pidstr, "%d", (int)ownpid);
      fprintf (test_log_stream, "Forked a child with PID: %s\n", pidstr);
      //lookup own name
      char exelink[32] = "/proc/";
      strcat(exelink, pidstr);
      strcat(exelink, "/exe");
      memset ( exepath , 0, PATH_MAX);
      //readlink fails if PID isn't running
      if ( readlink ( exelink, exepath, PATH_MAX ) == -1 )
        {
	  fprintf ( test_log_stream, "readlink: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
          return -1;
        }
      fprintf (test_log_stream, "Own path is %s\n", exepath);
      ruleslist_add(exepath, pidstr, DENY_ALWAYS, TRUE, "0", 0 , 0, 0, 0 );
      exit(0);
    }
  if (childpid > 0) //parent
    {
      int stat_loc;
      wait(childpid, &stat_loc, 0); //wait for child to return
      sleep(REFRESH_INTERVAL+1);
      ruleslist *temp;
      pthread_mutex_lock(&dlist_mutex);
      temp = first_rule;
      while (temp->next != NULL)
        {
          temp = temp->next;
          if (!strcmp(temp->pid, pidstr))
            {
	      fprintf(test_log_stream, "PID is still in dlist\n");
              pthread_mutex_unlock(&dlist_mutex);
              return -1;
            }
        }
      pthread_mutex_unlock(&dlist_mutex);
      return 1;
    }
}


int test_send_tcp ()
{

  //TEST No2 send a tcp out packet and check to see if it's pid&port is detected correctly
  //Also check if the packet actually hits the NFQUEUE handler
  int sock;
  struct sockaddr_in server;
  const struct sockaddr_in client = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY,
    .sin_port = htons(48879)};

  if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      fprintf ( test_log_stream, "socket: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return -1;
    }
  if (bind(sock, ( const struct sockaddr *) &client, sizeof(client)) < 0)
    {
      fprintf ( test_log_stream, "bind: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return -1;
    }

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr("1.1.1.1");
  server.sin_port = htons(1);
  fcntl(sock, F_SETFL, O_NONBLOCK);  //dont block on connect
  if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
      fprintf ( test_log_stream, "connect: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
    }
  sleep(1);

  //now make sure it is our process who owns sport
  long socket;
  int port = 48879;
  if ((socket = is_tcp_port_in_cache(&port)) == -1)
    {
      fprintf ( test_log_stream, "is_tcp_port_in_cache not found\n");
      return -1;
    }
  char path[PATHSIZE];
  char pid[PIDLENGTH];
  char perms[PERMSLENGTH];
  long long unsigned int stime;

  if (socket_procpidfd_search ( &socket, path, pid, &stime ) != SOCKET_FOUND_IN_PROCPIDFD)
  {
      fprintf ( test_log_stream, "socket_procpidfd_search not found\n");
      return -1;
  }

  close(sock);

  int foundpid;
  foundpid = atoi(pid);
  if (getpid() != foundpid)
    {
      fprintf ( test_log_stream, "pids dont match \n");
      return -1;
    }
  else
    {
      return 1;
    }
}

int test_send_udp ()
{

  //TEST No2 send a tcp out packet and check to see if it's pid&port is detected correctly
  int sock;
  struct sockaddr_in server;
  const struct sockaddr_in client = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY,
    .sin_port = htons(48878)};

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
      fprintf ( test_log_stream, "socket: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return -1;
    }
  if (bind(sock, ( const struct sockaddr *) &client, sizeof(client)) < 0)
    {
      fprintf ( test_log_stream, "bind: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return -1;
    }

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr("1.1.1.1");
  server.sin_port = htons(1);
  char buf[12];

  if (sendto(sock, buf, sizeof(buf), 0, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
      fprintf ( test_log_stream, "connect: %s in %s:%d\n", strerror ( errno ), __FILE__, __LINE__ );
    }
  sleep(1);

  //now make sure it is our process who owns sport
  long socket;
  int port = 48878;
  if ((socket = is_udp_port_in_cache(&port)) == -1)
    {
      fprintf ( test_log_stream, "is_udp_port_in_cache not found\n");
      return -1;
    }
  char path[PATHSIZE];
  char pid[PIDLENGTH];
  char perms[PERMSLENGTH];
  long long unsigned int stime;

  if (socket_procpidfd_search ( &socket, path, pid, &stime ) != SOCKET_FOUND_IN_PROCPIDFD)
  {
      fprintf ( test_log_stream, "socket_procpidfd_search not found\n");
      return -1;
  }

  close(sock);

  int foundpid;
  foundpid = atoi(pid);
  if (getpid() != foundpid)
    {
      fprintf ( test_log_stream, "pids dont match \n");
      return -1;
    }
  else
    {
      return 1;
    }
}



void * unittest_thread(void *ptr)
{
  int retval;
  if ( ( test_log_stream = fopen ( TEST_LOGFILE, "w") ) == NULL )
    {
      perror ( "open testlog" );
    }

  retval = test_refresh_thread();
  if (retval == 1){fprintf(test_log_stream, "Test 1 passed \n");}
  else{fprintf(test_log_stream,"Test 1 FAILED \n");}

  retval = test_send_tcp();
  if (retval == 1){fprintf(test_log_stream, "Test 2 passed \n");}
  else{fprintf(test_log_stream, "Test 2 FAILED \n");}

  retval = test_send_udp();
  if (retval == 1){fprintf(test_log_stream, "Test 3 passed \n");}
  else{fprintf(test_log_stream, "Test 3 FAILED \n");}


  exit(0);
}
