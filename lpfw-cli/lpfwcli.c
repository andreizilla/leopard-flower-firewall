#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <string.h>
#include <termios.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <ncurses.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdarg.h>
#include <grp.h>
#include "../common/defines.h"
#include "../common/includes.h"
#include "../argtable/argtable2.h"
#include "../version.h" //for version string during packaging


int (*m_printf)(const int loglevel, const char *logstring);
void list();

char TAB[2] = {9, 0};
//string holds daemon request
msg_struct global_struct;

dlist *first;

// lw -list window, uw - upper, tw - title, sw - status hw -help
WINDOW *sw, *lw, *tw, *uw, *hw;
WINDOW *memlw, *memuw, *memtw, *memsw, *memhw;

//current geometry of terminal
int term_width;
int term_height;
struct winsize ws;
int shiftx = 0; //viewport's shift right
int active = 0; //selected item's line no in all the list
int listsize = 0; //size of list
int view_active = 0; //selected item's line no. in viewport
//the uppermost line number in viewport
int upperline = 0;
//minimal allowable heights for windows:
int view_height = 2;
int uwheight = 2;
int twheight = 1;
int lwheight = 2;
int swheight = 1;
int hwheight = 1;

int is_being_run = 0;
int use_zenity = 1;
int use_xmessage = 0;
int use_msgq = 1;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t logstring_mutex = PTHREAD_MUTEX_INITIALIZER;

FILE *logfilefd;

int retval;
int zenity_answer;

extern  void frontend_unregister();
extern  void msgq_initialize();
extern void msgq_add(msg_struct add_struct);
extern void msgq_list();
extern void msgq_f2ddel(dlist rule, int ack_flag);

char logstring[PATHSIZE];

struct arg_file *log_file, *zenity_path;
struct arg_int *log_debug, *nozenity;


#define M_PRINTF(loglevel, ...) \
    pthread_mutex_lock(&logstring_mutex); \
    snprintf (logstring, PATHSIZE, __VA_ARGS__); \
    m_printf (loglevel, logstring); \
    pthread_mutex_unlock(&logstring_mutex); \
 




int m_printf_file(const int loglevel, const char * logstring)
{
  write ( fileno ( logfilefd ), logstring, strlen ( logstring ) );

  return 0;
}

void die()
{
  exit(0);
}

void process_verdict(int delnum)
{
  switch (delnum)
    {
    case 1:
      strcpy(global_struct.item.perms, ALLOW_ALWAYS);
      break;
    case 2:
      strcpy(global_struct.item.perms, ALLOW_ONCE);
      break;
    case 3:
      strcpy(global_struct.item.perms, DENY_ALWAYS);
      break;
    case 4:
      strcpy(global_struct.item.perms, DENY_ONCE);
      break;
    default:
      strcpy(global_struct.item.perms, "IGNORED");
      break;
    }
  //add perms and send answer to daemon
  msgq_add(global_struct);
  //add to f_array
  //farray_add(global_string);
  //list in lowerwin
  werase(lw);
  //list();
  msgq_list();
  //clear upper window
  werase(uw);
  wrefresh(uw);
  is_being_run = 0;
}


//while zenity is running, do a blocking read on stdout
// if user presses CAncel, then no read occurs and this thread keeps hanging, thus we have to cancel it
//from within zenitythread

void* threadZenity2(void *commpipe)
{
  char buf[PATHSIZE];
  int *a;
  a = (int*) commpipe;

  if (read(*a, buf, sizeof (buf)) == -1)
  {
      M_PRINTF(MLOG_ERROR, "read:%s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
      return;
  }
  zenity_answer = atoi(&buf[0]);
}

void * threadZenity(void *ptr)
{
  zenity_answer = 0;

  int commpipe[2];
  pipe(commpipe);
  pid_t pid;

  pid = fork();
  if (pid == 0)   //child
    {
      //suppress Gdk errors which litter the screen
      freopen("/dev/null", "w", stderr);

      //redirect STDOUT to our own file descriptor
      if (dup2(commpipe[1], 1) == -1)
      {
	  M_PRINTF(MLOG_ERROR, "dup2:%s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
	  return;
      }
      char zenity1[PATHSIZE] = "--text=The following program (with PID) is trying to access the network: \n";
      strcat(zenity1, global_struct.item.path);
      strcat(zenity1, "\n Please choose action:");

      //Gtk apps won't run with setgid(), so put back or real GID
      setegid(getgid());

//Run this from terminal to test this:
//zenity --list --title="request" --text="program: \n /blah \n action:" --column= 1 "ALLOW ALWAYS"
// 2 "ALLOW ONCE" 3 "DENY ALWAYS" 4 "DENY ONCE" --column= --hide-column=1  --height=240

      if (execl("/usr/bin/zenity", "/usr/bin/zenity", "--list", "--title=Leopard Flower- Permission request", zenity1,
	    "--column= ", "1", "ALLOW ALWAYS", "2", "ALLOW ONCE", "3", "DENY ALWAYS", "4", "DENY ONCE",
	    "--column= ", "--hide-column=1", "--height=240", (char *) 0) == -1)
      {
	  M_PRINTF(MLOG_ERROR, "exec:%s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
	  return;
      }

    }
  if (pid > 1)
    {
      pthread_t commread_thread;
      if (pthread_create(&commread_thread, NULL, threadZenity2, &commpipe[0]) !=0)
      {
	  M_PRINTF(MLOG_ERROR, "pthread_create:%s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
	  return;
      }
      int status;
      if (waitpid(pid, &status, 0) == (pid_t)-1)
      {
	  M_PRINTF(MLOG_ERROR, "waitpid:%s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
	  return;
      }
      //check if exited normally
      if (WIFEXITED(status))
        {
          //zenity returns 1 on Cancel pressed
          if (WEXITSTATUS(status) == 1)
            {
              //kill commreadthread, otherwise it's gonna wait for input endlessly
	      if (pthread_cancel(commread_thread) != 0)
	      {
		  M_PRINTF(MLOG_ERROR, "pthread_cancel:%s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
		  return;
	      }
              //any random number clears uw
              process_verdict(234);
              return;
            }
          //OK pressed
          if (WEXITSTATUS(status) == 0)
            {
              if (zenity_answer == 0)
                {
                  M_PRINTF(MLOG_ERROR, "OK pressed without selecting an answer: in %s:%d\n", __FILE__, __LINE__);
                  //kill commreadthread, otherwise it's gonna wait for input endlessly
		  if (pthread_cancel(commread_thread) != 0)
		  {
		      M_PRINTF(MLOG_ERROR, "pthread_cancel:%s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
		      return;
		  }
                  //any random number clears uw
                  process_verdict(234);
                  return;
                }
              process_verdict(zenity_answer);
              return;
            }
        }
      //else WIFEXITED(status) != 0
      M_PRINTF(MLOG_ERROR, "zenity exited abnormally: in %s:%d\n", __FILE__, __LINE__);
      die();
    }
}

void * threadXmessage(void *ptr)
{
  char cmd[PATHSIZE];
  char xmsg1[] = "echo 'An application (with PID) is trying to access the network:\n";
  char xmsg2[] = "\nChoose action:' | xmessage -buttons 'Allow always:101','Allow once:102','Deny always:103','Deny once:104' -file -";
  strcpy(cmd, xmsg1);
  strcat(cmd, global_struct.item.path);
  strcat(cmd, xmsg2);
  int retval;
  retval = system(cmd);
  process_verdict(retval);
}

void add_out(msg_struct add_struct)
{
  if (is_being_run) return;
  is_being_run = 1;
  global_struct = add_struct;

  waddstr(uw, add_struct.item.path);
  wrefresh(uw);
  if (use_zenity)
    {
      pthread_t zenity_thread;
      pthread_create(&zenity_thread, NULL, threadZenity, NULL);
    }
  else if (use_xmessage)
    {
      pthread_t xmessage_thread;
      pthread_create(&xmessage_thread, NULL, threadXmessage, NULL);
    }
}


void add_in(msg_struct add_struct)
{
  if (is_being_run) return;
  is_being_run = 1;
  global_struct = add_struct;

  //the following fields are re-used:
  //perms contain remote's IP addr
  waddstr(uw, add_struct.item.perms);
  waddstr(uw, ":");
  //stime contains remote's port
  char string[16];
  sprintf ( string, "%d", (int)add_struct.item.stime );
  waddstr(uw, string);
  waddstr(uw, " => port ");
  //inode contains local port
  sprintf ( string, "%d", (int)add_struct.item.inode );
  waddstr(uw, string);
  waddstr(uw, " ");
  waddstr(uw, add_struct.item.path);

  wrefresh(uw);
  if (use_zenity)
    {
      pthread_t zenity_thread;
      pthread_create(&zenity_thread, NULL, threadZenity, NULL);
    }
  else if (use_xmessage)
    {
      pthread_t xmessage_thread;
      pthread_create(&xmessage_thread, NULL, threadXmessage, NULL);
    }
}

void farray_clear()
{
  pthread_mutex_lock(&mutex);
  dlist *temp = first->next;
  dlist *temp2;
  while (temp != NULL)
    {
      temp2 = temp->next;
      free(temp);
      temp = temp2;
    }
  first->next = NULL;
  pthread_mutex_unlock(&mutex);
}

void farray_add(dlist rule) //split string to path/pid/permissions/flags and add to dynamic array
{
  char *result;
  dlist *temp = first;
  //find the last element in array i.e. the one that has .next == NULL...
  while (temp->next != NULL)
    {
      temp = temp->next;
    }
  //last element's .next should point now to our newly created one
  if ((temp->next = malloc(sizeof (dlist))) == NULL)
    {
      M_PRINTF(MLOG_ERROR, "malloc: %s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
      die();
    }
  // new element's prev field should point to the former last element...
  temp->next->prev = temp;
  // point temp to the newly added element...
  temp = temp->next;
  //initialize fields
  strcpy(temp->path, rule.path);
  strcpy(temp->pid, rule.pid);
  strcpy(temp->perms, rule.perms);
  temp->is_active =rule.is_active;
  temp->next = NULL;
}

//iterate through array and delete rule with number
//(this is of course a very rigid way, we should be able to implement indeces in rules_array)

void delindex(int index, int ack_flag)
{
  if (index == 0) return;
  dlist *temp = first;
  //upon the beginning of each iteration i == number of calculated elements in array
  int i = 0;
  while ((temp != 0) && (index != i))
    {
      ++i;
      temp = temp->next;
    }
  if (temp == 0)
    {
      M_PRINTF(MLOG_INFO, "no such index in %s:%d\n", __FILE__, __LINE__);
      return;
    }
  //else if index == i
  // call or modular del function
  msgq_f2ddel(*temp, ack_flag);
  //delete the entry in frontend's array
  // ((rule_array*) (temp->prev))->next = temp->next;
  //if (temp->next != 0) ((rule_array*) (temp->next))->prev = temp->prev;
  //free(temp);
}

void list()
{
  dlist *temp = first;
  int i = -1;
  char perms[16];
  wclear(memlw);
  listsize = 0;
  while (temp->next != NULL)
    {
      temp = temp->next;
      ++i;
      if (!strcmp(temp->path, KERNEL_PROCESS))
        {
          mvwprintw(memlw, 0 + i, 0, "KERN");
        }
      else
        {
          //right justify PID's with "%5s"
          mvwprintw(memlw, 0 + i, 0, "%5s", temp->pid);
        }
      if (!strcmp(temp->perms, ALLOW_ONCE)) strcpy(perms, "ALLOW ONCE");
      if (!strcmp(temp->perms, ALLOW_ALWAYS)) strcpy(perms, "ALLOW ALWAYS");
      if (!strcmp(temp->perms, DENY_ONCE)) strcpy(perms, "DENY ONCE");
      if (!strcmp(temp->perms, DENY_ALWAYS)) strcpy(perms, "DENY ALWAYS");

      mvwprintw(memlw, 0 + i, 6, perms);
      if (!strcmp(temp->path, KERNEL_PROCESS))
        {
          mvwprintw(memlw, 0 + i, 20, temp->pid);
        }
      else
        {
          mvwprintw(memlw, 0 + i, 20, temp->path);
        }
      ++listsize;
    }

  init_pair(3, COLOR_BLUE, COLOR_GREEN);

  if (ioctl(0, TIOCGWINSZ, &ws) != 0)
    {
      M_PRINTF(MLOG_ERROR, "ioctl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
  //wprintw(upperwin, "row=%d, col=%d, xpixel=%d, ypixel=%d\n",  ws.ws_row,ws.ws_col,ws.ws_xpixel,ws.ws_ypixel);
  term_width = ws.ws_col;
  term_height = ws.ws_row;

  wclear(lw);
  copywin(memlw, lw, upperline - 1, shiftx, 0, 0, lwheight - 1, term_width - 1, TRUE);
  mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);
  wrefresh(lw);
}

void delstring(char path[PATHSIZE])//daemon asked us to remove a certain rule since app is no longer running
{
  pthread_mutex_lock(&mutex);
  dlist *temp = first->next;
  while (temp != NULL)
    {
      if (!strcmp(temp->path, path))
        {
          //remove the item
          temp->prev->next = temp->next;
          if (temp->next != NULL)
            temp->next->prev = temp->prev;
          free(temp);
          list();
          return;
        }
      temp = temp->next;
    }
  pthread_mutex_unlock(&mutex);
  M_PRINTF(MLOG_INFO, "path not found: %s:%d", __FILE__, __LINE__);
}

// take the array and write everything line by line to lower window

void sigwinch(int signal)
{
  wclear(uw);
  int ret;

  if (ioctl(0, TIOCGWINSZ, &ws) != 0)
    {
      M_PRINTF(MLOG_ERROR, "ioctl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
  term_width = ws.ws_col;

  //mvwprintw(uw, 0, 0, " %d", term_width);
  wrefresh(uw);
  ret = resizeterm(ws.ws_row, ws.ws_col);

  if (ws.ws_row < UWMAX + TWMAX + SWMAX)
    {
      uwheight = ws.ws_row > UWMAX ? UWMAX : ws.ws_row;
      //make sure twheiht > 0 and <= TWMAX
      twheight = ws.ws_row - UWMAX > 0 ? ws.ws_row - UWMAX : 0;
      twheight = twheight > TWMAX ? TWMAX : twheight;

      swheight = ws.ws_row - UWMAX - TWMAX > 0 ? ws.ws_row - UWMAX - TWMAX : 0;
      swheight = swheight > SWMAX ? SWMAX : swheight;

      lwheight = 0;
    }
  else
    {
      uwheight = UWMAX;
      twheight = TWMAX;
      hwheight = HWMAX;
      swheight = SWMAX;
      lwheight = ws.ws_row - UWMAX - TWMAX - SWMAX - HWMAX;
    }

  wresize(uw, uwheight, term_width);
  wresize(tw, twheight, term_width);
  wresize(lw, lwheight, term_width);
  wresize(sw, swheight, term_width);
  wresize(hw, hwheight, term_width);


  mvwin(sw, ws.ws_row - 1, 0);

  wclear(uw);
  wclear(tw);
  wclear(lw);
  wclear(sw);
  wclear(hw);


  copywin(memuw, uw, 0, 0, 0, 0, uwheight - 1, term_width - 1, TRUE);
  copywin(memtw, tw, 0, 0, 0, 0, twheight - 1, term_width - 1, TRUE);
  copywin(memsw, sw, 0, 0, 0, 0, swheight - 1, term_width - 1, TRUE);
  copywin(memhw, hw, 0, 0, 0, 0, hwheight - 1, term_width - 1, TRUE);
  copywin(memlw, lw, upperline - 1, shiftx, 0, 0, lwheight - 1, term_width - 1, TRUE);
  mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);

  wrefresh(uw);
  wrefresh(tw);
  wrefresh(lw);
  wrefresh(sw);
  wrefresh(hw);

}

void refresh_upperwin()
{
  wclear(memuw);
  mvwprintw(memuw, 0, 0, "Awaiting new programs...");
  copywin(memuw, uw, 0, 0, 0, 0, uwheight - 1, term_width - 1, TRUE);
  wrefresh(uw);
}

//these flags are used to signal that an argument has been entered twice

void badArgs()
{
  M_PRINTF(MLOG_ERROR, "Duplicate,unknown or conflicting argument specified. Exitting...\n");
  exit(0);
}

void ncursesInit()
{

  initscr();
  //make chars available to program as soon as they are typed instead of waiting for Enter
  // Ctrl-C is handled by terminal
  cbreak();
  noecho();
  start_color();
  init_pair(1, COLOR_WHITE, COLOR_BLACK);
  init_pair(2, COLOR_BLUE, COLOR_GREEN);

  if (ioctl(0, TIOCGWINSZ, &ws) != 0)
    {
      M_PRINTF(MLOG_INFO, "ioctl: %s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
    }
  else term_width = ws.ws_col;

  //create pads from which info will be copied to viewports
  memuw = newpad(2, MAX_LINE_LENGTH);
  memtw = newpad(1, MAX_LINE_LENGTH);
  memlw = newpad(1000, MAX_LINE_LENGTH);
  memsw = newpad(1, MAX_LINE_LENGTH);
  memhw = newpad(1, MAX_LINE_LENGTH);


  //if we started with a tiny terminal window, make size adjustments
  if (ws.ws_row < UWMAX + TWMAX + SWMAX)
    {
      uwheight = ws.ws_row > UWMAX ? UWMAX : ws.ws_row;
      //make sure twheiht > 0 and <= TWMAX
      twheight = ws.ws_row - UWMAX > 0 ? ws.ws_row - UWMAX : 0;
      twheight = twheight > TWMAX ? TWMAX : twheight;

      swheight = ws.ws_row - UWMAX - TWMAX > 0 ? ws.ws_row - UWMAX - TWMAX : 0;
      swheight = swheight > SWMAX ? SWMAX : swheight;

      lwheight = 0;
    }
  else
    {
      hwheight = HWMAX;
      uwheight = UWMAX;
      twheight = TWMAX;
      swheight = SWMAX;
      lwheight = ws.ws_row - UWMAX - TWMAX - SWMAX - HWMAX;
    }

  //create viewports
  uw = newwin(uwheight, ws.ws_col, 0, 0);
  wattron(uw, COLOR_PAIR(1));

  tw = newwin(twheight, ws.ws_col, uwheight, 0);
  wattron(memtw, COLOR_PAIR(2));
  mvwprintw(memtw, 0, 0, "PID   PERMS          PATH");
  copywin(memtw, tw, 0, 0, 0, 0, 0, ws.ws_col - 1, TRUE);
  mvwchgat(tw, 0, 0, -1, COLOR_PAIR(2), COLOR_PAIR(2), NULL);

  lw = newwin(lwheight, ws.ws_col, uwheight + twheight, 0);

  sw = newwin(swheight, ws.ws_col, ws.ws_row - swheight, 0);

  hw = newwin(hwheight, ws.ws_col, ws.ws_row - swheight - hwheight, 0);
  mvwprintw(memhw, 0, 0, "a-add d-delete s-save rules q-quit");
  copywin(memhw, hw, 0, 0, 0, 0, 0, ws.ws_col - 1, TRUE);
  mvwchgat(tw, 0, 0, -1, COLOR_PAIR(2), COLOR_PAIR(2), NULL);
  /*
  if (use_zenity) {
      wclear(sw);
      wprintw(sw, "using zenity");
      wrefresh(sw);
  }*/

  active = view_active = upperline = 1;

  refresh_upperwin();
  wrefresh(lw);
  wrefresh(tw);
  wrefresh(hw);

  //ncurses should process arrow keys
  keypad(tw, TRUE);
}

void * zenityCheck2(void *commpipe)
{
  char buf[PATHSIZE];
  int *a;
  a = (int*) commpipe;
  read(*a, buf, sizeof (buf));
  //zenity_path = buf;

}

//bash script does this check on startup  now, so this func can be deleted

int zenityCheck()
{
  int commpipe[2];
  pipe(commpipe);
  pid_t pid;
  pid = fork();
  if (pid == 0)   //child
    {
      //suppress errors which litter the screen
      freopen("/dev/null", "w", stderr);
      //redirect STDOUT to our own file descriptor
      dup2(commpipe[1], 1);
      execl("/usr/bin/which", "zenity", (char *) 0);
    }
  if (pid > 1)
    {
      pthread_t zenityCheck2_thread;
      pthread_create(&zenityCheck2_thread, NULL, zenityCheck2, &commpipe[0]);
      int status;
      waitpid(pid, &status, 0);
      //check if exited normally
      if (WIFEXITED(status))
        {
          //zenity returns 1 on Cancel pressed
          if (WEXITSTATUS(status) != 0)
            {
              //kill thread, otherwise it's gonna wait for input endlessly
              pthread_cancel(zenityCheck2_thread);
              //any random number clears uw
              return 0;
            }
          //OK pressed
          if (WEXITSTATUS(status) == 0)
            {
              return 1;
            }

        }
    }

}

void  fe_cleanup_and_quit()
{
  endwin();
  frontend_unregister();
  die();
}

void check_own_gid()
{
    gid_t lpfwuser_gid, own_gid;
    struct group *m_group;

    errno = 0;
    m_group = getgrnam("lpfwuser");
    if(!m_group)
      {
	if (errno == 0)
	  {
	    printf ("lpfwuser group still doesn't exist even though we've just created it \n");
	  }
	else
	  {
	    perror ("getgrnam");
	  }
      }
    lpfwuser_gid = m_group->gr_gid;
    own_gid = getegid();
    if (own_gid != lpfwuser_gid)
    {
	printf("Please launch lpfw first \n", (int)own_gid, (int)lpfwuser_gid);
	exit(0);
    }
}

void parse_command_line(int argc, char* argv[])
{
    // if the parsing of the arguments was unsuccessful
    int nerrors;

    // Define argument table structs
    log_file = arg_file0 ( NULL, "log-file", "<path to file>", "Log output file" );
    zenity_path = arg_file0 ( NULL, "zenity-path", "<path to file>", "Path to zenity executable (if not in the $PATH)" );
    log_debug = arg_int0 ( NULL, "log-debug", "<1/0 for yes/no>", "Debug messages logging" );
    nozenity = arg_int0 ( NULL, "nozenity", "<1/0 for yes/no>", "Don't use zenity notifications" );

    struct arg_lit *help = arg_lit0 ( NULL, "help", "Display this help screen" );
    struct arg_lit *version = arg_lit0 ( NULL, "version", "Display the current version" );
    struct arg_end *end = arg_end ( 10 );
    void *argtable[] = {log_file, log_debug, nozenity, zenity_path, help, version, end};

    // Set default values
    char *log_file_pointer = malloc(strlen(LPFWCLI_LOG)+1);
    strcpy (log_file_pointer, LPFWCLI_LOG);
    log_file->filename[0] = log_file_pointer;

    char *zenity_path_pointer = malloc(strlen("/usr/bin/zenity")+1);
    strcpy (zenity_path_pointer, "/usr/bin/zenity");
    zenity_path->filename[0] = zenity_path_pointer;

    * ( log_debug->ival ) = 0;
    * ( nozenity->ival ) = 0;

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
	    printf ( "Leopard Flower frontend :\n Syntax and help:\n" );
	    arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
	    exit (0);
	  }
	else if ( version->count == 1 )
	  {
	    printf ( "%s\n", VERSION );
	    exit (0);
	  }
    }
    else if ( nerrors > 0 )
      {
	arg_print_errors ( stdout, end, "Leopard Flower frontend" );
	printf ( "Leopard Flower frontend:\n Syntax and help:\n" );
	arg_print_glossary ( stdout, argtable, "%-43s %s\n" );
	exit (1);
      }

	if (* ( nozenity->ival ) == 1){
	    use_zenity = 0;
	}


    // Free memory - don't do this cause args needed later on
    //  arg_freetable(argtable, sizeof (argtable) / sizeof (argtable[0]));
}

int main(int argc, char *argv[])
{
    if (argc == 2 && ( !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version")))
      {
	parse_command_line(argc, argv);
	return 0;
      }
    check_own_gid();
    parse_command_line(argc, argv);

    if ((logfilefd = fopen(log_file->filename[0], "w+")) == 0)
    {
	printf("Can't open file %s for logging\n %s\n", log_file->filename[0], strerror(errno));
	exit(0);
    }
  else m_printf = &m_printf_file;

  //check if zenity is in the PATH
  if (use_zenity) zenityCheck();

  //install signal handler on window resize
  signal(SIGWINCH, sigwinch);

  first = malloc(sizeof (dlist));
  first->next = first->prev = 0;

  ncursesInit();

  if (use_msgq)
    msgq_initialize();
  else
    {
      printf("No IPC mechanism specified..Exiting");
      exit(0);
    }


  int ch;
  int delnum;
  char askch;

  while (1)
    {
      ch = wgetch(tw);
      switch (ch)
        {
        case 'q':
        case 'Q':
          fe_cleanup_and_quit();
        case 'a':
        case 'A':
          //ignore if there is nothing pending
          if (!is_being_run) continue;
          //ignore if zenity's in charge
          if (use_zenity) continue;
          wattron(sw, COLOR_PAIR(1));
          wprintw(sw, " 1 ");
          wattron(sw, COLOR_PAIR(2));
          wprintw(sw, "Allow always");
          wattron(sw, COLOR_PAIR(1));
          wprintw(sw, " 2 ");
          wattron(sw, COLOR_PAIR(2));
          wprintw(sw, "Allow once");
          wattron(sw, COLOR_PAIR(1));
          wprintw(sw, " 3 ");
          wattron(sw, COLOR_PAIR(2));
          wprintw(sw, "Deny always");
          wattron(sw, COLOR_PAIR(1));
          wprintw(sw, " 4 ");
          wattron(sw, COLOR_PAIR(2));
          wprintw(sw, "Deny once");
          mvwin(sw, term_height - 1, term_width - 1);
          wrefresh(sw);

          askch = wgetch(sw);
          delnum = atoi(&askch);

          process_verdict(delnum);

          wclear(sw);
          wrefresh(sw);
          continue;

        case 'd':
        case 'D':
          if (view_active > 1) --view_active;
          delindex(active, 1);
          //delete the entry from the screen by refreshing the screnn
          //wclear(lw);
          //list();
          if (active > 1) --active;
          //mvwchgat(lw,view_active-1,0,-1,0,0,NULL);
          //wrefresh(lw);
          continue;
        case 's':
        case 'S':
          msgq_write();
          wclear(sw);
          wprintw(sw, "rules saved to file");
          wrefresh(sw);
          continue;
//            case 'x':
//                wclear(sw);
//                wprintw(sw, "%d", getmaxx(lw));
//                wrefresh(sw);
//                copywin(memlw, sw, 2, 16, 0, 24, 0, 100, TRUE);
//                wrefresh(sw);
//                wclear(lw);
//                copywin(memlw, lw, 0, 0, 0, 0, 9, term_width - 1, TRUE);
//                wrefresh(lw);
//                wrefresh(memlw);
//                continue;
        case KEY_LEFT:
          if (shiftx == 0) continue;
          wclear(lw);
          copywin(memlw, lw, upperline - 1, shiftx = --shiftx, 0, 0, lwheight - 1, term_width - 1, TRUE);
          mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);
          wrefresh(lw);
          wclear(tw);
          copywin(memtw, tw, 0, shiftx, 0, 0, 0, term_width - 1, TRUE);
          wrefresh(tw);
          //wclear(sw);
          //wprintw(sw, "left pressed, x=%d", shiftx);
          //wrefresh(sw);
          continue;
        case KEY_RIGHT:
          wclear(lw);
          copywin(memlw, lw, upperline - 1, shiftx = ++shiftx, 0, 0, lwheight - 1, term_width - 1, TRUE);
          mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);
          wrefresh(lw);
          wclear(tw);
          copywin(memtw, tw, 0, shiftx, 0, 0, 0, term_width - 1, TRUE);
          wrefresh(tw);
          //wclear(sw);
          //wprintw(sw, "right pressed, x=%d", shiftx);
          //wrefresh(sw);
          continue;
        case KEY_DOWN: //move down
          if (active >= listsize) continue;
          if (lwheight == view_active)
            {
              ++active;
              ++upperline;
              wclear(lw);
              copywin(memlw, lw, active - lwheight, 0, 0, 0, lwheight - 1, term_width - 1, TRUE);
              mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);
              wrefresh(lw);
              continue;
            }
          //else
          mvwchgat(lw, view_active - 1, 0, -1, 0, 0, NULL);
          ++view_active;
          mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);
          wrefresh(lw);
          ++active;
          continue;
        case KEY_UP: //move up
          if (active == 1) continue;

          if (view_active == 1)
            {
              --active;
              --upperline;
              wclear(lw);
              int a = active - lwheight;
              copywin(memlw, lw, a < 0 ? 0 : a, 0, 0, 0, lwheight - 1, term_width - 1, TRUE);
              mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);
              wrefresh(lw);
              continue;
            }
          //else

          mvwchgat(lw, view_active - 1, 0, -1, 0, 0, NULL);
          --view_active;
          --active;
          mvwchgat(lw, view_active - 1, 0, -1, COLOR_PAIR(3), COLOR_PAIR(3), NULL);
          wrefresh(lw);
          continue;
        default:
          //see if there was a pending request
          if (!is_being_run) continue;
          //tell backend that request was ignored
          process_verdict(0);


        }
    }
  return 0;
}
