#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <string.h>
#include <termios.h>
#include <stdio.h>
#include "errno.h"
#include <pthread.h>
#include <ncurses.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdarg.h>
#include "defines.h"
#include "includes.h"

int (*m_printf)(int loglevel, char *format, ...);
void list();

char TAB[2] = {9, 0};
//string holds daemon request
msg_struct global_struct;
char zenity_path[MAX_LINE_LENGTH] = "/usr/bin/zenity";

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

FILE *logfilefd;

int retval;
int zenity_answer;

extern  void frontend_unregister();
extern  void msgq_initialize();

int m_printf_file(int loglevel, char *format, ...) {

}

void die() {
    exit(0);
}

void process_verdict(int delnum) {
    switch (delnum) {
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

void* threadZenity2(void *commpipe) {
    char buf[PATHSIZE];
    int *a;
    a = (int*) commpipe;

    read(*a, buf, sizeof (buf));
    zenity_answer = atoi(&buf[0]);
}

void * threadZenity(void *ptr) {
    char cmd[PATHSIZE];
    char zenity1[] = " --list --title 'Leopard Flower- Permission request' --text 'The following program (with PID) is trying to access the network: \n";
    char zenity2[] = " Please choose action:' --hide-header --column= 1 'ALLOW ALWAYS' 2 'ALLOW ONCE' 3 'DENY ALWAYS' 4 'DENY ONCE' --column= --hide-column=1 ";
    strcpy(cmd, zenity1);
    strcat(cmd, global_struct.item.path);
    strcat(cmd, "\n");
    strcat(cmd, zenity2);

    zenity_answer = 0;

    int commpipe[2];
    pipe(commpipe);
    pid_t pid;

    pid = fork();
    if (pid == 0) { //child
        //suppress Gdk errors which litter the screen
        freopen("/dev/null", "w", stderr);

        //redirect STDOUT to our own file descriptor
        dup2(commpipe[1], 1);
        char zenity1[] = "--text=The following program (with PID) is trying to access the network: \n";
        strcat(zenity1, global_struct.item.path);
        strcat(zenity1, "\n Please choose action:");

        execl(zenity_path, zenity_path, "--list", "--title=Leopard Flower- Permission request", zenity1,
                "--column=", "1", "ALLOW ALWAYS", "2", "ALLOW ONCE", "3", "DENY ALWAYS", "4", "DENY ONCE",
                "--column=", "--hide-column=1", "--height=240", (char *) 0);
    }
    if (pid > 1) {
        pthread_t commread_thread;
        pthread_create(&commread_thread, NULL, threadZenity2, &commpipe[0]);
        int status;
        waitpid(pid, &status, 0);
        //check if exited normally
        if (WIFEXITED(status)) {
            //zenity returns 1 on Cancel pressed
            if (WEXITSTATUS(status) == 1) {
                //kill commreadthread, otherwise it's gonna wait for input endlessly
                pthread_cancel(commread_thread);
                //any random number clears uw
                process_verdict(234);
                return;
            }
            //OK pressed
            if (WEXITSTATUS(status) == 0) {
                if (zenity_answer == 0) {
                    m_printf(MLOG_ERROR, "OK pressed without selecting an answer: in %s:%d\n", __FILE__, __LINE__);
		     //kill commreadthread, otherwise it's gonna wait for input endlessly
                pthread_cancel(commread_thread);
                //any random number clears uw
                process_verdict(234);
                    return;
                }
                process_verdict(zenity_answer);
                return;
            }
        }
        //else WIFEXITED(status) != 0
        m_printf(MLOG_ERROR, "zenity exited abnormally: in %s:%d\n", __FILE__, __LINE__);
        die();
    }
}

void * threadXmessage(void *ptr) {
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

void add_out(msg_struct add_struct) {
    if (is_being_run) return;
    is_being_run = 1;
    global_struct = add_struct;

    waddstr(uw, add_struct.item.path);
    wrefresh(uw);
    if (use_zenity) {
        pthread_t zenity_thread;
        pthread_create(&zenity_thread, NULL, threadZenity, NULL);
    }
    if (use_xmessage) {
        pthread_t xmessage_thread;
        pthread_create(&xmessage_thread, NULL, threadXmessage, NULL);
    }
}


void add_in(msg_struct add_struct) {
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
    if (use_zenity) {
        pthread_t zenity_thread;
        pthread_create(&zenity_thread, NULL, threadZenity, NULL);
    }
    if (use_xmessage) {
        pthread_t xmessage_thread;
        pthread_create(&xmessage_thread, NULL, threadXmessage, NULL);
    }
}

void farray_clear() {
    pthread_mutex_lock(&mutex);
    dlist *temp = first->next;
    dlist *temp2;
    while (temp != NULL) {
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
    while (temp->next != NULL) {
        temp = temp->next;
    }
    //last element's .next should point now to our newly created one
    if ((temp->next = malloc(sizeof (dlist))) == NULL) {
        m_printf(MLOG_ERROR, "malloc: %s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
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
    temp->current_pid =rule.current_pid;
    temp->next = NULL;
}

//iterate through array and delete rule with number
//(this is of course a very rigid way, we should be able to implement indeces in rules_array)

void delindex(int index, int ack_flag) {
    if (index == 0) return;
    dlist *temp = first;
    //upon the beginning of each iteration i == number of calculated elements in array
    int i = 0;
    while ((temp != 0) && (index != i)) {
        ++i;
        temp = temp->next;
    }
    if (temp == 0) {
        m_printf(MLOG_INFO, "no such index in %s:%d\n", __FILE__, __LINE__);
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

void list() {
    dlist *temp = first;
    int i = -1;
    char perms[16];
    wclear(memlw);
    listsize = 0;
    while (temp->next != NULL) {
        temp = temp->next;
        ++i;
        //right justify PID's with "%5s"
        mvwprintw(memlw, 0 + i, 0, "%5s", temp->pid);
        if (!strcmp(temp->perms, ALLOW_ONCE)) strcpy(perms, "ALLOW ONCE");
        if (!strcmp(temp->perms, ALLOW_ALWAYS)) strcpy(perms, "ALLOW ALWAYS");
        if (!strcmp(temp->perms, DENY_ONCE)) strcpy(perms, "DENY ONCE");
        if (!strcmp(temp->perms, DENY_ALWAYS)) strcpy(perms, "DENY ALWAYS");

        mvwprintw(memlw, 0 + i, 6, perms);
        mvwprintw(memlw, 0 + i, 20, temp->path);
        ++listsize;
    }

    init_pair(3, COLOR_BLUE, COLOR_GREEN);

    if (ioctl(0, TIOCGWINSZ, &ws) != 0) {
        m_printf(MLOG_ERROR, "ioctl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
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
    while (temp != NULL) {
        if (!strcmp(temp->path, path)) {
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
    m_printf(MLOG_INFO, "path not found: %s:%d", __FILE__, __LINE__);
}

// take the array and write everything line by line to lower window

void sigwinch(int signal) {
    wclear(uw);
    int ret;

    if (ioctl(0, TIOCGWINSZ, &ws) != 0) {
        m_printf(MLOG_ERROR, "ioctl: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    }
    term_width = ws.ws_col;

    //mvwprintw(uw, 0, 0, " %d", term_width);
    wrefresh(uw);
    ret = resizeterm(ws.ws_row, ws.ws_col);

    if (ws.ws_row < UWMAX + TWMAX + SWMAX) {
        uwheight = ws.ws_row > UWMAX ? UWMAX : ws.ws_row;
        //make sure twheiht > 0 and <= TWMAX
        twheight = ws.ws_row - UWMAX > 0 ? ws.ws_row - UWMAX : 0;
        twheight = twheight > TWMAX ? TWMAX : twheight;

        swheight = ws.ws_row - UWMAX - TWMAX > 0 ? ws.ws_row - UWMAX - TWMAX : 0;
        swheight = swheight > SWMAX ? SWMAX : swheight;

        lwheight = 0;
    } else {
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

void refresh_upperwin() {
    wclear(memuw);
    mvwprintw(memuw, 0, 0, "Awaiting new programs...");
    copywin(memuw, uw, 0, 0, 0, 0, uwheight - 1, term_width - 1, TRUE);
    wrefresh(uw);
}

//these flags are used to signal that an argument has been entered twice

void badArgs() {
    printf("Duplicate,unknown or conflicting argument specified. Exitting...\n");
    exit(0);
}

void ncursesInit() {

    initscr();
    //make chars available to program as soon as they are typed instead of waiting for Enter
    // Ctrl-C is handled by terminal
    cbreak();
    noecho();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLACK);
    init_pair(2, COLOR_BLUE, COLOR_GREEN);

    if (ioctl(0, TIOCGWINSZ, &ws) != 0) {
        m_printf(MLOG_INFO, "ioctl: %s in %s:%d\n", strerror(errno), __FILE__, __LINE__);
    } else term_width = ws.ws_col;

    //create pads from which info will be copied to viewports
    memuw = newpad(2, MAX_LINE_LENGTH);
    memtw = newpad(1, MAX_LINE_LENGTH);
    memlw = newpad(1000, MAX_LINE_LENGTH);
    memsw = newpad(1, MAX_LINE_LENGTH);
    memhw = newpad(1, MAX_LINE_LENGTH);


    //if we started with a tiny terminal window, make size adjustments
    if (ws.ws_row < UWMAX + TWMAX + SWMAX) {
        uwheight = ws.ws_row > UWMAX ? UWMAX : ws.ws_row;
        //make sure twheiht > 0 and <= TWMAX
        twheight = ws.ws_row - UWMAX > 0 ? ws.ws_row - UWMAX : 0;
        twheight = twheight > TWMAX ? TWMAX : twheight;

        swheight = ws.ws_row - UWMAX - TWMAX > 0 ? ws.ws_row - UWMAX - TWMAX : 0;
        swheight = swheight > SWMAX ? SWMAX : swheight;

        lwheight = 0;
    } else {
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

void * zenityCheck2(void *commpipe) {
    char buf[PATHSIZE];
    int *a;
    a = (int*) commpipe;
    read(*a, buf, sizeof (buf));
    //zenity_path = buf;

}

//bash script does this check on startup  now, so this func can be deleted

int zenityCheck() {
    int commpipe[2];
    pipe(commpipe);
    pid_t pid;
    pid = fork();
    if (pid == 0) { //child
        //suppress errors which litter the screen
        freopen("/dev/null", "w", stderr);
        //redirect STDOUT to our own file descriptor
        dup2(commpipe[1], 1);
        execl("/usr/bin/which", "zenity", (char *) 0);
    }
    if (pid > 1) {
        pthread_t zenityCheck2_thread;
        pthread_create(&zenityCheck2_thread, NULL, zenityCheck2, &commpipe[0]);
        int status;
        waitpid(pid, &status, 0);
        //check if exited normally
        if (WIFEXITED(status)) {
            //zenity returns 1 on Cancel pressed
            if (WEXITSTATUS(status) != 0) {
                //kill thread, otherwise it's gonna wait for input endlessly
                pthread_cancel(zenityCheck2_thread);
                //any random number clears uw
                return 0;
            }
            //OK pressed
            if (WEXITSTATUS(status) == 0) {
                return 1;
            }

        }
    }

}

void  fe_cleanup_and_quit(){
    endwin();
    frontend_unregister();
    die();
}

int main(int argc, char *argv[]) {
 
  
  
#ifndef DEBUG 
if (argc == 1 || strcmp(argv[1],"magic_number")){
  printf("This program is part of LeopardFlower suite and should not be executed directly by user. \n");
  return 2;
}
#endif
  
    if ((logfilefd = fopen(LPFWCLI_LOG, "w+")) == 0)
        printf("Can't open file for logging\n %s\n", strerror(errno));
    else m_printf = &m_printf_file;

    //reiterate through arg list, setting flags to prevent arg being given more than once
    if (argc > 2) {
        int no_zenity_flag = 0;
        int ipc_flag = 0;
        int zenity_path_flag = 0;

        int i = 3;
        for (i; i <= argc; ++i) {
            // printf ("ARGC= %d arg %d %s\n",argc, i, argv[i-1]);
            if (!strcmp(argv[i - 1], "--no-zenity")) {
                if (no_zenity_flag || zenity_path_flag) badArgs();
                use_zenity = 0;
                no_zenity_flag = 1;
            } else if (!strcmp(argv[i - 1], "--msgq")) {
                if (ipc_flag) badArgs();
                use_msgq = 1;
                ipc_flag = 1;
            } else if (!strcmp(argv[i - 1], "--zenity-path")) {
                if (zenity_path_flag || no_zenity_flag) badArgs();
                //there should be another arg
                if (!(argc > i)) badArgs();
                ++i;
                strcpy(zenity_path, argv[i - 1]);
                zenity_path_flag = 1;
            } else badArgs();
        }
    }

    //check if zenity is in the PATH
    //if (use_zenity) zenityCheck();

    //install signal handler on window resize
    signal(SIGWINCH, sigwinch);

    first = malloc(sizeof (dlist));
    first->next = first->prev = 0;

    ncursesInit();

    if (use_msgq)
        msgq_initialize();
    else {
        printf("No IPC mechanism specified..Exiting");
        exit(0);
    }


    int ch;
    int delnum;
    char askch;

    while (1) {
        ch = wgetch(tw);
        switch (ch) {
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
                msgq_list();
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
            case 'x':
                wclear(sw);
                wprintw(sw, "%d", getmaxx(lw));
                wrefresh(sw);
                copywin(memlw, sw, 2, 16, 0, 24, 0, 100, TRUE);
                wrefresh(sw);
                wclear(lw);
                copywin(memlw, lw, 0, 0, 0, 0, 9, term_width - 1, TRUE);
                wrefresh(lw);
                wrefresh(memlw);
                continue;
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
                if (lwheight == view_active) {
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

                if (view_active == 1) {
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
