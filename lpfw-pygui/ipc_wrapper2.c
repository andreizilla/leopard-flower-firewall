#include <unistd.h>
#include <stdio.h>
#include "common/includes.h"
#include <sys/ipc.h>
#include <pthread.h>
#include "stdio.h"
#include "errno.h"
#include <string.h>
#include <stdlib.h>

void send_message (char *message)
{
    int size;
    size = strlen(message);
    message[size] = '\n'; //python's readline needs newline to unblock
    write (2, message, size+1);
}


void* f2dthread(void * ptr) {
    key_t ipckey_f2d;
    int mqd_f2d;

    if ((ipckey_f2d = ftok(TMPFILE, FTOKID_F2D)) == -1) {
	printf("ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    };
    if ((mqd_f2d = msgget(ipckey_f2d, 0)) == -1) {
	printf("msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	exit(0);
    };

    char line[MAX_LINE_LENGTH];

    while (1)
    {
#ifdef DEBUG
	printf ("Listening for commands from f/e \n");
#endif
	int size;
	char sizestring[8];
	char *token;
	char *search = " ";

	msg_struct msg;
	msg.type = 1;

	memset(line, 0, sizeof(line));
	read (0, line, sizeof(line)); //unblocks when zero byte is encounter
	//dissect the line and forward it on
#ifdef DEBUG
	printf ("f/e asked %s\n", line);
#endif
	token = strtok(line, search);
	if (!strcmp(token, "F2DCOMM_LIST"))
	{
	    msg.item.command = F2DCOMM_LIST;
	}
	else if (!strcmp(token, "F2DCOMM_ADD"))
	{
	    msg.item.command = F2DCOMM_ADD;
	    token = strtok(NULL, search); //take next element in line[]
	    if (!strcmp(token, KERNEL_PROCESS))
	    {
		strcpy (msg.item.path, KERNEL_PROCESS);
		token = strtok(NULL, search);
		strcpy (msg.item.pid, token);
		token = strtok(NULL, search);
		strcpy (msg.item.perms, token);
	    }
	    else strcpy (msg.item.perms, token);
	}
	else if (!strcmp(token, "F2DCOMM_DELANDACK"))
	{
	    msg.item.command = F2DCOMM_DELANDACK;
	    token = strtok(NULL, search);
	    strcpy (msg.item.path, token);
	    token = strtok(NULL, search);
	    strcpy (msg.item.pid, token);
	}
	else if (!strcmp(token, "F2DCOMM_WRT"))
	{
	    msg.item.command = F2DCOMM_WRT;
	}
	else if (!strcmp(token, "F2DCOMM_REG"))
	{
	    msg.item.command = F2DCOMM_REG;
	}
	else if (!strcmp(token, "F2DCOMM_UNREG"))
	{
	    msg.item.command = F2DCOMM_UNREG;
	}
	else if (!strcmp(token, "QUIT"))
	{
	    exit(0);
	}
	if ( msgsnd ( mqd_f2d, &msg, sizeof ( msg_struct ), 0 ) == -1 )
	{
	    printf ( "msgsnd: %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	};
    }

}

void* d2fthread(void * ptr) {
    key_t ipckey_d2f;
    int mqd_d2f;

    if ((ipckey_d2f = ftok(TMPFILE, FTOKID_D2F)) == -1) {
	printf("ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    };
    if ((mqd_d2f = msgget(ipckey_d2f, 0)) == -1) {
	printf("msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	exit(0);
    };

    msg_struct msg_d2f;
    char message[MAX_LINE_LENGTH];
    while (1)
    {
	memset(message, 0, sizeof(message));
	if (msgrcv(mqd_d2f, &msg_d2f, sizeof (msg_struct), 0, 0) == -1) {
	    printf("msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	};
	switch (msg_d2f.item.command) {
	    case D2FCOMM_ASK_OUT:
		strcpy(message, "D2FCOMM_ASK_OUT ");
		break;
	    case D2FCOMM_ASK_IN:
		strcpy(message, "D2FCOMM_ASK_IN ");
		break;
	    case D2FCOMM_LIST:
		strcpy(message, "D2FCOMM_LIST ");
		break;
	    default:
		printf("Received an invalid command. Please report %s,%d\n",__FILE__, __LINE__);
		break;
	}
	strcat (message, msg_d2f.item.path);
	strcat (message, " ");
	strcat (message, msg_d2f.item.pid);
	strcat (message, " ");
	strcat (message, msg_d2f.item.perms);
	send_message(message);
    }
}

void* d2flistthread(void * ptr) {

    key_t ipckey_d2flist;
    int mqd_d2flist;

    if ((ipckey_d2flist = ftok(TMPFILE, FTOKID_D2FLIST)) == -1) {
	printf("ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    };
    if ((mqd_d2flist = msgget(ipckey_d2flist, 0)) == -1) {
	printf("msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	exit(0);
    };

    msg_struct msg_d2flist;
    char message[65536];
    while (1)
    {
	memset(message, 0, sizeof(message));
	strcat (message, "RULESLIST ");
	while (1)
	{
	    if (msgrcv(mqd_d2flist, &msg_d2flist, sizeof (msg_struct), 0, 0) == -1) {
	    printf("msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	    };
	    if (!strcmp(msg_d2flist.item.path, "EOF"))
	    {
		strcat (message, "EOF");
#ifdef DEBUG
		printf ("sending message %s\n", message);
#endif
		send_message(message);
		break;
	    }
	    else
	    {
		strcat (message, msg_d2flist.item.path);
		strcat (message, " ");
		strcat (message, msg_d2flist.item.pid);
		strcat (message, " ");
		if (!strcmp (msg_d2flist.item.perms, ALLOW_ONCE)) strcat(message, "ALLOW_ONCE ");
		else if (!strcmp (msg_d2flist.item.perms, ALLOW_ALWAYS)) strcat(message, "ALLOW_ALWAYS ");
		else if (!strcmp (msg_d2flist.item.perms, DENY_ONCE)) strcat(message, "DENY_ONCE ");
		else if (!strcmp (msg_d2flist.item.perms, DENY_ALWAYS)) strcat(message, "DENY_ALWAYS ");
		else
		{
		    printf("A rule without permission set detected %s,%d\n",__FILE__, __LINE__);
		}
		if (msg_d2flist.item.is_active) strcat (message, "ACTIVE ");
		else strcat (message, "NOTACTIVE ");
		char nfmark_str[16];
		sprintf(nfmark_str, "%d", msg_d2flist.item.nfmark_out);
#ifdef DEBUG
		printf ("%s nfmark %d\n", msg_d2flist.item.path, msg_d2flist.item.nfmark_out);
#endif
		strcat (message, nfmark_str);
		strcat(message, " ");
	    }
	}
    }
}



typedef struct
{
    long type;
    int ct_entries_export[CT_ENTRIES_EXPORT_MAX][3];
} mymsg;

void* d2ftrafficthread(void * ptr) {

    key_t ipckey_d2ftraffic;
    int mqd_d2ftraffic;

    if ((ipckey_d2ftraffic = ftok(TMPFILE, FTOKID_D2FTRAFFIC)) == -1) {
	printf("ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    };
    if ((mqd_d2ftraffic = msgget(ipckey_d2ftraffic, 0)) == -1) {
	printf("msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	exit(0);
    };
#ifdef DEBUG
    printf ("traffic mqid: %d\n", mqd_d2ftraffic);
#endif

    mymsg msg_d2ftraffic;
    char message[MAX_LINE_LENGTH];
    while (1)
    {
	if (msgrcv(mqd_d2ftraffic, &msg_d2ftraffic, sizeof (mymsg), 0, 0) == -1) {
	    printf("msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
	    exit(0);
	};

	strcpy(message, "TRAFFIC ");

	int i;
	char int2str[16];
	for (i=0; msg_d2ftraffic.ct_entries_export[i][0] != 0; ++i)
	{
	    sprintf(int2str, "%d", msg_d2ftraffic.ct_entries_export[i][0]);
	    strcat(message, int2str);
	    strcat(message, " ");
	    sprintf(int2str, "%d", msg_d2ftraffic.ct_entries_export[i][1]);
	    strcat(message, int2str);
	    strcat(message, " ");
	    sprintf(int2str, "%d", msg_d2ftraffic.ct_entries_export[i][2]);
	    strcat(message, int2str);
	    strcat(message, " ");
	}
	strcat (message, "EOF");
	send_message(message);
    }
}


int main ( int argc, char *argv[] )
{    
    pthread_t f2d_thread, d2f_thread, d2flist_thread, d2fdel_thread, d2ftraffic_thread;
    pthread_create(&f2d_thread, NULL, f2dthread, NULL);
    pthread_create(&d2f_thread, NULL, d2fthread, NULL);
    pthread_create(&d2flist_thread, NULL, d2flistthread, NULL);
    //pthread_create(&d2fdel_thread, NULL, d2fdelthread, NULL);
    pthread_create(&d2ftraffic_thread, NULL, d2ftrafficthread, NULL);
#ifdef DEBUG
    printf ("Beginning the main loop \n");
#endif
    while(1)
    {
	sleep(100);
    }
}
