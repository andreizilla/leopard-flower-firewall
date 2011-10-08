#include "defines.h"
#include <unistd.h>
#include <sys/types.h> //for ino_t

#ifndef INCLUDES_H_
#define INCLUDES_H_

typedef struct
{
    char * name;
    char * value;
} para;

typedef struct m_dlist
{
    int command;
    char path[PATHSIZE]; //path to executable
    char pid[PIDLENGTH]; //its pid
    char perms[PERMSLENGTH]; // permission in the form "ALLOW ALWAYS"
    char current_pid; //TRUE if app has already been seen sending packets
    unsigned char first_instance; //TRUE for a first instance of an app or a parent process
    //sha must be a uchar, otherwise if it's just char, printf "%x" will promote it to int and cause a lot of pain, SIGV
    unsigned char sha[65]; //sha512sum digest
    unsigned long long stime; //obsolete: start time of the process
    ino_t inode; // /proc/PID entry's inode number. Can change only if another process with the same PID is running
    off_t exesize; //executable's size
    u_int32_t nfmark; //netfilter's packet mark. Is assigned to each packet and used when a user deletes a rule to tell conntrack to immediately drop any existing connections associated with the mark
    struct m_dlist *prev; //previous element in dlist
    struct m_dlist *next; // next element in dlist
} dlist;

//structures used in msgq for communication daemon<>frontend

typedef struct
{
    long type;
    dlist item;
} msg_struct;

//this structure is populated when invoking lpfw --cli

typedef struct
{
    uid_t uid;
    char tty [TTYNAME];
    char display[DISPLAYNAME];
    char params[6][16]; //extra params for lpfwcli 16 chars each 0th param holds the total amount of params

} credentials;

typedef struct
{
    long type;
    credentials creds;
} msg_struct_creds;



//constants for ftok() function

enum
{
    FTOKID_D2F,
    FTOKID_F2D,
    FTOKID_D2FLIST,
    FTOKID_F2DLIST,
    FTOKID_D2FDEL,
    FTOKID_F2DDEL,
    FTOKID_CREDS
};

enum
{
    GOTO_NEXT_STEP,
    ACCEPT,
    DROP,
    PORT_NOT_FOUND,
    INODE_NOT_FOUND_IN_PROC,
    INODE_FOUND_IN_DLIST_ALLOW,
    INODE_FOUND_IN_DLIST_DENY,
    PATH_FOUND_IN_DLIST_ALLOW,
    PATH_FOUND_IN_DLIST_DENY,
    NEW_INSTANCE_ALLOW,
    NEW_INSTANCE_DENY,
    SENT_TO_FRONTEND,
    FRONTEND_NOT_ACTIVE,
    FRONTEND_BUSY,
    ICMP_MORE_THAN_ONE_ENTRY,
    ICMP_NO_ENTRY,
    UNSUPPORTED_PROTOCOL,
    SHA_DONT_MATCH,
    EXESIZE_DONT_MATCH,
    STIME_DONT_MATCH,
    INODE_HAS_CHANGED,
    EXE_HAS_BEEN_CHANGED,
    FORKED_CHILD_ALLOW,
    FORKED_CHILD_DENY,
    PROCFS_ERROR
};

//commands passed through msgq
enum
{
    D2FCOMM_ASK,
    D2FCOMM_LIST,
    F2DCOMM_LIST,
    F2DCOMM_ADD,
    F2DCOMM_DEL,
    F2DCOMM_DELANDACK,
    F2DCOMM_WRT,
    F2DCOMM_REG,
    F2DCOMM_UNREG
};


#endif /* INCLUDES_H_ */
// kate: indent-mode cstyle; space-indent on; indent-width 4; 
