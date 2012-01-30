#include "defines.h"
#include <unistd.h>
#include <sys/types.h> //for ino_t
#include <dirent.h> //for DIR*

#ifndef INCLUDES_H_
#define INCLUDES_H_

typedef char mbool;

typedef struct m_ports_list
{
    mbool is_range;
    int min_port; //when !is_range, contains port number
    int max_port;
    struct m_ports_list *next;
    struct m_ports_list *prev;
} ports_list_t;

typedef struct m_global_rule
{
    struct m_global_rule *next;
    struct m_global_rule *prev;
    int protocol;
    int direction;
    int permission;
    ports_list_t *ports_list;
} global_rule_t;

typedef struct m_dlist
{
  int command;
  char path[PATHSIZE]; //path to executable
  char pid[PIDLENGTH]; //its pid (or IP address for kernel processes)
  char perms[PERMSLENGTH]; // permission in the form "ALLOW ALWAYS"
  mbool is_active; //Has process already been seen sending/receiving packets?
  u_int32_t nfmark_out;
  u_int32_t nfmark_in; //netfilter's packet mark. Is assigned to each packet and used when a user deletes a rule to tell conntrack to immediately drop any existing connections associated with the mark
  unsigned char first_instance; //TRUE for a first instance of an app or a parent process
  //sha must be a uchar, otherwise if it's just char, printf "%x" will promote it to int and cause a lot of pain, SIGV
  unsigned char sha[65]; //sha512sum digest
  unsigned long long stime; //obsolete: start time of the process
  ino_t inode; // /proc/PID entry's inode number. Can change only if another process with the same PID is running
  off_t exesize; //executable's size
  char cpuhog; //flag to show that ann app generates too many new connections and thus lpfw uses certain workarounds to decrease CPU consumption
  struct m_dlist *prev; //previous element in dlist
  struct m_dlist *next; // next element in dlist
  int *sockets_cache;//pointer to 2D array of cache
  DIR *dirstream; //a constantly open stream to /proc/PID/fd
  char pidfdpath[32];
  int ordinal_number; //each rule gets assigned a consecutive number
  //traffic counters
  ulong out_allow_counter;
  ulong out_block_counter;
  ulong in_allow_counter;
  ulong in_block_counter;
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

//not in use ATM, cache is part of dlist, until there arises a need to separate cache from dlist due to excessive mutex locking/unlocking
typedef struct m_cache_item
{
  struct m_cache_item *prev;
  struct m_cache_item *next;
  char path[PATHSIZE];
  char pid[PIDLENGTH];
  char perms[PERMSLENGTH];
  char sockets[MAX_CACHE][32];
} cache_item_old;




//constants for ftok() function

enum
{
  FTOKID_D2F,
  FTOKID_F2D,
  FTOKID_D2FLIST,
  FTOKID_F2DLIST,
  FTOKID_D2FDEL,
  FTOKID_F2DDEL = 5,
  FTOKID_CREDS,
  FTOKID_D2FTRAFFIC
};

enum
{
  ACCEPT,
  SOCKET_FOUND_IN_DLIST_ALLOW,
  PATH_FOUND_IN_DLIST_ALLOW,
  NEW_INSTANCE_ALLOW,
  FORKED_CHILD_ALLOW,
  CACHE_TRIGGERED_ALLOW,
  INKERNEL_RULE_ALLOW,
  ALLOW_VERDICT_MAX,

  SOCKET_FOUND_IN_DLIST_DENY,
  PATH_FOUND_IN_DLIST_DENY,
  NEW_INSTANCE_DENY,
  FORKED_CHILD_DENY,
  CACHE_TRIGGERED_DENY,
  DENY_VERDICT_MAX,

  DROP,
  GOTO_NEXT_STEP,
  PORT_NOT_FOUND,
  SOCKET_NONE_PIDFD,
  SENT_TO_FRONTEND,
  FRONTEND_NOT_LAUNCHED,
  FRONTEND_BUSY,
  ICMP_MORE_THAN_ONE_ENTRY,
  ICMP_NO_ENTRY,
  UNSUPPORTED_PROTOCOL,
  SHA_DONT_MATCH,
  EXESIZE_DONT_MATCH,
  STIME_DONT_MATCH,
  INODE_HAS_CHANGED,
  EXE_HAS_BEEN_CHANGED,
  PROCFS_ERROR,
  SRCPORT_NOT_FOUND_IN_PROC,
  INKERNEL_RULE_DENY,
  INKERNEL_SOCKET_FOUND,
  INKERNEL_IPADDRESS_NOT_IN_DLIST, //drop always
  SPOOFED_PID
};

//commands passed through msgq
enum
{
  D2FCOMM_ASK_OUT,
  D2FCOMM_ASK_IN,
  D2FCOMM_LIST,
  F2DCOMM_LIST,
  F2DCOMM_ADD,
  F2DCOMM_DEL, //not in use, superseded by DELANDACK
  F2DCOMM_DELANDACK,
  F2DCOMM_WRT,
  F2DCOMM_REG,
  F2DCOMM_UNREG
};


#endif /* INCLUDES_H_ */
// kate: indent-mode cstyle; space-indent on; indent-width 4;
//ss
