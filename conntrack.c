#include "conntrack.h"
#include <string.h> //for memcpy
#include "lpfw.h"
#include "msgq.h" //for extern int mqd_d2ftraffic;
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "common/includes.h"
#include <pthread.h>
#include <errno.h>
#include <sys/msg.h>

//ct_delete_mark_thread uses waiting on condition
pthread_cond_t condvar = PTHREAD_COND_INITIALIZER;
pthread_mutex_t condvar_mutex = PTHREAD_MUTEX_INITIALIZER;
char predicate = FALSE;
//two NFCT_Q_DUMP simultaneous operations can produce an error
pthread_mutex_t ct_dump_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ct_entries_mutex = PTHREAD_MUTEX_INITIALIZER;

//netfilter mark to be put on an ALLOWed packet
int nfmark_to_set_out_tcp, nfmark_to_set_out_udp,nfmark_to_set_out_icmp, nfmark_to_set_in;
int nfmark_to_delete_in, nfmark_to_delete_out;

struct nf_conntrack *ct_out_tcp, *ct_out_udp, *ct_out_icmp, *ct_in;
struct nfct_handle *dummy_handle_delete, *dummy_handle_setmark_out, *dummy_handle_setmark_in;
struct nfct_handle *setmark_handle_out_tcp, *setmark_handle_in, *setmark_handle_out_udp, *setmark_handle_out_icmp;

//this array is used internally by lpfw to prepare for export
ulong ct_array[CT_ENTRIES_EXPORT_MAX][9] = {};
//this array is built for export to frontend based on ct_array
ulong ct_array_export[CT_ENTRIES_EXPORT_MAX][5] = {};
/*
  [0] nfmark (export[0])
  [1] bytes in allowed
  [2] bytes out allowed
  [3] bytes in from all previously destroyed conntracks which had this nfmark
  [4] bytes out from all previously destroyed conntracks which had this nfmark
  [5] [1] + [3] (export[1])
  [6] [2] + [4] (export[2])
  [7] total bytes in denied so far  (export[3])
  [8] total bytes out denied so far (export[4])
*/


void * ct_destroy_thread( void *ptr)
{
  struct nfct_handle *traffic_handle;
  if ((traffic_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, NF_NETLINK_CONNTRACK_DESTROY)) == NULL)
    {
      perror("nfct_open");
    }
  if ((nfct_callback_register(traffic_handle, NFCT_T_ALL, ct_destroy_cb, NULL) == -1))
    {
      perror("cb_reg");
    }
  int res = 0;
  res = nfct_catch(traffic_handle); //the thread should block here
}

void* ct_delete_mark_thread ( void* ptr )
{
  u_int8_t family = AF_INET; //used by conntrack
  struct nfct_handle *deletemark_handle;
  if ((deletemark_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((nfct_callback_register(deletemark_handle, NFCT_T_ALL, ct_delete_mark_cb, NULL) == -1))
    {
      perror("cb_reg");
    }

  while(1)
    {
      pthread_mutex_lock(&condvar_mutex);
      while(predicate == FALSE)
	{
	  pthread_cond_wait(&condvar, &condvar_mutex);
	}
      predicate = FALSE;
      pthread_mutex_unlock(&condvar_mutex);
      pthread_mutex_lock(&ct_dump_mutex);
      if (nfct_query(deletemark_handle, NFCT_Q_DUMP, &family) == -1)
	{
	  perror("query-DELETE");
	}
      pthread_mutex_unlock(&ct_dump_mutex);
    }
}

int setmark_out_tcp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_out_tcp);
  nfct_query(dummy_handle_setmark_out, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

int setmark_out_udp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_out_udp);
  nfct_query(dummy_handle_setmark_out, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

int setmark_out_icmp (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_out_icmp);
  nfct_query(dummy_handle_setmark_out, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

int setmark_in (enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  nfmark_to_set_in += NFMARK_DELTA;
  nfct_set_attr_u32(mct, ATTR_MARK, nfmark_to_set_in);
  nfct_query(dummy_handle_setmark_in, NFCT_Q_UPDATE, mct);
  return NFCT_CB_CONTINUE;
}

void  init_conntrack()
{
  u_int8_t family = AF_INET;
  if ((ct_out_tcp = nfct_new()) == NULL)
    {
      perror("new");
    }
  if ((ct_out_udp = nfct_new()) == NULL)
    {
      perror("new");
    }
  if ((ct_out_icmp = nfct_new()) == NULL)
    {
      perror("new");
    }
  if ((ct_in = nfct_new()) == NULL)
    {
      perror("new");
    }
  if ((dummy_handle_delete = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if (nfct_query(dummy_handle_delete, NFCT_Q_FLUSH, &family) == -1)
  {
      M_PRINTF ( MLOG_INFO, "nfct_query FLUSH %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
  }
  if ((dummy_handle_setmark_out = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((dummy_handle_setmark_in = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((setmark_handle_out_tcp = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((setmark_handle_out_udp = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((setmark_handle_out_icmp = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((setmark_handle_in = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((nfct_callback_register(setmark_handle_out_tcp, NFCT_T_ALL, setmark_out_tcp, NULL) == -1))
    {
      perror("cb_reg");
    }
  if ((nfct_callback_register(setmark_handle_out_udp, NFCT_T_ALL, setmark_out_udp, NULL) == -1))
    {
      perror("cb_reg");
    }
  if ((nfct_callback_register(setmark_handle_out_icmp, NFCT_T_ALL, setmark_out_icmp, NULL) == -1))
    {
      perror("cb_reg");
    }
  if ((nfct_callback_register(setmark_handle_in, NFCT_T_ALL, setmark_in, NULL) == -1))
    {
      perror("cb_reg");
    }
  return;
}



int ct_delete_mark_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int mark = nfct_get_attr_u32(mct, ATTR_MARK);
  if ( mark == nfmark_to_delete_in || mark == nfmark_to_delete_out)
    {
      if (nfct_query(dummy_handle_delete, NFCT_Q_DESTROY, mct) == -1)
	{
	  M_PRINTF ( MLOG_DEBUG, "nfct_query DESTROY %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
	  return NFCT_CB_CONTINUE;
	}
      M_PRINTF ( MLOG_DEBUG, "deleted entry %s,%s,%d\n", strerror ( errno ), __FILE__, __LINE__ );
      return NFCT_CB_CONTINUE;
    }
  return NFCT_CB_CONTINUE;
}

int ct_dump_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int mark;
  ulong in_bytes, out_bytes;
  if ((mark = nfct_get_attr_u32(mct, ATTR_MARK)) == 0)
    {
      return NFCT_CB_CONTINUE;
    }
  out_bytes = nfct_get_attr_u32(mct, ATTR_ORIG_COUNTER_BYTES);
  in_bytes = nfct_get_attr_u32(mct, ATTR_REPL_COUNTER_BYTES);

  pthread_mutex_lock ( &ct_entries_mutex);
  int i;
  for (i = 0; ct_array[i][0] != 0; ++i)
    {
      if (ct_array[i][0] != mark) continue;
      ct_array[i][1] += in_bytes;
      ct_array[i][2] += out_bytes;
      pthread_mutex_unlock ( &ct_entries_mutex);
      return NFCT_CB_CONTINUE;
    }
  //the entry is not yet in array, adding now
  ct_array[i][0] = mark;
  ct_array[i][1] = in_bytes;
  ct_array[i][2] = out_bytes;
  pthread_mutex_unlock ( &ct_entries_mutex);
  return NFCT_CB_CONTINUE;
}

//When conntrack deletes an entry, we get called. Bump up the in/out bytes statistics
int ct_destroy_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *mct,void *data)
{
  int mark;
  ulong in_bytes, out_bytes;
  if ((mark = nfct_get_attr_u32(mct, ATTR_MARK)) == 0)
    {
      //printf ("destroy nfmark 0 detected \n");
      return NFCT_CB_CONTINUE;
    }
  out_bytes = nfct_get_attr_u32(mct, ATTR_ORIG_COUNTER_BYTES);
  in_bytes = nfct_get_attr_u32(mct, ATTR_REPL_COUNTER_BYTES);

  int i;
  for (i = 0; ct_array[i][0] != 0; ++i)
    {
      if (ct_array[i][0] != mark) continue;
      ct_array[i][3] += in_bytes;
      ct_array[i][4] += out_bytes;
      return NFCT_CB_CONTINUE;
    }
  printf ("Error: there was a request to destroy nfmark which is not in the list \n");
  return NFCT_CB_CONTINUE;
}

void * ct_dump_thread( void *ptr)
{
  u_int8_t family = AF_INET;
  struct nfct_handle *ct_dump_handle;
  if ((ct_dump_handle = nfct_open(NFNL_SUBSYS_CTNETLINK, 0)) == NULL)
    {
      perror("nfct_open");
    }
  if ((nfct_callback_register(ct_dump_handle, NFCT_T_ALL, ct_dump_cb, NULL) == -1))
    {
      perror("cb_reg");
    }
  while(1)
    {
      //zero out from previous iteration
      int i;
      for (i=0; i<CT_ENTRIES_EXPORT_MAX; ++i)
	{
	  ct_array[i][1] = ct_array[i][2] = ct_array_export[i][0] = ct_array_export[i][1] =
		  ct_array_export[i][2] = ct_array_export[i][3] = ct_array_export[i][4] = 0;
	}
      pthread_mutex_lock(&ct_dump_mutex);
      if (nfct_query(ct_dump_handle, NFCT_Q_DUMP, &family) == -1)
	{
	  perror("query-DELETE");
	}
      pthread_mutex_unlock(&ct_dump_mutex);
//we get here only when dumping operation finishes and traffic_callback has created a new array of
//conntrack entries

      pthread_mutex_lock(&ct_entries_mutex);

      for (i = 0; ct_array[i][0] != 0; ++i)
	{
	  ct_array[i][5] = ct_array[i][1]+ct_array[i][3];
	  ct_array[i][6] = ct_array[i][2]+ct_array[i][4];
	}

      //rearrange array for export
      int j;
      for (i=0; ct_array[i][0] != 0; ++i)
	{
	  for (j=0; ct_array_export[j][0] !=0; ++j)
	    {
	      //if this is an IN nfmark
	      if (ct_array[i][0] >= NFMARKIN_BASE)
		{
		  //find its OUT nfmark
		  int delta = ct_array[i][0] - NFMARK_DELTA;
		  if (delta == ct_array_export[j][0])
		    {
		      //bytes in for IN nfmark are bytes out for OUT nfmark
		      ct_array_export[j][1] += ct_array[i][6];
		      ct_array_export[j][2] += ct_array[i][5];
		      ct_array_export[j][3] += ct_array[i][8];
		      ct_array_export[j][4] += ct_array[i][7];
		      goto next;
		    }
		}
	      //else if this is a OUT nfmark
	      if (ct_array[i][0] == ct_array_export[j][0])
		{
		  ct_array_export[j][1] += ct_array[i][5];
		  ct_array_export[j][2] += ct_array[i][6];
		  ct_array_export[j][3] += ct_array[i][7];
		  ct_array_export[j][4] += ct_array[i][8];

		  goto next;
		}
	    }
	  //Doesn't exist in export list, create an entry
	  if (ct_array[i][0] >= NFMARKIN_BASE)
	    {
	      ct_array_export[j][0] = ct_array[i][0] - NFMARK_DELTA;
	      ct_array_export[j][1] = ct_array[i][6];
	      ct_array_export[j][2] = ct_array[i][5];
	      ct_array_export[j][3] = ct_array[i][8];
	      ct_array_export[j][4] = ct_array[i][7];

	    }
	  else
	    {
	      ct_array_export[j][0] = ct_array[i][0];
	      ct_array_export[j][1] = ct_array[i][5];
	      ct_array_export[j][2] = ct_array[i][6];
	      ct_array_export[j][3] = ct_array[i][7];
	      ct_array_export[j][4] = ct_array[i][8];

	    }
next:
;
      }

      pthread_mutex_unlock(&ct_entries_mutex);

#ifdef DEBUG
      for (i = 0; ct_array_export[i][0] != 0; ++i)
	{
	  //printf("rulesexp: %d: >%d <%d \n", rulesexp[i][0], rulesexp[i][1], rulesexp[i][2]);
	}
#endif

      mymsg msg;
      msg.type = 1;
      memcpy (msg.ct_array_export, ct_array_export, sizeof(msg.ct_array_export));

      msgctl(mqd_d2ftraffic, IPC_STAT, msgqid_d2ftraffic);
      //don't send if there is already some data down the queue that frontend hasn't yet received
      if (msgqid_d2ftraffic->msg_qnum == 0)
	{
	  if ( msgsnd ( mqd_d2ftraffic, &msg, sizeof (msg.ct_array_export), IPC_NOWAIT ) == -1 )
	    {
	      M_PRINTF (MLOG_INFO, "msgsnd: %d %s,%s,%d\n",errno, strerror ( errno ), __FILE__, __LINE__ );
	    }
	}
      sleep(1);
    }
}

void denied_traffic_add (const int direction, const int mark, const int bytes)
{
  int i;
    pthread_mutex_lock ( &ct_entries_mutex);
    for (i = 0; ct_array[i][0] != 0; ++i)
      {
	if (ct_array[i][0] != mark) continue;
	if (direction == DIRECTION_OUT)
	{
	    ct_array[i][8] += bytes;
	}
	else if (direction == DIRECTION_IN)
	{
	    ct_array[i][7] += bytes;
	}
	pthread_mutex_unlock ( &ct_entries_mutex);
	return;
      }
    //the entry is not yet in array, adding now
    ct_array[i][0] = mark;
    if (direction == DIRECTION_OUT)
    {
	ct_array[i][8] += bytes;
    }
    else if (direction == DIRECTION_IN)
    {
	ct_array[i][7] += bytes;
    }
    pthread_mutex_unlock ( &ct_entries_mutex);
    return ;
}
