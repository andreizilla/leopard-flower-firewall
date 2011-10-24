#include "includes.h"
#include <sys/ipc.h>
#include <pthread.h>
#include "stdio.h"
#include "errno.h"
#include <string.h>
#include <stdlib.h>

int mqd_d2f, mqd_f2d, mqd_d2flist, mqd_d2fdel;

msg_struct msg_d2f = {1, 0};
msg_struct msg_d2flist = {1, 0};
msg_struct msg_d2fdel = {1, 0};
msg_struct msg_f2d = {1, 0};

void msgq_initialize();

extern void list();
extern void add_out(msg_struct add_struct);
extern void add_in(msg_struct add_struct);
extern int (*m_printf)(int loglevel, char *format, ...);


void msgq_list() {
    msg_f2d.item.command = F2DCOMM_LIST;
    if (msgsnd(mqd_f2d, &msg_f2d, sizeof (msg_struct), 0) == -1) {
        m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    };
    farray_clear();
    while (1) {
        if (msgrcv(mqd_d2flist, &msg_d2flist, sizeof (msg_struct), 0, 0) == -1) {
            m_printf(MLOG_INFO, "msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        };
        if (!strcmp(msg_d2flist.item.path, "EOF")) break;
        farray_add(msg_d2flist.item);
    }
    list();
}

void* listenthread(void * ptr) {
    ptr = 0;
    //fill the f_array with current darray data;;
    msgq_list();

    while (1) {
        if (msgrcv(mqd_d2f, &msg_d2f, sizeof (msg_struct), 0, 0) == -1) {
            m_printf(MLOG_INFO, "msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        };
        switch (msg_d2f.item.command) {
            case D2FCOMM_ASK_OUT:
                add_out(msg_d2f);
                break;

            case D2FCOMM_ASK_IN:
                add_in(msg_d2f);
                break;

                //refresh list because some app is no longer running
            case D2FCOMM_LIST:
                msgq_list();
                break;

            default:
                m_printf(MLOG_INFO, "unknown command", __FILE__, __LINE__);
        };

    }
}

void msgq_f2ddel(dlist rule, int ack_flag) {
    msg_f2d.item = rule;
    if (ack_flag) {
        msg_f2d.item.command = F2DCOMM_DELANDACK;
        if (msgsnd(mqd_f2d, &msg_f2d, sizeof (msg_struct), 0) == -1) {
            m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        };
	//get acknowledgement that the rule has been deleted
        if (msgrcv(mqd_d2fdel, &msg_d2fdel, sizeof (msg_struct), 0, 0) == -1) {
            m_printf(MLOG_INFO, "msgrcv: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        };
    }
}

void msgq_write() {
    msg_f2d.item.command = F2DCOMM_WRT;
    if (msgsnd(mqd_f2d, &msg_f2d, sizeof (msg_struct), 0) == -1) {
        m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    };
}

void msgq_add(msg_struct add_struct) {
    add_struct.item.command = F2DCOMM_ADD;
    if (msgsnd(mqd_f2d, &add_struct, sizeof (msg_struct), 0) == -1) {
        m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
    };
}

void frontend_register() {
    msg_f2d.item.command = F2DCOMM_REG;
    if (msgsnd(mqd_f2d, &msg_f2d, sizeof (msg_struct), 0) == -1) {
        m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
        return;
    }
}

    void frontend_unregister() {
        msg_f2d.item.command = F2DCOMM_UNREG;
        if (msgsnd(mqd_f2d, &msg_f2d, sizeof (msg_struct), 0) == -1) {
            m_printf(MLOG_INFO, "msgsnd: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            return;
        }
    }

        void msgq_initialize() {

            key_t ipckey_f2d, ipckey_d2f, ipckey_d2flist, ipckey_d2fdel;
            if ((ipckey_d2f = ftok(TMPFILE, FTOKID_D2F)) == -1) {
                m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            };
            if ((mqd_d2f = msgget(ipckey_d2f, 0)) == -1) {
                m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                exit(0);
            };

            if ((ipckey_d2flist = ftok(TMPFILE, FTOKID_D2FLIST)) == -1) {
                m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            };
            if ((mqd_d2flist = msgget(ipckey_d2flist, 0)) == -1) {
                m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                exit(0);
            };

            if ((ipckey_f2d = ftok(TMPFILE, FTOKID_F2D)) == -1) {
                m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            };
            if ((mqd_f2d = msgget(ipckey_f2d, 0)) == -1) {
                m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                exit(0);
            };

            if ((ipckey_d2fdel = ftok(TMPFILE, FTOKID_D2FDEL)) == -1) {
                m_printf(MLOG_INFO, "ftok: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
            };
            if ((mqd_d2fdel = msgget(ipckey_d2fdel, 0)) == -1) {
                m_printf(MLOG_INFO, "msgget: %s,%s,%d\n", strerror(errno), __FILE__, __LINE__);
                exit(0);
            };

            frontend_register();

            pthread_t listen_thread;
            pthread_create(&listen_thread, NULL, listenthread, NULL);
        }
