DESTDIR = ./
DEBUG =
GCCFLAGS = -gdwarf-2 -g3

SYSCALLS := fopen			\
	    opendir			\
	    nfct_query			\
	    nfct_callback_register	\
	    fseek			\
	    fclose			\
	    fputs			\
	    fputc			\
	    fgets			\
	    access			\
	    stat			\
	    system			\
	    nfq_unbind_pf		\
	    nfq_bind_pf			\
	    nfq_set_mode		\
	    nfq_set_queue_maxlen	\
	    nfct_new			\
	    nfct_open			\
	    write			\
	    nfq_create_queue		\
	    nfq_open			\
	    fileno			\
	    pthread_mutex_lock		\
	    pthread_mutex_unlock	\
	    cap_get_proc		\
	    cap_set_proc		\
	    cap_clear			\
	    cap_free			\
	    cap_set_flag		\
	    nfq_close			\
	    malloc			\
	    closedir			\
	    pthread_cond_signal		\
	    mkfifo			\
	    open			\
	    fsync			\
	    lseek			\
	    read			\
	    ftok			\
	    msgget			\
	    getenv			\
	    msgsnd			\
	    remove			\
	    readlink			\
	    mmap			\
	    close			\
	    munmap			\
	    pthread_create		\
	    msgctl			\

SYSCALL_WRAP := $(foreach syscall,$(SYSCALLS),-Wl,-wrap,$(syscall))
OBJS := main.o sha512/sha.o msgq.o conntrack.o syscall_wrap.o test.o \
argtable/argtable2.o argtable/arg_end.o argtable/arg_file.o argtable/arg_int.o \
argtable/arg_lit.o argtable/arg_rem.o argtable/arg_str.o

ifeq ($(DESTDIR), ./)
    DESTDIR = $(shell pwd)
endif

all: lpfw install lpfwcli lpfwpygui

lpfw: Makefile $(OBJS)
	gcc $(GCCFLAGS) $(SYSCALL_WRAP) $(OBJS) \
	    -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

# pull in dependency info for *existing* .o files
-include $(OBJS:.o=.d)

%.o: %.c
	gcc $(GCCFLAGS) -c $*.c -o $*.o
	gcc -MM $(GCCFLAGS) $*.c > $*.d

lpfwcli:
	cd lpfw-cli; make $(DEBUG); make DESTDIR=$(DESTDIR) install

lpfwpygui:
	cd lpfw-pygui; make $(DEBUG); make DESTDIR=$(DESTDIR) install

debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: DESTDIR = $(shell pwd)
debug: DEBUG = debug
debug: lpfw install lpfwcli lpfwpygui

install: dummy
dummy: lpfw
	cp lpfw $(DESTDIR)
	touch dummy

clean:
	rm *.d *.o
	cd sha512; rm *.d *.o
	cd argtable; rm *.d *.o
