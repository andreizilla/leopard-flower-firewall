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

OBJS := main.o sha.o msgq.o conntrack.o syscall_wrap.o test.o \
argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o

ifeq ($(DESTDIR), ./)
    DESTDIR = $(shell pwd)
endif

all: lpfw install lpfwcli lpfwpygui

lpfw: Makefile $(OBJS)
	gcc $(GCCFLAGS) $(SYSCALL_WRAP) $(OBJS) \
	    -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

# pull in dependency info for *existing* .o files
-include $(OBJS:.o=.d)

main.o:	main.c
	gcc $(GCCFLAGS) -c main.c
	gcc -MM $(GCCFLAGS) $*.c > $*.d
sha.o:	sha512/sha.c sha512/sha.h sha512/u64.h
	gcc $(GCCFLAGS) -c sha512/sha.c
	gcc -MM $(GCCFLAGS) sha512/$*.c > $*.d
msgq.o: msgq.c msgq.h main.h common/defines.h common/includes.h
	gcc $(GCCFLAGS) -c msgq.c
	gcc -MM $(GCCFLAGS) $*.c > $*.d
conntrack.o: conntrack.c conntrack.h
	gcc $(GCCFLAGS) -c conntrack.c
	gcc -MM $(GCCFLAGS) $*.c > $*.d
syscall_wrap.o: syscall_wrap.c
	gcc $(GCCFLAGS) -c syscall_wrap.c
	gcc -MM $(GCCFLAGS) $*.c > $*.d
test.o: test.c test.h common/includes.h
	gcc $(GCCFLAGS) -c test.c
	gcc -MM $(GCCFLAGS) $*.c > $*.d
argtable2.o : argtable/argtable2.c
	gcc $(GCCFLAGS) -c argtable/argtable2.c
	gcc -MM $(GCCFLAGS) argtable/$*.c > $*.d
arg_end.o : argtable/arg_end.c
	gcc $(GCCFLAGS) -c argtable/arg_end.c
	gcc -MM $(GCCFLAGS) argtable/$*.c > $*.d
arg_file.o : argtable/arg_file.c
	gcc $(GCCFLAGS) -c argtable/arg_file.c
	gcc -MM $(GCCFLAGS) argtable/$*.c > $*.d
arg_int.o : argtable/arg_int.c
	gcc $(GCCFLAGS) -c argtable/arg_int.c
	gcc -MM $(GCCFLAGS) argtable/$*.c > $*.d
arg_lit.o : argtable/arg_lit.c
	gcc $(GCCFLAGS) -c argtable/arg_lit.c
	gcc -MM $(GCCFLAGS) argtable/$*.c > $*.d
arg_rem.o : argtable/arg_rem.c
	gcc $(GCCFLAGS) -c argtable/arg_rem.c
	gcc -MM $(GCCFLAGS) argtable/$*.c > $*.d
arg_str.o : argtable/arg_str.c
	gcc $(GCCFLAGS) -c argtable/arg_str.c
	gcc -MM $(GCCFLAGS) argtable/$*.c > $*.d

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
