DESTDIR = ./
DEBUG =
GCCFLAGS = -g

#SOURCES 	=	lpfw.c \
#			lpfw.h \
#			msgq.h \
#			test.c \
#			test.h \
#			sha512/sha.c \
#			argtable/arg_end.c \
#			argtable/arg_file.c \
#			argtable/arg_int.c \
#			argtable/arg_lit.c \
#			argtable/arg_rem.c \
#			argtable/arg_str.c \
#			argtable/argtable2.c \
#			common/includes.h \
#			common/defines.h \

ifeq ($(DESTDIR), ./)
    DESTDIR = $(shell pwd)
endif

all: lpfw install lpfwcli lpfwpygui

lpfw: sha.o msgq.o test.o \
      argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
      lpfw.c lpfw.h common/defines.h common/includes.h
	gcc $(GCCFLAGS) sha.o msgq.o test.o lpfw.c \
		      argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o \
		      -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

sha.o : sha512/sha.c sha512/sha.h sha512/u64.h
	gcc $(GCCFLAGS) -c sha512/sha.c
msgq.o : msgq.c msgq.h lpfw.h common/defines.h common/includes.h
	gcc $(GCCFLAGS) -c msgq.c
test.o : test.c test.h common/includes.h
	gcc $(GCCFLAGS) -c test.c
argtable2.o : argtable/argtable2.c
	gcc $(GCCFLAGS) -c argtable/argtable2.c
arg_end.o : argtable/arg_end.c
	gcc $(GCCFLAGS) -c argtable/arg_end.c
arg_file.o : argtable/arg_file.c
	gcc $(GCCFLAGS) -c argtable/arg_file.c
arg_int.o : argtable/arg_int.c
	gcc $(GCCFLAGS) -c argtable/arg_int.c
arg_lit.o : argtable/arg_lit.c
	gcc $(GCCFLAGS) -c argtable/arg_lit.c
arg_rem.o : argtable/arg_rem.c
	gcc $(GCCFLAGS) -c argtable/arg_rem.c
arg_str.o : argtable/arg_str.c
	gcc $(GCCFLAGS) -c argtable/arg_str.c

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
	rm sha.o msgq.o test.o \
	argtable2.o arg_end.o arg_file.o arg_int.o arg_lit.o arg_rem.o arg_str.o
