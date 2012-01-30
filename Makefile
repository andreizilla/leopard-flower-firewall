DESTDIR = ./
GCCFLAGS = -g
SOURCES 	=	lpfw.c \
			msgq.c \
			test.c \
			sha512/sha.c \
			argtable/arg_end.c \
			argtable/arg_file.c \
			argtable/arg_int.c \
			argtable/arg_lit.c \
			argtable/arg_rem.c \
			argtable/arg_str.c \
			argtable/argtable2.c \
			common/includes.h \
			common/defines.h \

all: lpfw lpfwcli lpfwpygui
all: DESTDIR = $(shell pwd)

lpfw: $(SOURCES)
	gcc $(GCCFLAGS) $(SOURCES) -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

lpfwcli:
	cd lpfw-cli; make; make DESTDIR=$(DESTDIR) install

lpfwpygui:
	cd lpfw-pygui; make; make DESTDIR=$(DESTDIR) install

debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: lpfw lpfwcli lpfwpygui

install:
	cp lpfw $(DESTDIR)

#lpfw2: $(SOURCES)
#we link against our own -lnetfiler_conntrack library v. 0.9.1
#during runtime we search our own directory first for .so files, hence -Wl,-rpath,./
#UPDATE: no it's not fully broken, sometimes it works, sometimes it doesnt
#	gcc $(LPFWSOURCES) $(GCCFLAGS) -lnetfilter_queue -L/sda/newrepo/libnetfilter_conntrack-0.9.1/src/.libs -lnetfilter_conntrack -lpthread -o lpfw -Wl,-rpath,./
