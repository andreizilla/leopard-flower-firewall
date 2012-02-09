DESTDIR = ./
DEBUG =
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

ifeq ($(DESTDIR), ./)
    DESTDIR = $(shell pwd)
endif

all: lpfw install lpfwcli lpfwpygui

lpfw: $(SOURCES)
	gcc $(GCCFLAGS) $(SOURCES) -lnetfilter_queue -lnetfilter_conntrack -lpthread -lcap -o lpfw

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
