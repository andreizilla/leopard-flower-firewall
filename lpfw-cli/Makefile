DESTDIR = ./
GCCFLAGS =
SOURCES 	=	ipc.c \
			lpfwcli.c \
			common/includes.h \
			common/defines.h \


all: lpfwcli

lpfwcli: $(SOURCES)
	gcc $(GCCFLAGS) $(SOURCES) -lncurses -lpthread -o lpfwcli

debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: lpfwcli


install:
	cp lpfwcli $(DESTDIR)
