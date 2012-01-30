DESTDIR = ./
GCCFLAGS =
SOURCES 	=	ipc.c \
			lpfwcli.c \
			common/includes.h \
			common/defines.h \
			../argtable/arg_end.c \
			../argtable/arg_file.c \
			../argtable/arg_int.c \
			../argtable/arg_lit.c \
			../argtable/arg_rem.c \
			../argtable/arg_str.c \
			../argtable/argtable2.c \

all: lpfwcli

lpfwcli: $(SOURCES)
	gcc -g $(GCCFLAGS) $(SOURCES) -lncurses -lpthread -o lpfwcli

debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: lpfwcli


install:
	cp lpfwcli $(DESTDIR)
