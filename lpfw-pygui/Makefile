GCCFLAGS =
DESTDIR = ./
SOURCES 	=	lpfw-pygui.c \
			../common/includes.h \
			../common/defines.h \
			../argtable/arg_end.c \
			../argtable/arg_file.c \
			../argtable/arg_int.c \
			../argtable/arg_lit.c \
			../argtable/arg_rem.c \
			../argtable/arg_str.c \
			../argtable/argtable2.c \

all: ipc_wrapper2 lpfwpygui

ipc_wrapper.so: ipc_wrapper.c
	gcc ../common/includes.h ipc_wrapper.c $(GCCFLAGS) -shared -lpython2.6 -o ipc_wrapper.so

ipc_wrapper2: ipc_wrapper2.c
	gcc ../common/includes.h ipc_wrapper2.c $(GCCFLAGS) -lpthread -o ipc_wrapper2

lpfwpygui:  $(SOURCES)
	gcc $(SOURCES) -o lpfwpygui


debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: ipc_wrapper2 lpfwpygui
