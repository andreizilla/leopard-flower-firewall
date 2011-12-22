GCCFLAGS =
DESTDIR = ./

all: ipc_wrapper.so ipc_wrapper2

ipc_wrapper.so: ipc_wrapper.c
	gcc ipc_wrapper.c $(GCCFLAGS) -shared -lpython2.6 -o ipc_wrapper.so

ipc_wrapper2: ipc_wrapper2.c
	gcc ipc_wrapper2.c $(GCCFLAGS) -lpthread -o ipc_wrapper2

debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: ipc_wrapper.so ipc_wrapper2
