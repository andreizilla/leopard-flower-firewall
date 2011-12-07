GCCFLAGS =
DESTDIR = ./

all: ipc_wrapper.so

ipc_wrapper.so: ipc_wrapper.c
	gcc ipc_wrapper.c $(GCCFLAGS) -shared -lpython2.6 -o ipc_wrapper.so

debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: ipc_wrapper.so
