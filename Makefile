GCCFLAGS = -fno-stack-protector

LPFWSOURCES 	=	lpfw.c \
			msgq.c \
			sha.c \
			argtable/arg_end.c \
			argtable/arg_file.c \
			argtable/arg_int.c \
			argtable/arg_lit.c \
			argtable/arg_rem.c \
			argtable/arg_str.c \
			argtable/argtable2.c

all: lpfw lpfwcli

lpfw: $(LPFWSOURCES)
	gcc $(LPFWSOURCES) $(GCCFLAGS) -lnetfilter_queue -lnetfilter_conntrack -lpthread -o lpfw

lpfwcli: lpfwcli.c ipc.c
	gcc lpfwcli.c ipc.c $(GCCFLAGS) -lncurses -lpthread -o lpfwcli

#gcc lpfwcli.c ipc.c $(GCCFLAGS) -static -lncurses -Bdynamic -lpthread -o lpfwcli


ipcwrapper: gui/IPC_wrapper.so
gui/IPC_wrapper.so: ipc_wrapper.c
	gcc ipc_wrapper.c $(GCCFLAGS) -shared -lpython2.6 -o gui/IPC_wrapper.so

ipcwrapper_debug: GCCFLAGS += -g -DDEBUG 
ipcwrapper_debug: ipcwrapper
	
debug: GCCFLAGS += -g -DDEBUG
debug: lpfw lpfwcli