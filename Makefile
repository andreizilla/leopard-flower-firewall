GCCFLAGS = -fno-stack-protector

LPFWSOURCES 	=	lpfw.c \
			msgq.c \
			sha512/sha.c \
			argtable/arg_end.c \
			argtable/arg_file.c \
			argtable/arg_int.c \
			argtable/arg_lit.c \
			argtable/arg_rem.c \
			argtable/arg_str.c \
			argtable/argtable2.c \
			includes.h \
			defines.h \


all: lpfw lpfwcli

lpfw: $(LPFWSOURCES)
#we link against our own -lnetfiler_conntrack library v. 0.9.1 (0.0.101 is broken)
#during runtime we search our own directory first for .so files, hence -Wl,-rpath,./
	gcc $(LPFWSOURCES) $(GCCFLAGS) -lnetfilter_queue -lnetfilter_conntrack -lpthread -o lpfw

lpfwcli: lpfwcli.c ipc.c
	gcc lpfwcli.c ipc.c $(GCCFLAGS) -lncurses -lpthread -o lpfwcli

ipcwrapper: gui/IPC_wrapper.so
gui/IPC_wrapper.so: ipc_wrapper.c
	gcc ipc_wrapper.c $(GCCFLAGS) -shared -lpython2.6 -o gui/IPC_wrapper.so

ipcwrapper_debug: GCCFLAGS += -g -DDEBUG 
ipcwrapper_debug: ipcwrapper
	
debug: GCCFLAGS += -g -DDEBUG
debug: lpfw lpfwcli


lpfw2: $(LPFWSOURCES)
#we link against our own -lnetfiler_conntrack library v. 0.9.1 (0.0.101 is broken)
#during runtime we search our own directory first for .so files, hence -Wl,-rpath,./
#UPDATE: no it's not fully broken, sometimes it works, sometimes it doesnt
	gcc $(LPFWSOURCES) $(GCCFLAGS) -lnetfilter_queue -L/sda/newrepo/libnetfilter_conntrack-0.9.1/src/.libs -lnetfilter_conntrack -lpthread -o lpfw -Wl,-rpath,./
