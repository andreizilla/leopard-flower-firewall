GCCFLAGS = -g
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

ipc_wrapper2: ipc_wrapper2.c
	gcc ../common/includes.h ipc_wrapper2.c $(GCCFLAGS) -lpthread -o ipc_wrapper2

lpfwpygui:  $(SOURCES)
	gcc $(SOURCES) $(GCCFLAGS) -o lpfwpygui

dummy: lpfwpygui ipc_wrapper2 resource.py prefs.py popup_out.py popup_in.py lpfwgui.py frontend.py
	cp lpfwpygui $(DESTDIR)
	mkdir -p $(DESTDIR)/lpfw-pygui
	cp ipc_wrapper2 $(DESTDIR)/lpfw-pygui
	cp resource.py $(DESTDIR)/lpfw-pygui
	cp prefs.py $(DESTDIR)/lpfw-pygui
	cp popup_out.py $(DESTDIR)/lpfw-pygui
	cp popup_in.py $(DESTDIR)/lpfw-pygui
	cp lpfwgui.py $(DESTDIR)/lpfw-pygui
	cp frontend.py $(DESTDIR)/lpfw-pygui
	touch dummy

install: dummy

debug: GCCFLAGS += -g -DDEBUG2 -DDEBUG -DDEBUG3
debug: ipc_wrapper2 lpfwpygui

#Obsolete, keep here just in case
#ipc_wrapper.so: ipc_wrapper.c
#	gcc ../common/includes.h ipc_wrapper.c $(GCCFLAGS) -shared -lpython2.6 -o ipc_wrapper.so
