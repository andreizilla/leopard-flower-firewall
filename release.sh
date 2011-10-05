#!/bin/bash

#This script takes as an argument a git TAG and creates tar.bz release packages of that TAG in "releases" folder
#If no arguments other than TAG given, it creates all packages
#It is possible to create only certain packages by giving the following argument
# b - binary package
# s - source package
# g - standlone GUI package
# p - Python-based GUI package
# Example ./release.sh 0.7.1 s g
# checks-out git's TAG 0.7.1 and creates source and standalone GUI package under
# /releases/0.7.1 directory
# If you want to compile standalone GUI, you need to set PYINSTALLER variable, see below

if [ $# -eq 0 ]; then
	echo "Please specify a git TAG to checkout"
	exit 1
fi

b=0
s=0
g=0
p=0

if [ $# -gt 1 ]; then
	for opt in "$@"
	do
		case $opt in
			b) b=1 ;;
			s) s=1 ;;
			g) g=1 ;;
			p) p=1 ;;
		esac
	done
else
	b=1
	s=1
	g=1
	p=1
fi
	
RELEASE_FOLDER=$1
#change this variable to point to your pyinstaller installation
PYINSTALLER=/home/wwwwww/Downloads/pyinstaller-1.5.1/pyinstaller.py


if [ ! -d "releases" ]; then
	echo "Creating folder releases"
	mkdir releases
fi

#returns 0 when tag exists
git show-ref --tags --quiet --verify refs/tags/$1
if [ $? == 1 ];then
	echo "Tag $1 doesn't exist in gittree"
	exit 1
else
	echo "Tag $1 found"
fi

if [ -d "releases/newrepo" ]; then
	echo "What is newrepo folder doing here? Emptying it..."
	rm -r -f releases/newrepo
fi

#clone the repository to releases/newrepo and checkout TAG
cd releases
git clone file:////sda/newrepo
cd newrepo
git checkout $1 --quiet

#cd to releases
cd ..
#create an empty folder
if [ -d "$1" ]; then
	echo "Folder $1 exists, creating another with the current time"
	mtime=`date --date=now +%H:%M:%S`
	RELEASE_FOLDER=$1_$mtime
	if [ -d "$1_$mtime" ]; then
		echo "The luckiest person on the planet detected. Please report. Exitting"
		exit 1
	fi
	mkdir $1_$mtime
else
	echo "Creating folder $1"
	mkdir $1
fi

cd newrepo

if [ $s -eq 1 ]; then
	LPFWSRC=lpfw_backend_$1_source
	mkdir $LPFWSRC
	cp -R argtable $LPFWSRC
	cp -R gui $LPFWSRC
	cp u64.h $LPFWSRC
	cp sha.h $LPFWSRC
	cp sha.c $LPFWSRC
	cp README $LPFWSRC
	cp msgq.c $LPFWSRC
	cp Makefile $LPFWSRC
	cp lpfwcli.c $LPFWSRC
	cp lpfw.conf $LPFWSRC
	cp lpfw.c $LPFWSRC
	cp ipc.c $LPFWSRC
	cp includes.h $LPFWSRC
	cp defines.h $LPFWSRC
	cp CHANGELOG $LPFWSRC
	cp INSTALL $LPFWSRC
	cp 30-lpfw.conf $LPFWSRC
	tar cjf $LPFWSRC.tar.bz $LPFWSRC
	cp $LPFWSRC.tar.bz ../$RELEASE_FOLDER

fi

if [ $b -eq 1 ]; then
	LPFWBIN=lpfw_backend_$1
	mkdir $LPFWBIN
	make
	cp lpfw $LPFWBIN
	cp lpfwcli $LPFWBIN
	cp README $LPFWBIN
	cp CHANGELOG $LPFWBIN
	cp lpfw.conf $LPFWBIN
	cp 30-lpfw.conf $LPFWBIN
	tar cjf $LPFWBIN.tar.bz $LPFWBIN
	cp $LPFWBIN.tar.bz ../$RELEASE_FOLDER

fi

if [ $p -eq 1 ]; then
	LPFWGUIPY=lpfw_frontend_python_$1
	mkdir $LPFWGUIPY
	make ipcwrapper
	cp gui/resource.py $LPFWGUIPY
	cp gui/README.guipy $LPFWGUIPY
	cp gui/popupdialog.py $LPFWGUIPY
	cp gui/lpfwgui.py $LPFWGUIPY
	cp gui/frontend.py $LPFWGUIPY
	tar cjf $LPFWGUIPY.tar.bz $LPFWGUIPY
	cp $LPFWGUIPY.tar.bz ../$RELEASE_FOLDER

fi

if [ $g -eq 1 ]; then
	LPFWGUI=lpfw_frontend_standalone_$1
	mkdir $LPFWGUI
	make ipcwrapper
	$PYINSTALLER -F gui/lpfwgui.py
	cp dist/lpfwgui $LPFWGUI
	cp gui/README.standalone $LPFWGUI
	tar cjf $LPFWGUI.tar.bz $LPFWGUI
	cp $LPFWGUI.tar.bz ../$RELEASE_FOLDER
fi

cd ..
rm -r -f newrepo
