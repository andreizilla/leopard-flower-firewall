#!/bin/bash

#This script takes as an argument a git TAG and creates tar.bz release packages of that TAG in "releases" folder
#If no arguments other than TAG given, it creates all packages
#It is possible to create only certain packages by giving the following argument
# r - release package 
# s - source package

# Example ./release.sh 0.7.1 s r
# checks-out git's TAG 0.7.1 and creates source and release GUI package under
# /releases/0.7.1 directory
# If you want to compile GUI, you need to set PYINSTALLER variable, see below

if [ $# -eq 0 ]; then
	echo "Please specify a git TAG to checkout"
	exit 1
fi

r=0
s=0

if [ $# -gt 1 ]; then
	for opt in "$@"
	do
		case $opt in
			b) r=1 ;;
			s) s=1 ;;
		esac
	done
else
	r=1
	s=1
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

echo "#define VERSION \"$1\"" > version.h

if [ $s -eq 1 ]; then
	LPFW=lpfw_$1
	LPFWCLI=lpfw-cli_$1
	LPFWPYGUI=lpfw-pygui_$1

	mkdir $LPFW
	cp -R argtable $LPFW
	cp -R sha512 $LPFW
	cp -R common $LPFW
	cp lpfw.c $LPFW
	cp msgq.c $LPFW
	cp Makefile $LPFW
	cp configure $LPFW
	cp version.h $LPFW
	cp README $LPFW
	cp CHANGELOG $LPFW
	cp INSTALL $LPFW
	tar cjf $LPFW.tar.bz $LPFW

	mkdir $LPFWCLI
	cp -R common $LPFWCLI
	cp lpfw-cli/lpfwcli.c $LPFWCLI
	cp lpfw-cli/ipc.c $LPFWCLI
	cp lpfw-cli/Makefile $LPFWCLI
	tar cjf $LPFWCLI.tar.bz $LPFWCLI

	mkdir $LPFWPYGUI
	cp -R common $LPFWPYGUI
	cp lpfw-pygui/frontend.py $LPFWPYGUI
	cp lpfw-pygui/lpfwgui.py $LPFWPYGUI
	cp lpfw-pygui/popup_in.py $LPFWPYGUI
	cp lpfw-pygui/popup_out.py $LPFWPYGUI
	cp lpfw-pygui/resource.py $LPFWPYGUI
	cp lpfw-pygui/ipc_wrapper.c $LPFWPYGUI
	cp lpfw-pygui/Makefile $LPFWPYGUI
	tar cjf $LPFWPYGUI.tar.bz $LPFWPYGUI

	#cp lpfw.conf $LPFWSRC
	#cp 30-lpfw.conf $LPFWSRC

	cp $LPFW.tar.bz $LPFWCLI.tar.bz $LPFWPYGUI.tar.bz ../$RELEASE_FOLDER
fi


if [ $r -eq 1 ]; then
	LPFWBIN=lpfw_$1
	mkdir $LPFWBIN
	make
	cp lpfw $LPFWBIN
	cp lpfwcli $LPFWBIN
	cp README $LPFWBIN
	cp CHANGELOG $LPFWBIN
	cp lpfw.conf $LPFWBIN
	cp 30-lpfw.conf $LPFWBIN
	
	make ipcwrapper
	$PYINSTALLER -F gui/lpfwgui.py
	cp dist/lpfwgui $LPFWBIN
	
	tar cjf $LPFWBIN.tar.bz $LPFWBIN
	cp $LPFWBIN.tar.bz ../$RELEASE_FOLDER
fi

cd ..
rm -r -f newrepo
