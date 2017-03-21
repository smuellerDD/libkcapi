#!/bin/bash

# default invocation
CWD=$(pwd)
cd ..
./configure --enable-kcapi-test
make
if [ $? -ne 0 ]
then
	echo "Compilation failure"
	exit 1
fi
cd $CWD
./test.sh
ret=$?
if [ $ret -ne 0 ]
then
	exit $ret
fi
cd ..
make distclean

# if we are on 64 bit system, test 32 bit alternative mode
if $(uname -m | grep -q "x86_64")
then
	LDFLAGS=-m32 CFLAGS=-m32 ./configure --enable-kcapi-test
	make
	if [ $? -ne 0 ]
	then
		echo "32 bit compilation failure"
		exit 1
	fi
	cd $CWD
	./test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi
	cd ..
	make distclean
fi
