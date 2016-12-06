#!/bin/bash

# default invocation
make
if [ $? -ne 0 ]
then
	echo "Compilation failure"
	exit 1
fi
./test.sh
ret=$?
if [ $ret -ne 0 ]
then
	exit $ret
fi
make clean

# if we are on 64 bit system, test 32 bit alternative mode
if $(uname -m | grep -q "x86_64")
then
	make -f Makefile.m32
	if [ $? -ne 0 ]
	then
		echo "32 bit compilation failure"
		exit 1
	fi
	./test.sh 32
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi
	make -f Makefile.m32 clean
fi
