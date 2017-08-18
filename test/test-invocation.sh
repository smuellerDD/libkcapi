#!/bin/bash

COMPILE_OPTS="--enable-kcapi-test --enable-kcapi-encapp --enable-kcapi-hasher --enable-kcapi-dgstapp"

exec_test()
{
	./test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	./kcapi-enc-test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	./kcapi-dgst-test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	./compile-test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi
}

# default invocation
CWD=$(pwd)
cd ..
./configure $COMPILE_OPTS
make
if [ $? -ne 0 ]
then
	echo "Compilation failure"
	exit 1
fi
cd $CWD
exec_test
cd ..

make distclean

# if we are on 64 bit system, test 32 bit alternative mode
if $(uname -m | grep -q "x86_64")
then
	LDFLAGS=-m32 CFLAGS=-m32 ./configure $COMPILE_OPTS
	make
	if [ $? -ne 0 ]
	then
		echo "32 bit compilation failure"
		exit 1
	fi
	cd $CWD
	exec_test
	cd ..
	make distclean
fi
