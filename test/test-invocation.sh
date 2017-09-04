#!/bin/bash

DIR=$(dirname $0)
cd $DIR

COMPILE_OPTS="--enable-kcapi-test --enable-kcapi-encapp --enable-kcapi-hasher --enable-kcapi-dgstapp --enable-kcapi-rngapp"

exec_test()
{
	${DIR}/test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	${DIR}/kcapi-enc-test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	${DIR}/kcapi-dgst-test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	${DIR}/hasher-test.sh
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

#	${DIR}/kcapi-enc-test-large.sh
#	ret=$?
#	if [ $ret -ne 0 ]
#	then
#		exit $ret
#	fi

	# Only execute on bare metal
	if ! dmesg | grep -i Hypervisor | grep -q -i detected
	then
		${DIR}/virttest.sh
		ret=$?
		if [ $ret -ne 0 ]
		then
			exit $ret
		fi

		${DIR}/compile-test.sh
		ret=$?
		if [ $ret -ne 0 ]
		then
			exit $ret
		fi
	fi
}

# Only execute tests without compilation on virtual environment
if dmesg | grep -i Hypervisor | grep -q -i detected
then
	exec_test
	exit 0
fi

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
	make distclean > /dev/null 2>&1
fi

exit 0
