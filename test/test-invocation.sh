#!/bin/bash
#
# Copyright (C) 2016 - 2021, Stephan Mueller <smueller@chronox.de>
#
# License: see LICENSE file in root directory
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
# WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.
#

DIRNAME="$(dirname "$0")"
. "$DIRNAME/libtest.sh"

COMPILE_OPTS="--enable-kcapi-test --enable-kcapi-encapp --enable-kcapi-hasher --enable-kcapi-dgstapp --enable-kcapi-rngapp --enable-lib-kpp --enable-lib-asym"

exec_test()
{
	"$DIRNAME/test.sh"
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	"$DIRNAME/kcapi-enc-test.sh"
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	"$DIRNAME/kcapi-dgst-test.sh"
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	"$DIRNAME/hasher-test.sh"
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	"$DIRNAME/kcapi-enc-test-large.sh"
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	"$DIRNAME/kcapi-convenience.sh"
	ret=$?
	if [ $ret -ne 0 ]
	then
		exit $ret
	fi

	# Run optionally.
	if [ ! -z "$ENABLE_FUZZ_TEST" ]
	then
		"$DIRNAME/kcapi-fuzz-test.sh"
		ret=$?
		if [ $ret -ne 0 ]
		then
			exit $ret
		fi
	fi

	# Only execute on bare metal
	if ! dmesg | grep -i Hypervisor | grep -q -i detected
	then
		"$DIRNAME/virttest.sh"
		ret=$?
		if [ $ret -ne 0 ]
		then
			exit $ret
		fi
	fi
}

# Only execute tests without compilation on virtual environment
if [ "$KCAPI_TEST_LOCAL" -ne 1 ] || mount | grep -q "9p2000"
then
	exec_test
	exit 0
fi

# default invocation
(cd "$DIRNAME/.." && ./configure $COMPILE_OPTS && make)
if [ $? -ne 0 ]
then
	echo "Compilation failure"
	exit 1
fi
exec_test

"$DIRNAME/compile-test.sh"
ret=$?
if [ $ret -ne 0 ]
then
	exit $ret
fi

(cd "$DIRNAME/.." && make distclean > /dev/null 2>&1)

# if we are on 64 bit system, test 32 bit alternative mode,
# except is has been disabled explicitly.
if $(uname -m | grep -q "x86_64") && [ -z "$NO_32BIT_TEST" ]
then
	(
		cd "$DIRNAME/.." && \
		LDFLAGS=-m32 CFLAGS=-m32 ./configure $COMPILE_OPTS && \
		make
	)
	if [ $? -ne 0 ]
	then
		echo "32 bit compilation failure"
		exit 1
	fi
	exec_test
	(cd "$DIRNAME/.." && make distclean > /dev/null 2>&1)
fi

exit 0
