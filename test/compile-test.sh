#!/bin/bash
#
# Copyright (C) 2017 - 2021, Stephan Mueller <smueller@chronox.de>
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
# This test tries to compile all code and tries to install it
#

DIRNAME="$(dirname "$0")"
. "$DIRNAME/libtest.sh"

if [ "$KCAPI_TEST_LOCAL" -ne 1 ]; then
	echo "Compile test can only be run in a local test!"
	exit 1
fi

INSTALLTARGET="$(pwd)/tmp-install"

check_result()
{
	local result=$1
	shift
	local info=$@

	if [ $result -eq 0 ]
	then
		echo_pass $info
	else
		echo_fail $result $info
		failures=$(($failures+1))
		exit $result
	fi
}

trap "rm -rf $INSTALLTARGET; exit" 0 1 2 3 15

mkdir -p $INSTALLTARGET
cd "$DIRNAME/.."
make distclean > /dev/null 2>&1
./configure	--enable-kcapi-test \
		--enable-kcapi-speed \
		--enable-kcapi-hasher \
		--enable-kcapi-rngapp \
		--enable-kcapi-encapp \
		--enable-kcapi-dgstapp \
		--enable-lib-asym \
		--enable-lib-kpp \
		--prefix=$INSTALLTARGET
check_result $? "configure"

make -j8; check_result $? "make -j8"
make install; check_result $? "make install"
make pdf; check_result $? "make pdf"
make man; check_result $? "make man"
make ps; check_result $? "make ps"
make html; check_result $? "make html"
make distclean; check_result $? "make distclean"

check_result $failures "Final result"
