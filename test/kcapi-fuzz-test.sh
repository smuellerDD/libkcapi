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

DIRNAME="$(dirname "$0")"
. "$DIRNAME/libtest.sh"

KCAPI="$KCAPI_TEST_BIN_DIR/kcapi"
find_platform $KCAPI

ROUNDS=100

SYMCIPHER="cbc(aes)"
AEADCIPHER="authenc(hmac(sha256),cbc(aes)) gcm(aes)"

checkret()
{
	local ret=$1
	shift

	if [ $ret -eq 0 ]
	then
		echo_pass "Fuzz test $@"
	else
		echo_fail "Fuzz test $@"
	fi
}

for i in $SYMCIPHER
do
	$KCAPI -h -x 1 -c "$i" -d $ROUNDS
	checkret $? "$i synchronous"
done

if $(check_min_kernelver 4 1); then
	for i in $AEADCIPHER
	do
		$KCAPI -h -x 2 -c "$i" -d $ROUNDS
		checkret $? "$i synchronous"
	done
else
	echo_deact "AEAD fuzz tests deactivated"
fi

echo "==================================================================="
echo "Number of failures: $failures"

exit $failures
