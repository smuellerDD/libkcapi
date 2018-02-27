#!/bin/bash
#
# Copyright (C) 2017 - 2018, Stephan Mueller <smueller@chronox.de>
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

. libtest.sh

HASHERBIN="${APPDIR}/kcapi-hasher"
find_platform $HASHERBIN
HASHERBIN=$(get_binlocation $HASHERBIN)

SUMHASHER="${TMPDIR}/md5sum ${TMPDIR}/sha1sum ${TMPDIR}/sha256sum ${TMPDIR}/sha384sum ${TMPDIR}/sha512sum"
HMACHASHER="${TMPDIR}/sha1hmac ${TMPDIR}/sha256hmac ${TMPDIR}/sha384hmac ${TMPDIR}/sha512hmac"
CHKFILE="${TMPDIR}/chk.$$"
ANOTHER="${TMPDIR}/test.$$"

touch $ANOTHER
trap "rm -f $ANOTHER $CHKFILE $SUMHASHER $HMACHASHER" 0 1 2 3 15

if [ ! -e $HASHERBIN ]
then
	echo "Hasher binary missing"
	exit 1
fi

#although a hard link suffices, we need to copy it
for i in $SUMHASHER $HMACHASHER
do
	#ln $HASHERBIN $i
	cp -f $HASHERBIN $i
done

libdir=$(dirname $(realpath ../.libs/libkcapi.so))
libname=$(realpath ../.libs/libkcapi.so)

for i in $SUMHASHER
do
	hash=$(basename $i)
	hash=${hash%%sum}
	hasher=$i
	i=$(basename $i)
	[ ! -e "$hasher" ] && {
		echo_deact "Hasher $hasher does not exist"
		continue
	}

	LD_LIBRARY_PATH=$libdir LD_PRELOAD=$libname $hasher $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo_fail "Generation of hashes with hasher $hasher failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo_fail "Generation of checker file $CHKFILE with hasher $hasher failed"
		continue
	}

	$i --status -c $CHKFILE
	[ $? -ne 0 ] && echo_fail "Verification of checker file $CHKFILE with reference hasher $i failed"
	$i $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo_fail "Generation of hashes with reference hasher $i failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo_fail "Generation of checker file $CHKFILE with referemce hasher $i failed"
		continue
	}

	LD_LIBRARY_PATH=$libdir LD_PRELOAD=$libname $hasher --status -c $CHKFILE
	[ $? -ne 0 ] && echo_fail "Verification of checker file $CHKFILE with hasher $hasher failed"
	
	a=$(LD_LIBRARY_PATH=$libdir LD_PRELOAD=$libname $hasher -b 123 $0 | cut -f 1 -d" ")
	b=$(openssl dgst -$hash -hmac 123 $0 | cut -f 2 -d" ")
	[ x"$a" != x"$b" ] && {
		echo_fail "HMAC calculation for $hasher failed"
		continue
	}
	echo_pass "HMAC calculation for $hasher"
	rm -f $CHKFILE
done

for i in $HMACHASHER
do
	hash=$(basename $i)
	hash=${hash%%hmac}
	hasher=$i
	t=$(basename $i)
	i=$(command -v $t)

	[ -z "$i" ] && {
		echo_deact "hmaccalc reference application $t missing"
		continue
	}

	[ ! -e "$hasher" ] && {
		echo_fail "Hasher $hasher does not exist"
		continue
	}

	LD_LIBRARY_PATH=$libdir LD_PRELOAD=$libname $hasher $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo_fail "Generation of hashes with hasher $hasher failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo_fail "Generation of checker file $CHKFILE with hasher $hasher failed"
		continue
	}

	$i -q -c $CHKFILE
	[ $? -ne 0 ] && echo_fail "Verification of checker file $CHKFILE with reference hasher $i failed"
	$i $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo_fail "Generation of hashes with reference hasher $i failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo_fail "Generation of checker file $CHKFILE with referemce hasher $i failed"
		continue
	}

	LD_LIBRARY_PATH=$libdir LD_PRELOAD=$libname $hasher -q -c $CHKFILE
	if [ $? -ne 0 ]
	then
		echo_fail "Verification of checker file $CHKFILE with hasher $hasher failed"
	else
		echo_pass "Verification of hasher $hasher"
	fi

	rm -f $CHKFILE
done

echo "==================================================================="
echo "Number of failures: $failures"

exit $failures
