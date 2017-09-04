#!/bin/bash

. libtest.sh

HASHERBIN="${APPDIR}/kcapi-hasher"
find_platform $HASHERBIN

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

for i in $SUMHASHER
do
	hash=$(basename $i)
	hash=${hash%%sum}
	hasher=$i
	[ ! -e "$hasher" ] && {
		echo_deact "Hasher $hasher does not exist"
		continue
	}

	$hasher $0 $ANOTHER > $CHKFILE
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

	$hasher --status -c $CHKFILE
	[ $? -ne 0 ] && echo_fail "Verification of checker file $CHKFILE with hasher $hasher failed"
	
	a=$($hasher -b 123 $0 | cut -f 1 -d" ")
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
	[ ! -x "/bin/$(basename $i)" ] && {
		echo_deact "hmaccalc reference application /bin/$i missing"
		continue
	}

	hash=$(basename $i)
	hash=${hash%%hmac}
	hasher=$i
	[ ! -e "$hasher" ] && {
		echo_fail "Hasher $hasher does not exist"
		continue
	}

	$hasher $0 $ANOTHER > $CHKFILE
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

	$hasher -q -c $CHKFILE
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
