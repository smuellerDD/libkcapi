#!/bin/bash

DIR=".."
SUMHASHER="md5sum sha1sum sha256sum sha384sum sha512sum"
HMACHASHER="sha1hmac sha256hmac sha384hmac sha512hmac"
CHKFILE="chk.$$"
ANOTHER="test.$$"

HASHERBIN="../bin/.libs/kcapi-hasher"
LIBRARYDIR="../.libs"

failures=0

# color -- emit ansi color codes
color()
{
	bg=0
	echo -ne "\033[0m"
	while [[ $# -gt 0 ]]; do
		code=0
		case $1 in
			black) code=30 ;;
			red) code=31 ;;
			green) code=32 ;;
			yellow) code=33 ;;
			blue) code=34 ;;
			magenta) code=35 ;;
			cyan) code=36 ;;
			white) code=37 ;;
			background|bg) bg=10 ;;
			foreground|fg) bg=0 ;;
			reset|off|default) code=0 ;;
			bold|bright) code=1 ;;
		esac
		[[ $code == 0 ]] || echo -ne "\033[$(printf "%02d" $((code+bg)))m"
		shift
	done
}

echo_pass()
{
	echo $(color "green")[PASSED]$(color off) $@
}

echo_fail()
{
	echo $(color "red")[FAILED]$(color off) $@
	failures=$(($failures+1))
}

echo_deact()
{
	echo $(color "yellow")[DEACTIVATED]$(color off) $@
}

touch $ANOTHER
trap "rm -f $CHKFILE $ANOTHER $SUMHASHER $HMACHASHER" 0 1 2 3 15

if [ ! -e $HASHERBIN ]
then
	echo "Hasher binary missing"
	exit 1
fi

if [ ! -d $LIBRARYDIR ]
then
	echo "Library dir missing"
	exit 1
fi

export LD_LIBRARY_PATH=$LIBRARYDIR

for i in $SUMHASHER $HMACHASHER
do
	ln $HASHERBIN $i
done

for i in $SUMHASHER
do
	hash=${i%%sum}
	hasher=./$i
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
	[ ! -x "/bin/$i" ] && {
		echo_fail "hmaccalc reference application /bin/$i missing"
		continue
	}

	hash=${i%%hmac}
	hasher=./$i
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
