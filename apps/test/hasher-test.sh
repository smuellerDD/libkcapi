#!/bin/bash

DIR=".."
SUMHASHER="md5sum sha1sum sha256sum sha384sum sha512sum"
HMACHASHER="sha1hmac sha256hmac sha384hmac sha512hmac"
CHKFILE="chk.$$"
ANOTHER="test.$$"

touch $ANOTHER
trap "rm -f $CHKFILE $ANOTHER" 0 1 2 3 15

for i in $SUMHASHER
do
	hash=${i%%sum}
	hasher=$DIR/$i
	[ ! -e "$hasher" ] && {
		echo "Hasher $hasher does not exist"
		continue
	}

	$hasher $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo "Generation of hashes with hasher $hasher failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo "Generation of checker file $CHKFILE with hasher $hasher failed"
		continue
	}

	$i --status -c $CHKFILE
	[ $? -ne 0 ] && echo "Verification of checker file $CHKFILE with reference hasher $i failed"
	$i $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo "Generation of hashes with reference hasher $i failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo "Generation of checker file $CHKFILE with referemce hasher $i failed"
		continue
	}

	$hasher --status -c $CHKFILE
	[ $? -ne 0 ] && echo "Verification of checker file $CHKFILE with hasher $hasher failed"
	
	a=$($hasher -b 123 $0 | cut -f 1 -d" ")
	b=$(openssl dgst -$hash -hmac 123 $0 | cut -f 2 -d" ")
	[ x"$a" != x"$b" ] && {
		echo "HMAC calculation for $hasher failed"
		continue
	}
	rm -f $CHKFILE
done

for i in $HMACHASHER
do
	[ ! -x "/bin/$i" ] && {
		echo "hmaccalc reference application /bin/$i missing"
		continue
	}

	hash=${i%%hmac}
	hasher=$DIR/$i
	[ ! -e "$hasher" ] && {
		echo "Hasher $hasher does not exist"
		continue
	}

	$hasher $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo "Generation of hashes with hasher $hasher failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo "Generation of checker file $CHKFILE with hasher $hasher failed"
		continue
	}

	$i -q -c $CHKFILE
	[ $? -ne 0 ] && echo "Verification of checker file $CHKFILE with reference hasher $i failed"
	$i $0 $ANOTHER > $CHKFILE
	[ $? -ne 0 ] && {
		echo "Generation of hashes with reference hasher $i failed"
		continue
	}
	[ ! -f "$CHKFILE" ] && {
		echo "Generation of checker file $CHKFILE with referemce hasher $i failed"
		continue
	}

	$hasher -q -c $CHKFILE
	[ $? -ne 0 ] && echo "Verification of checker file $CHKFILE with hasher $hasher failed"

	rm -f $CHKFILE
done
	
