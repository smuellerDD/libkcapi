#!/bin/bash

DIR=".."
HASHER="md5sum sha1sum sha256sum sha384sum sha512sum"
CHKFILE="chk.$$"
ANOTHER="test.$$"

touch $ANOTHER
trap "rm -f $CHKFILE $ANOTHER" 0 1 2 3 15

for i in $HASHER
do
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

	rm -f $CHKFILE
done
	
