#!/bin/bash

MAX=8388608
OUTFILE=testfile

i=1
error=""

trap "rm -f $OUTFILE; exit" 0 1 2 3 15

while [ $i -le $MAX ]
do
	echo "Processing size $i"
	rm -f $OUTFILE
	dd if=/dev/urandom of=$OUTFILE bs=1 count=$i > /dev/null 2>&1
	out1=$(./kcapi $OUTFILE)
	out2=$(openssl sha1 $OUTFILE |  awk '{print $2}')

	if [ "$out1" != "$out2" ]; then
		echo "Mismatch with size $i"
		error="$error $i"
	fi
	let i=(i+1)
done

if [ -n "$error" ]
then
	echo "Mismatches seen at counts $error"
else
	echo "Test passed without mismatches"
fi
