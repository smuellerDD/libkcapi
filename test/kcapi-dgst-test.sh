#!/bin/bash

. libtest.sh

APP="${APPDIR}/kcapi-dgst"
find_platform $APP
TSTPREFIX="${TMPDIR}/kcapi-dgst-testfiles."
KEYFILE_128="${TSTPREFIX}128key"
KEYFILE_256="${TSTPREFIX}256key"
OPENSSLKEY128=""
OPENSSLKEY256=""

ORIGPT="${TSTPREFIX}orig_pt"
GENDGST="${TSTPREFIX}generated_dgst"

SALT="0123456789abcdef0123456789abcdef"

echo_pass_local()
{
	local bytes=$(stat -c %s $ORIGPT)
	echo_pass "$bytes bytes: $@"
}

echo_fail_local()
{
	local bytes=$(stat -c %s $ORIGPT)
	echo_fail "$bytes bytes: $@"
}

init_setup()
{
	trap "rm -f $TSTPREFIX*; exit" 0 1 2 3 15

	# CR is also character
	# Hex key string: 3031323334353637383961626364650a
	echo -n "0123456789abcdef" > $KEYFILE_128
	OPENSSLKEY128="0123456789abcdef"
	# Hex key string: 303132333435363738396162636465663031323334353637383961626364650a
	echo -n "0123456789abcdef0123456789abcdef" > $KEYFILE_256
	OPENSSLKEY256="0123456789abcdef0123456789abcdef"
}

gen_orig()
{
	local size=$1
	dd if=/dev/urandom of=$ORIGPT bs=$size count=1 2>/dev/null
}

diff_file()
{
	local orighash=$(sha256sum $1 | cut -d " " -f1)
	local genhash=$(sha256sum $2 | cut -d " " -f1)
	shift
	shift

	if [ x"$orighash" = x"$genhash" ]
	then
		echo_pass_local "$@"
	else
		echo_fail_local "$@: original file ($orighash) and generated file ($genhash)"
	fi

}

test_stdin_stdout()
{
	local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	$APP -c "sha256" --hex < $ORIGPT > $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "STDIN / STDOUT test (hash)"

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))
	eval opensslkey=\$OPENSSLKEY${keysize}

	exec 10<$keyfile; $APP --keyfd 10 -c "hmac(sha256)" --hex < $ORIGPT  > $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 -hmac $opensslkey $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "STDIN / STDOUT test (keyed MD $keysize bits)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)" < $ORIGPT > $GENDGST
	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)" < $ORIGPT > $GENDGST.2

	diff_file $GENDGST $GENDGST.2 "STDIN / STDOUT test (password)"
}

test_stdin_fileout()
{
	local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	$APP -c "sha256" --hex -o $GENDGST < $ORIGPT
	echo >> $GENDGST
	openssl dgst -sha256 $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "STDIN / FILEOUT test (hash)"

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))
	eval opensslkey=\$OPENSSLKEY${keysize}

	exec 10<$keyfile; $APP --keyfd 10 -c "hmac(sha256)" --hex -o $GENDGST < $ORIGPT
	echo >> $GENDGST
	openssl dgst -sha256 -hmac $opensslkey $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "STDIN / FILEOUT test (keyed MD $keysize bits)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)" -o $GENDGST < $ORIGPT
	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)" -o $GENDGST.2 < $ORIGPT

	diff_file $GENDGST $GENDGST.2 "STDIN / FILEOUT test (password)"
}

test_filein_stdout()
{
	local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	$APP -c "sha256" --hex -i $ORIGPT > $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "FILEIN / STDOUT test (hash)"

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))
	eval opensslkey=\$OPENSSLKEY${keysize}

	exec 10<$keyfile; $APP --keyfd 10 -c "hmac(sha256)" --hex -i $ORIGPT > $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 -hmac $opensslkey $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "FILEIN / STDOUT test (keyed MD $keysize bits)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)" -i $ORIGPT > $GENDGST
	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)"  -i $ORIGPT > $GENDGST.2

	diff_file $GENDGST $GENDGST.2 "FILEIN / STDOUT test (password)"
}

test_filein_fileout()
{
	local keyfile=$1

		local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	$APP -c "sha256" --hex -i $ORIGPT -o $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "FILEIN / FILEOUT test (hash)"

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))
	eval opensslkey=\$OPENSSLKEY${keysize}

	exec 10<$keyfile; $APP --keyfd 10 -c "hmac(sha256)" --hex -i $ORIGPT -o $GENDGST
	echo >> $GENDGST
	openssl dgst -sha256 -hmac $opensslkey $ORIGPT  | awk 'BEGIN {FS="= "} {print $2}' > $GENDGST.openssl
	diff_file $GENDGST $GENDGST.openssl "FILEIN / FILEOUT test (keyed MD $keysize bits)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)" -i $ORIGPT -o $GENDGST
	$APP -q --pbkdfiter 1000 -p "passwd" -s $SALT -c "hmac(sha256)"  -i $ORIGPT -o $GENDGST.2

	diff_file $GENDGST $GENDGST.2 "FILEIN / FILEOUT test (password)"
}

init_setup

for i in 1 15 16 29 32 257 512 1023 16385 65535 65536 65537 99999 100000 100001
do
	gen_orig $i
	test_stdin_stdout $KEYFILE_128
	test_stdin_stdout $KEYFILE_256
	test_stdin_fileout $KEYFILE_128
	test_stdin_fileout $KEYFILE_256
	test_filein_stdout $KEYFILE_128
	test_filein_stdout $KEYFILE_256
	test_filein_fileout $KEYFILE_128
	test_filein_fileout $KEYFILE_256
done

echo "==================================================================="
echo "Number of failures: $failures"
