#!/bin/bash

APP="../bin/kcapi-enc"
TSTPREFIX="kcapi-enc-testfiles."
KEYFILE_AES128="${TSTPREFIX}aes128key"
KEYFILE_AES256="${TSTPREFIX}aes256key"
OPENSSLKEY128=""
OPENSSLKEY256=""

ORIGPT="${TSTPREFIX}orig_pt"
GENPT="${TSTPREFIX}generated_pt"
GENCT="${TSTPREFIX}generated_ct"

IV="0123456789abcdef0123456789abcdef"
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
	local bytes=$(stat -c %s $ORIGPT)
	echo $(color "green")[PASSED - $bytes bytes]$(color off) $@
}

echo_fail()
{
	local bytes=$(stat -c %s $ORIGPT)
	echo $(color "red")[FAILED - $bytes bytes]$(color off) $@
	failures=$(($failures+1))
}

echo_deact()
{
	echo $(color "yellow")[DEACTIVATED]$(color off) $@
}

init_setup()
{
	trap "rm -f $TSTPREFIX*; exit" 0 1 2 3 15

	# CR is also character
	# Hex key string: 3031323334353637383961626364650a
	echo "0123456789abcde" > $KEYFILE_AES128
	OPENSSLKEY128="3031323334353637383961626364650a"
	# Hex key string: 303132333435363738396162636465663031323334353637383961626364650a
	echo "0123456789abcdef0123456789abcde" > $KEYFILE_AES256
	OPENSSLKEY256="303132333435363738396162636465663031323334353637383961626364650a"
}

gen_orig()
{
	local size=$1
	size=$((size-1))
	dd if=/dev/urandom of=$ORIGPT bs=$size count=1 2>/dev/null

	#ensure that the last byte is no pad-byte
	echo -n -e '\xff' >> $ORIGPT
}

diff_file()
{
	local orighash=$(sha256sum $1 | cut -d " " -f1)
	local genhash=$(sha256sum $2 | cut -d " " -f1)
	shift
	shift

	if [ x"$orighash" = x"$genhash" ]
	then
		echo_pass "$@"
	else
		echo_fail "$@: original file ($orighash) and generated file ($genhash)"
	fi

}

# Do not test CBC as padding is not removed
test_stdin_stdout()
{
	local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))

	exec 10<$keyfile; $APP --keyfd 10 -e -c "ctr(aes)" --iv $IV < $ORIGPT  > $GENCT
	exec 10<$keyfile; $APP --keyfd 10 -d -c "ctr(aes)" --iv $IV < $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "STDIN / STDOUT test ($keysize bits)"

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-ctr -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV
	openssl enc -d -aes-$keysize-ctr -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV

	diff_file $GENCT $GENCT.openssl "STDIN / STDOUT test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "STDIN / STDOUT test ($keysize bits) (openssl generated PT)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s $IV -e -c "ctr(aes)" --iv $IV < $ORIGPT > $GENCT
	$APP -q --pbkdfiter 1000 -p "passwd" -s $IV -d -c "ctr(aes)" --iv $IV < $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "STDIN / STDOUT test (password)"
}

# Do not test CBC as padding is not removed
test_stdin_fileout()
{
	local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))

	exec 10<$keyfile; $APP --keyfd 10 -e -c "ctr(aes)" --iv $IV -o $GENCT < $ORIGPT
	exec 10<$keyfile; $APP --keyfd 10 -d -c "ctr(aes)" --iv $IV -o $GENPT < $GENCT

	diff_file $ORIGPT $GENPT "STDIN / FILEOUT test ($keysize bits)"

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-ctr -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV
	openssl enc -d -aes-$keysize-ctr -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV

	diff_file $GENCT $GENCT.openssl "STDIN / FILEOUT test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "STDIN / FILEOUT test ($keysize bits) (openssl generated PT)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s $IV -e -c "ctr(aes)" --iv $IV -o $GENCT < $ORIGPT
	$APP -q --pbkdfiter 1000 -p "passwd" -s $IV -d -c "ctr(aes)" --iv $IV -o $GENPT < $GENCT

	diff_file $ORIGPT $GENPT "STDIN / FILEOUT test (password)"
}

# Do not test CBC as padding is not removed
test_filein_stdout()
{
	local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))

	exec 10<$keyfile; $APP --keyfd 10 -e -c "ctr(aes)" --iv $IV -i $ORIGPT > $GENCT
	exec 10<$keyfile; $APP --keyfd 10 -d -c "ctr(aes)" --iv $IV -i $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / STDOUT test ($keysize bits)"

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-ctr -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV
	openssl enc -d -aes-$keysize-ctr -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV

	diff_file $GENCT $GENCT.openssl "FILEIN / STDOUT test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "FILEIN / STDOUT test ($keysize bits) (openssl generated PT)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s $IV -e -c "ctr(aes)" --iv $IV -i $ORIGPT > $GENCT
	$APP -q --pbkdfiter 1000 -p "passwd" -s $IV -d -c "ctr(aes)" --iv $IV -i $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / STDOUT test (password)"
}

# Use cipher with padding requirement
test_filein_fileout()
{
	local keyfile=$1

	if [ ! -f "$keyfile" ]
	then
		echo "Keyfile $file does not exist"
		exit 1
	fi

	local keysize=$(stat -c %s $keyfile)
	keysize=$((keysize*8))


	exec 10<$keyfile; $APP --keyfd 10 -e -c "cbc(aes)" --iv $IV -i $ORIGPT -o $GENCT
	exec 10<$keyfile; $APP --keyfd 10 -d -c "cbc(aes)" --iv $IV -i $GENCT -o $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / FILEOUT test ($keysize bits)"

	# FIXME: error in openssl?
	local ptsize=$(stat -c %s $ORIGPT)
	local fullblock=$((ptsize%16))

	if [ $fullblock -eq 0 ]
	then
		return
	fi

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-cbc -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV
	openssl enc -d -aes-$keysize-cbc -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV

	diff_file $GENCT $GENCT.openssl "FILEIN / FILEOUT test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "FILEIN / FILEOUT test ($keysize bits) (openssl generated PT)"

	$APP -q --pbkdfiter 1000 -p "passwd" -s "123" -e -c "cbc(aes)" --iv $IV -i $ORIGPT -o $GENCT
	$APP -q --pbkdfiter 1000 -p "passwd" -s "123" -d -c "cbc(aes)" --iv $IV -i $GENCT -o $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / FILEOUT test (password)"
}

init_setup

for i in 1 15 16 29 32 257 512 1023 16385 65535 65536 65537 99999 100000 100001
do
	gen_orig $i
	test_stdin_stdout $KEYFILE_AES128
	test_stdin_stdout $KEYFILE_AES256
	test_stdin_fileout $KEYFILE_AES128
	test_stdin_fileout $KEYFILE_AES256
	test_filein_stdout $KEYFILE_AES128
	test_filein_stdout $KEYFILE_AES256
	test_filein_fileout $KEYFILE_AES128
	test_filein_fileout $KEYFILE_AES256
done

echo "==================================================================="
echo "Number of failures: $failures"
