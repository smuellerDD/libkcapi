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

find_platform kcapi-enc
TSTPREFIX="${TMPDIR}/kcapi-enc-testfiles."
KEYFILE_AES128="${TSTPREFIX}aes128key"
KEYFILE_AES256="${TSTPREFIX}aes256key"
OPENSSLKEY128=""
OPENSSLKEY256=""

ORIGPT="${TSTPREFIX}orig_pt"
GENPT="${TSTPREFIX}generated_pt"
GENCT="${TSTPREFIX}generated_ct"

IV="0123456789abcdef0123456789abcdef"

#CCM Decrypt
CCM_MSG="4edb58e8d5eb6bc711c43a6f3693daebde2e5524f1b55297abb29f003236e43d"
CCM_KEY="2861fd0253705d7875c95ba8a53171b4"
CCM_AAD="fb7bc304a3909e66e2e0c5ef952712dd884ce3e7324171369f2c5db1adc48c7d"
CCM_TAG="a7877c99"
CCM_TAG_FAIL="a7877c98"
CCM_NONCE="674742abd0f5ba"
CCM_EXP="8dd351509dcf1df9c33987fb31cd708dd60d65d3d4e1baa53581d891d994d723"

#GCM Encrypt
GCM_MSG="507937f393b2de0fa218d0a9713262f4"
GCM_KEY="5aa3d01e7242d7a64f5fd4ad25505390"
GCM_IV="94af90b40cc541173d201250"
GCM_AAD="0f7479e28c53d120fcf57a525e0b36a0"
GCM_TAGLEN="14"
GCM_EXP="e80e074e70b089c160c6d3863e8d2b75ac767d2d44412252eed41a220f31"

failures=0

hex2bin()
{
	local hex=$1
	local dstfile=$2

	echo -n $hex | perl -pe 's/([0-9a-f]{2})/chr hex $1/gie' > $dstfile
}

bin2hex_noaad()
{
	local origfile=$1
	local aadlenskip=$2

	local hex=$(hexdump -ve '/1 "%02x"' -s$aadlenskip $origfile)

	echo $hex
}

echo_pass_local()
{
	if [ -f $ORIGPT ]
	then
		local bytes=$(stat -c %s $ORIGPT)
		echo_pass "$bytes bytes: $@"
	else
		echo_pass $@
	fi
}

echo_fail_local()
{
	if [ -f $ORIGPT ]
	then
		local bytes=$(stat -c %s $ORIGPT)
		echo_fail "$bytes bytes: $@"
	else
		echo_fail $@
	fi
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

	hex2bin $CCM_MSG ${TSTPREFIX}ccm_msg
	hex2bin $CCM_KEY ${TSTPREFIX}ccm_key
	hex2bin $GCM_MSG ${TSTPREFIX}gcm_msg
	hex2bin $GCM_KEY ${TSTPREFIX}gcm_key
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
		echo_pass_local "$@"
	else
		echo_fail_local "$@: original file ($orighash) and generated file ($genhash)"
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

	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -e -c "ctr(aes)" --iv $IV < $ORIGPT  > $GENCT
	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -d -c "ctr(aes)" --iv $IV < $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "STDIN / STDOUT enc test ($keysize bits)"

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-ctr -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV
	openssl enc -d -aes-$keysize-ctr -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV

	diff_file $GENCT $GENCT.openssl "STDIN / STDOUT enc test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "STDIN / STDOUT enc test ($keysize bits) (openssl generated PT)"

	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s $IV -e -c "ctr(aes)" --iv $IV < $ORIGPT > $GENCT
	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s $IV -d -c "ctr(aes)" --iv $IV < $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "STDIN / STDOUT enc test (password)"
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

	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -e -c "ctr(aes)" --iv $IV -o $GENCT < $ORIGPT
	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -d -c "ctr(aes)" --iv $IV -o $GENPT < $GENCT

	diff_file $ORIGPT $GENPT "STDIN / FILEOUT test ($keysize bits)"

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-ctr -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV
	openssl enc -d -aes-$keysize-ctr -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV

	diff_file $GENCT $GENCT.openssl "STDIN / FILEOUT enc test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "STDIN / FILEOUT enc test ($keysize bits) (openssl generated PT)"

	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s $IV -e -c "ctr(aes)" --iv $IV -o $GENCT < $ORIGPT
	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s $IV -d -c "ctr(aes)" --iv $IV -o $GENPT < $GENCT

	diff_file $ORIGPT $GENPT "STDIN / FILEOUT enc test (password)"
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

	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -e -c "ctr(aes)" --iv $IV -i $ORIGPT > $GENCT
	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -d -c "ctr(aes)" --iv $IV -i $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / STDOUT enc test ($keysize bits)"

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-ctr -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV
	openssl enc -d -aes-$keysize-ctr -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV

	diff_file $GENCT $GENCT.openssl "FILEIN / STDOUT enc test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "FILEIN / STDOUT enc test ($keysize bits) (openssl generated PT)"

	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s $IV -e -c "ctr(aes)" --iv $IV -i $ORIGPT > $GENCT
	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s $IV -d -c "ctr(aes)" --iv $IV -i $GENCT > $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / STDOUT enc test (password)"
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


	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -e -c "cbc(aes)" --iv $IV -i $ORIGPT -o $GENCT
	exec 10<$keyfile; run_app kcapi-enc --keyfd 10 -d -c "cbc(aes)" --iv $IV -i $GENCT -o $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / FILEOUT enc test ($keysize bits)"

	local ptsize=$(stat -c %s $ORIGPT)
	local fullblock=$((ptsize%16))
	local extra_openssl_opts=""

	if [ $fullblock -eq 0 ]
	then
		# OpenSSL uses PKCS#7 padding which adds an extra pad block in this case
		# Disable PKCS#7 padding when input length is a multiple of block size
		extra_openssl_opts="$extra_openssl_opts -nopad"
	fi

	eval opensslkey=\$OPENSSLKEY${keysize}
	openssl enc -aes-$keysize-cbc -in $ORIGPT -out $GENCT.openssl -K $opensslkey -iv $IV $extra_openssl_opts
	openssl enc -d -aes-$keysize-cbc -in $GENCT -out $GENPT.openssl -K $opensslkey -iv $IV $extra_openssl_opts

	diff_file $GENCT $GENCT.openssl "FILEIN / FILEOUT enc test ($keysize bits) (openssl generated CT)"
	diff_file $GENPT $GENPT.openssl "FILEIN / FILEOUT enc test ($keysize bits) (openssl generated PT)"

	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s "123" -e -c "cbc(aes)" --iv $IV -i $ORIGPT -o $GENCT
	run_app kcapi-enc -q --pbkdfiter 1000 -p "passwd" -s "123" -d -c "cbc(aes)" --iv $IV -i $GENCT -o $GENPT

	diff_file $ORIGPT $GENPT "FILEIN / FILEOUT enc test (password)"
}

test_ccm_dec()
{
	local aadlen=${#CCM_AAD}

	aadlen=$(($aadlen/2))

	exec 10<${TSTPREFIX}ccm_key; run_app kcapi-enc --keyfd 10 -d -c "ccm(aes)" -i ${TSTPREFIX}ccm_msg -o ${TSTPREFIX}ccm_out --ccm-nonce $CCM_NONCE --aad $CCM_AAD --tag $CCM_TAG
	local hexret=$(bin2hex_noaad ${TSTPREFIX}ccm_out $aadlen)

	if [ x"$hexret" != x"$CCM_EXP" ]
	then
		echo_fail_local "CCM output does not match expected output (received: $hexret -- expected $CCM_EXP)"
	else
		echo_pass_local "FILEIN / FILEOUT CCM decrypt"
	fi

	exec 10<${TSTPREFIX}ccm_key; run_app kcapi-enc --keyfd 10 -d -c "ccm(aes)" -i ${TSTPREFIX}ccm_msg -o ${TSTPREFIX}ccm_out --ccm-nonce $CCM_NONCE --aad $CCM_AAD --tag $CCM_TAG_FAIL -q

	# 182 == -EBADMSG
	if [ $? -eq 182 ]
	then
		echo_pass_local "FILEIN / FILEOUT CCM decrypt integrity violation"
	else
		echo_fail_local "CCM integrity violation not caught"
	fi
}

test_gcm_enc()
{
	local aadlen=${#GCM_AAD}

	aadlen=$(($aadlen/2))

	exec 10<${TSTPREFIX}gcm_key; run_app kcapi-enc --keyfd 10 -e -c "gcm(aes)" -i ${TSTPREFIX}gcm_msg -o ${TSTPREFIX}gcm_out --iv $GCM_IV --aad $GCM_AAD --taglen $GCM_TAGLEN
	local hexret=$(bin2hex_noaad ${TSTPREFIX}gcm_out $aadlen)

	if [ x"$hexret" != x"$GCM_EXP" ]
	then
		echo_fail_local "GCM output does not match expected output (received: $hexret -- expected $GCM_EXP)"
	else
		echo_pass_local "FILEIN / FILEOUT GCM encrypt"
	fi
}

init_setup
test_gcm_enc
test_ccm_dec

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

exit $failures
