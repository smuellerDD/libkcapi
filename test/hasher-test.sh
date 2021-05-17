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

SUMHASHER="md5sum sha1sum sha256sum sha384sum sha512sum"
HMACHASHER="sha1hmac sha256hmac sha384hmac sha512hmac"
CHKFILE="${TMPDIR}/chk.$$"
ANOTHER="${TMPDIR}/test.$$"

if [ "$KCAPI_TEST_LOCAL" -eq 1 ]; then
	find_platform kcapi-hasher
	function run_hasher() {
		run_app kcapi-hasher -n "$@"
	}
else
	find_platform sha1hmac
	function run_hasher() {
		"$@"
	}

	for hasher in $SUMHASHER $HMACHASHER
	do
		binary="$(find_app_binary $hasher)"
		if [ ! -x "$(command -v "$binary")" ]
		then
			echo_deact "Hasher binary $hasher missing, tests deactivated"
			exit 0
		fi
	done
fi

touch $ANOTHER
trap "rm -f $ANOTHER $CHKFILE" 0 1 2 3 15

for hasher in $SUMHASHER $HMACHASHER
do
	>$CHKFILE
	run_hasher $hasher -c $CHKFILE
	if [ $? -eq 0 ]
	then
		echo_fail "Verification of empty checker file with hasher $hasher did not fail"
	else
		echo_pass "Failure on empty checker file for $hasher"
	fi

	echo >$CHKFILE
	run_hasher $hasher -c $CHKFILE
	if [ $? -eq 0 ]
	then
		echo_fail "Verification of empty line checker file with hasher $hasher did not fail"
	else
		echo_pass "Failure on empty line checker file for $hasher"
	fi

	run_hasher $hasher $0 $ANOTHER | sed -E 's/(\w+\s)\s/\1*/' >$CHKFILE
	run_hasher $hasher --status -c $CHKFILE
	if [ $? -eq 0 ]
	then
		echo_pass "Parsing checker file with asterisk with $hasher"
	else
		echo_fail "Parsing checker file with asterisk (binary mode) with $hasher failed"
	fi

	run_hasher $hasher $0 $ANOTHER | run_hasher $hasher --status -c -
	if [ $? -eq 0 ]
	then
		echo_pass "Checker file '-' interpretation with $hasher"
	else
		echo_fail "Checker file '-' interpretation with $hasher failed"
	fi

	run_hasher $hasher $0 - <$ANOTHER >/dev/null
	if [ $? -eq 0 ]
	then
		echo_pass "Input file '-' interpretation with $hasher"
	else
		echo_fail "Input file '-' interpretation with $hasher failed"
	fi

	rm -f $CHKFILE
done

for i in $SUMHASHER
do
	hasher=$i
	hash=${hasher%%sum}
	i=$(command -v $i)

	[ -z "$i" ] && {
		echo_deact "reference application $hasher missing"
		continue
	}

	run_hasher $hasher $0 $ANOTHER > $CHKFILE
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
		echo_fail "Generation of checker file $CHKFILE with reference hasher $i failed"
		continue
	}

	run_hasher $hasher --status -c $CHKFILE
	[ $? -ne 0 ] && echo_fail "Verification of checker file $CHKFILE with hasher $hasher failed"

	if [ "$KCAPI_TEST_LOCAL" -eq 1 ]; then
		echo -n 123 >$CHKFILE

		a=$(openssl dgst -$hash -hmac 123 $0 | cut -f 2 -d" ")
		b=$(run_hasher $hasher -K 123 $0 | cut -f 1 -d" ")
		c=$(run_hasher $hasher -k $CHKFILE $0 | cut -f 1 -d" ")
		[ x"$a" != x"$b" ] && {
			echo_fail "HMAC calculation for $hasher failed (cmdline key)"
			continue
		}
		[ x"$a" != x"$b" ] && {
			echo_fail "HMAC calculation for $hasher failed (key in regular file)"
			continue
		}
		echo_pass "HMAC calculation for $hasher"
	fi
	rm -f $CHKFILE
done

[ "$KCAPI_TEST_LOCAL" -eq 1 ] && for i in $HMACHASHER
do
	hasher=$i
	hash=${hasher%%hmac}
	i=$(command -v $i)

	[ -z "$i" ] && {
		echo_deact "hmaccalc reference application $hasher missing"
		continue
	}

	run_hasher $hasher $0 $ANOTHER > $CHKFILE
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
		echo_fail "Generation of checker file $CHKFILE with reference hasher $i failed"
		continue
	}

	run_hasher $hasher -q -c $CHKFILE
	if [ $? -ne 0 ]
	then
		echo_fail "Verification of checker file $CHKFILE with hasher $hasher failed"
	else
		echo_pass "Verification of hasher $hasher"
	fi

	rm -f $CHKFILE
done

#
# Test unkeyed HMAC mode:
#
for i in $HMACHASHER
do
	ref=${i%%hmac}sum
	hasher=$i

	run_hasher $ref $0 $ANOTHER > $CHKFILE
	run_hasher $hasher -u -q -c $CHKFILE
	if [ $? -ne 0 ]
	then
		echo_fail "Unkeyed verification with hasher $hasher failed"
	else
		echo_pass "Unkeyed verification with hasher $hasher"
	fi

	run_hasher $hasher -u $0 $ANOTHER > $CHKFILE
	run_hasher $ref --status -c $CHKFILE
	if [ $? -ne 0 ]
	then
		echo_fail "Unkeyed generation of checker file with hasher $hasher failed"
	else
		echo_pass "Unkeyed generation of checker file with hasher $hasher"
	fi

	rm -f $CHKFILE
done

#
# Test hmaccalc's ignored compatibility options:
#
for hasher in $HMACHASHER
do
	compat="-d -P -b"
	run_hasher $hasher $compat $0 $ANOTHER > /dev/null
	if [ $? -ne 0 ]
	then
		echo_fail "Hasher $hasher does not accept compatiblity options: $compat"
	else
		echo_pass "Compatibility options for hasher $hasher"
	fi
done

#
# Test hmaccalc's -S option:
#
for hasher in $HMACHASHER
do
	run_hasher $hasher -S >$CHKFILE
	if [ $? -ne 0 ]
	then
		echo_fail "Hasher $hasher does not accept the -S option"
	elif ! [ -s $CHKFILE ]
	then
		echo_fail "Hasher $hasher does not output hash with the -S option"
	else
		echo_pass "Self-checksum option for hasher $hasher"
	fi

	rm -f $CHKFILE
done

#
# Test hmaccalc's -h option:
#
for hasher in $HMACHASHER
do
	run_hasher $hasher -h sha1 $0 $ANOTHER >$CHKFILE
	if [ $? -ne 0 ]
	then
		echo_fail "Hasher $hasher does not accept the -h option"
		rm -f $CHKFILE
		continue
	fi

	run_hasher sha1hmac $0 $ANOTHER | diff $CHKFILE -
	if  [ $? -ne 0 ]
	then
		echo_fail "Hasher $hasher does not work correctly with the -h option"
	else
		echo_pass "Different hash option for hasher $hasher"
	fi

	rm -f $CHKFILE
done

#
# Test FIPS self-check:
#
[ "$KCAPI_TEST_LOCAL" -ne 1 ] && for hasher in $SUMHASHER $HMACHASHER
do
	KCAPI_HASHER_FORCE_FIPS=1 run_hasher $hasher $0 >/dev/null
	if  [ $? -ne 0 ]
	then
		echo_fail "FIPS self-check of hasher $hasher failed"
	else
		echo_pass "FIPS self-check of hasher $hasher"
	fi
done

#
# hmaccalc known-answer tests from RFC 2202 and 4231
#

function expand_string() {
	if [[ "$1" == 0x* ]]
	then
		printf "$(echo -n "${1#0x}" | sed 's/\(..\)/\\x\1/g')"
	else
		echo -n "$1"
	fi
}

function run_kat() {
	hasher="$1"; shift
	id="$1"; shift
	key="$1"; shift
	data="$1"; shift
	result="$1"; shift
	truncate="$1"; shift

	# The following tests do not work on eudyptula
	# See below for the offending invocation
	if uname -n | grep -q eudyptula
	then
		echo_deact "Hasher test deactivated"
		return
	fi

	truncate_opt=''
	[ -z "$truncate" ] || truncate_opt="-t $truncate"

	expand_string "$data" >"$ANOTHER"
	echo "${result#0x}  $ANOTHER" >"$CHKFILE"

	# The -k requires a file descriptor which cannot be created in the
	# eudyptula Hypervsior test environment
	run_hasher $hasher -q \
		-k <(expand_string "$key") -c "$CHKFILE" $truncate_opt
	if [ $? -ne 0 ]
	then
		echo_fail "Verification of hasher $hasher -c ... with KAT '$id' failed"
	else
		echo_pass "Verification of hasher $hasher -c ... with KAT '$id'"
	fi

	run_hasher $hasher -q \
		-k <(expand_string "$key") "$ANOTHER" $truncate_opt \
		| diff - "$CHKFILE"
	if [ $? -ne 0 ]
	then
		echo_fail "Verification of hasher $hasher output with KAT '$id' failed"
	else
		echo_pass "Verification of hasher $hasher output with KAT '$id'"
	fi
}

if [ "$KCAPI_TEST_LOCAL" -eq 1 ]; then
	KAT_SUFFIXES="sum hmac"
else
	KAT_SUFFIXES="hmac"
fi

for suffix in $KAT_SUFFIXES
do
	run_kat sha1$suffix   "RFC 2202, section 3, #1"   0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b "Hi There" 0xb617318655057264e28bc0b6fb378c8ef146be00
	run_kat sha1$suffix   "RFC 2202, section 3, #2"   "Jefe" "what do ya want for nothing?" 0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79
	run_kat sha1$suffix   "RFC 2202, section 3, #3"   0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 0x125d7342b9ac11cd91a39af48aa17b4f63f175d3
	run_kat sha1$suffix   "RFC 2202, section 3, #4"   0x0102030405060708090a0b0c0d0e0f10111213141516171819 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 0x4c9007f4026250c6bc8414f9bf50c86c2d7235da
	run_kat sha1$suffix   "RFC 2202, section 3, #5"   0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c "Test With Truncation" 0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04
	run_kat sha1$suffix   "RFC 2202, section 3, #6"   0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "Test Using Larger Than Block-Size Key - Hash Key First" 0xaa4ae5e15272d00e95705637ce8a3b55ed402112
	run_kat sha1$suffix   "RFC 2202, section 3, #7"   0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" 0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91
	run_kat sha256$suffix "RFC 4231, section 4.2, #1" 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b "Hi There" 0xb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
	run_kat sha384$suffix "RFC 4231, section 4.2, #2" 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b "Hi There" 0xafd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6
	run_kat sha512$suffix "RFC 4231, section 4.2, #3" 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b "Hi There" 0x87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
	run_kat sha256$suffix "RFC 4231, section 4.3, #1" "Jefe" "what do ya want for nothing?" 0x5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
	run_kat sha384$suffix "RFC 4231, section 4.3, #2" "Jefe" "what do ya want for nothing?" 0xaf45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649
	run_kat sha512$suffix "RFC 4231, section 4.3, #3" "Jefe" "what do ya want for nothing?" 0x164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737
	run_kat sha256$suffix "RFC 4231, section 4.4, #1" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 0x773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
	run_kat sha384$suffix "RFC 4231, section 4.4, #2" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 0x88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27
	run_kat sha512$suffix "RFC 4231, section 4.4, #3" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 0xfa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb
	run_kat sha256$suffix "RFC 4231, section 4.5, #1" 0x0102030405060708090a0b0c0d0e0f10111213141516171819 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 0x82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b
	run_kat sha384$suffix "RFC 4231, section 4.5, #2" 0x0102030405060708090a0b0c0d0e0f10111213141516171819 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 0x3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb
	run_kat sha512$suffix "RFC 4231, section 4.5, #3" 0x0102030405060708090a0b0c0d0e0f10111213141516171819 0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 0xb0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd
	run_kat sha256$suffix "RFC 4231, section 4.6, #1" 0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c 0x546573742057697468205472756e636174696f6e 0xa3b6167473100ee06e0c796c2955552b 128
	run_kat sha384$suffix "RFC 4231, section 4.6, #2" 0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c 0x546573742057697468205472756e636174696f6e 0x3abf34c3503b2a23a46efc619baef897 128
	run_kat sha512$suffix "RFC 4231, section 4.6, #3" 0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c 0x546573742057697468205472756e636174696f6e 0x415fad6271580a531d4179bc891d87a6 128
	run_kat sha256$suffix "RFC 4231, section 4.7, #1" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0x54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374 0x60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
	run_kat sha384$suffix "RFC 4231, section 4.7, #2" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0x54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374 0x4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952
	run_kat sha512$suffix "RFC 4231, section 4.7, #3" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0x54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374 0x80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598
	run_kat sha256$suffix "RFC 4231, section 4.8, #1" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0x5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e 0x9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2
	run_kat sha384$suffix "RFC 4231, section 4.8, #2" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0x5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e 0x6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e
	run_kat sha512$suffix "RFC 4231, section 4.8, #3" 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0x5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e 0xe37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58
done

echo "==================================================================="
echo "Number of failures: $failures"

exit $failures
