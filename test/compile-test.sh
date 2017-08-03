#!/bin/bash
#
# Written by: Stephan Müller <smueller@chronox.de>
#
# This test tries to compile all code and tries to install it
#
LOCALDIR=$(pwd)
INSTALLTARGET=$LOCALDIR/tmp-install

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
	echo "------------------------------------------------------------------"
	echo $(color "green")[PASSED]$(color off) $@
	echo "=================================================================="
}

echo_fail()
{
	echo "------------------------------------------------------------------"
	echo $(color "red")[FAILED: $1]$(color off) $@
	echo "=================================================================="
}

echo_deact()
{
	echo "------------------------------------------------------------------"
	echo $(color "yellow")[DEACTIVATED: $1]$(color off) $@
	echo "=================================================================="
}

check_result()
{
	local result=$1
	shift
	local info=$@

	if [ $result -eq 0 ]
	then
		echo_pass $info
	else
		echo_fail $result $info
		failures=$(($failures+1))
		exit $result
	fi
}

trap "rm -rf $INSTALLTARGET; exit" 0 1 2 3 15

mkdir -p $INSTALLTARGET
cd ..
./configure	--enable-kcapi-test \
		--enable-kcapi-speed \
		--enable-kcapi-hasher \
		--enable-kcapi-rngapp \
		--prefix=$INSTALLTARGET
check_result $? "configure"

make -j8; check_result $? "make -j8"
make install; check_result $? "make install"
make pdf; check_result $? "make pdf"
make man; check_result $? "make man"
make ps; check_result $? "make ps"
make html; check_result $? "make html"
make distclean; check_result $? "make distclean"

check_result $failures "Final result"
