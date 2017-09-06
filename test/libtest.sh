#!/bin/bash
#
# Copyright (C) 2017, Stephan Mueller <smueller@chronox.de>
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
# Common code for test cases
#

#####################################################################
# Common functions
#####################################################################
# color -- emit ansi color codes

failures=0
PLATFORM="unknown wordsize"
KERNVER=$(uname -r)

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
	echo $(color "green")[PASSED: $PLATFORM - $KERNVER]$(color off) $@
}

echo_fail()
{
	echo $(color "red")[FAILED: $PLATFORM - $KERNVER]$(color off) $@
	failures=$(($failures+1))
}

echo_deact()
{
	echo $(color "yellow")[DEACTIVATED: $PLATFORM - $KERNVER]$(color off) $@
}

find_platform()
{
	local app=$1

	if [ ! -x "$app" ]
	then
		echo_fail "Application binary $app not found"
		exit 1
	fi

	PLATFORM=$(file $app | cut -d" " -f 3)
}

# check whether a given kernel version is present
# returns true for yes, false for no
check_min_kernelver() {
	major=$1
	minor=$2

	if [ $(uname -r | cut -d"." -f1) -ge $major ]; then
		if [ $(uname -r | cut -d"." -f2) -ge $minor ]; then
			return 0
		fi
	fi
	return 1
}

#####################################################################
# Common variables
#####################################################################
# Location of shared lib
export LD_LIBRARY_PATH="../.libs"
export PATH=$PATH:.

# Location of apps
APPDIR="../bin/.libs"
if [ ! -d $APPDIR ]
then
	APPDIR="../bin"
fi
if [ ! -d $APPDIR ]
then
	echo_fail "No appdir found"
	exit 1
fi

# Storage location of temp files
TMPDIR="/var/tmp"
if [ ! -d $TMPDIR ]
then
	TMPD="."
fi
