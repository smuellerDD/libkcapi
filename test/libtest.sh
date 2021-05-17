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
# Common code for test cases
#

#####################################################################
# Common functions
#####################################################################

DIRNAME="$(dirname "$0")"

# Allow overriding default value:
if [ -e "$DIRNAME/test-is-local" ]; then
	KCAPI_TEST_LOCAL=${KCAPI_TEST_LOCAL:-1}
else
	KCAPI_TEST_LOCAL=${KCAPI_TEST_LOCAL:-0}
fi

if [ "$KCAPI_TEST_LOCAL" -eq 1 ]; then
	get_app_path()
	{
		echo -n "$DIRNAME/../bin/$1"
	}
	run_app()
	{
		local appname="$1"; shift

		"$(get_app_path "$appname")" "$@"
	}
	find_app_binary()
	{
		echo -n "$(dirname "$1")/.libs/$(basename "$1")"
	}
	KCAPI_TEST_BIN_DIR="$DIRNAME/../bin"
else
	get_app_path()
	{
		command -v "$1"
	}
	run_app()
	{
		"$@"
	}
	find_app_binary()
	{
		echo -n "$1"
	}
	KCAPI_TEST_BIN_DIR="$DIRNAME"
fi

failures=0
PLATFORM="unknown wordsize"
KERNVER=$(uname -r)

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
	local app="$(get_app_path "$1")"
	local binlocation="$(find_app_binary $app)"
	if ! [ -x "$binlocation" ]
	then
		binlocation="$app"
	fi
	PLATFORM=$(file "$binlocation" | cut -d" " -f 3)
}

# check whether a given kernel version is present
# returns true for yes, false for no
check_min_kernelver() {
	major=$1
	minor=$2

	if [ $(uname -r | cut -d"." -f1) -gt $major ]; then
		return 0
	fi

	if [ $(uname -r | cut -d"." -f1) -eq $major ]; then
		if [ $(uname -r | cut -d"." -f2) -ge $minor ]; then
			return 0
		fi
	fi
	return 1
}

#####################################################################
# Common variables
#####################################################################

# Storage location of temp files
TMPDIR="/var/tmp"
if [ ! -d $TMPDIR ]
then
	TMPDIR="."
fi
