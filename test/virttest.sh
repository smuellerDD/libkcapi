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

###################################################################
# Test configuration - may be changed
###################################################################

# The KERNEL_BASE points to the directory where the linux kernel sources
# are located. These kernel sources must be properly configured as
# documented in https://github.com/vincentbernat/eudyptula-boot
#
# If needed, the kernel is automatically compiled and installed
# for use by eudyptula-boot.
#
# Note, this must be an absolute path name
KERNEL_BASE=$1
if [ -z "$KERNEL_BASE" -a -h "./kernel-sources" ]
then
	KERNEL_BASE="$(readlink ./kernel-sources)"
else
	echo_deact "Linux kernel sources directory not found - skipping eudyptula-boot tests"
	exit 0
fi

# TESTKERNELS specifies the kernel versions (i.e. Linux kernel
# source code directories) to be used and tested
TESTKERNELS="linux-5.12 linux-5.9 linux-5.8 linux-5.1 linux-4.20 linux-4.17 linux-4.13 linux-4.12 linux-4.10 linux-4.7 linux-4.5 linux-4.4.86 linux-4.3.6"

###################################################################
# General variables - do not change
###################################################################

# We need to provide an absolute path name
if [ x"${a:0:1}" = x"/" ]
then
	SCRIPT="$DIRNAME/test-invocation.sh"
else
	SCRIPT="$(pwd)/$DIRNAME/test-invocation.sh"
fi
EUDYPTULA="${EUDYPTULA:-"${HOME}/bin/eudyptula-boot"}"

###################################################################
# Code - do not change
###################################################################
execvirt()
{
	local script=$1
	local kernel_ver=$2

	local depmod=0
	local kernel_src="${KERNEL_BASE}/${kernel_ver}"
	local kernel_build="${KERNEL_BASE}/build/${kernel_ver}"
	local kernel_binary=""
	local moddir=""

	echo "Testing Linux kernel version $kernel_ver in directory $KERNEL_BASE"

	if [ ! -d "$kernel_src" ]
	then
		echo "No kernel source directory found"
		exit 1
	fi
	cd $kernel_src

	if [ ! -f .config ]
	then
		echo "No configured kernel found in $(pwd)"
		exit 1
	fi
	if ! grep -q "CONFIG_9P_FS=y" .config
	then
		echo "No virtme compliant kernel config found"
		exit 1
	fi

	# Build and install fully configured kernel
	if [ ! -d ${kernel_build} ]
	then
		make -j2
		make modules_install install INSTALL_MOD_PATH=${kernel_build} INSTALL_PATH=${kernel_build}
		depmod=1
	fi

	# get latest modules directory
	moddir=${kernel_build}/lib/modules
	local version=$(ls -t ${moddir} | head -n1)
	moddir=${moddir}/$version
	if [ ! -d "$moddir" ]
	then
		echo "No directory $moddir"
		exit 1
	fi

	kernel_binary=${kernel_build}/vmlinuz-$version
	if [ ! -f $kernel_binary ]
	then
		echo "Kernel binary $kernel_binary not found"
		exit 1
	fi

	if [ $depmod -ne 0 ]
	then
		depmod -b ${kernel_build} $version
	fi

	$EUDYPTULA --kernel $kernel_binary $script
	if [ $? -ne 0 ]
	then
		local ret=$?
		echo_fail "Test for kernel version $kernel_ver failed"
		exit $ret
	fi
}

if [ ! -x $EUDYPTULA ]
then
	echo_deact "$EUDYPTULA not found"
	exit 0
fi

for i in ${TESTKERNELS}
do
	execvirt $SCRIPT $i
done
