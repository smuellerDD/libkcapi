libkcapi -- Linux Kernel Crypto API User Space Interface Library
================================================================

libkcapi allows user-space to access the Linux kernel crypto API.

libkcapi uses this Netlink interface and exports easy to use APIs so that
a developer does not need to consider the low-level Netlink interface handling.

The library does not implement any cipher algorithms. All consumer requests
are sent to the kernel for processing. Results from the kernel crypto API
are returned to the consumer via the library API.

The kernel interface and therefore this library can be used by unprivileged
processes.

The focus during the development of this library is put on speed. This library
does not perform any memcpy for processing the cryptographic data! The library
uses scatter / gather lists to eliminate the need for moving data around in
memory.

Applications
============

The libkcapi distribution contains the following applications which are
intended as a drop-in replacement for the respective applications commonly
available in all Linux distributions:

* coreutils: sha512sum, sha384sum, sha256sum, sha224sum, sha1sum, md5sum

* libfipscheck: fipscheck / fipshmac

* hmaccalc: sha512hmac, sha384hmac, sha256hmac, sha224hmac, sha1hmac

The output as well as the command line options are modeled according to the
commands found in the coreutils package.

These applications do not depend on any user space library other than the
C-lib.


Version Numbers
===============
The version numbers for this library have the following schema:
MAJOR.MINOR.PATCHLEVEL

Changes in the major number implies API and ABI incompatible changes, or
functional changes that require consumer to be updated (as long as this 
number is zero, the API is not considered stable and can change without a 
bump of the major version).

Changes in the minor version are API compatible, but the ABI may change. 
Functional enhancements only are added. Thus, a consumer can be left 
unchanged if enhancements are not considered. The consumer only needs to 
be recompiled.

Patchlevel changes are API / ABI compatible. No functional changes, no
enhancements are made. This release is a bug fixe release only. The
consumer can be left unchanged and does not need to be recompiled.


Make Targets
============

The following make targets are applicable:

* make              # compile library

* make install      # install library into $PREFIX

* make scan         # use CLANG static code analyzer

* make man          # compile man pages in doc/man

* make maninstall   # install man pages into $PREFIX

* make pdf          # generate documentation in PDF

* make ps           # generate documentation in PS

* make html         # generate documentation as HTML in doc/html


Compilation
===========

The Makefile compiles libkcapi as a shared library.

The "install" Makefile target installs libkcapi under /usr/local/lib or
/usr/local/lib64. The header file is installed to /usr/local/include.


Test cases
==========

The test/ directory contains test cases to verify the correct operation of
this library. In addition it allows the verification of the correct operation
of the kernel crypto API.

The test cases are documented in test/README.


Kernel Patches
==============

With the current cryptodev-2.6 tree from Herbert Xu, all patches are integrated.


Author
======
Stephan Mueller <smueller@chronox.de>
