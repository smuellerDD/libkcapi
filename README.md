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

The following kernel patches are distributed with this library. There is no
need to add them to the kernel unless you want to use the following
functionality that is already supported by this library:

	* AEAD cipher

	* Random number generator

Use the latest patch set in the kernel-patch/ directory.

Author
======
Stephan Mueller <smueller@chronox.de>
