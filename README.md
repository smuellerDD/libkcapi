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

Directory Structure
===================

lib/ -- directory holding the library

apps/ -- directory holding the applications discussed below; these
	 applications hard link the library code in.

test/ -- functional verification code

speed-test/ -- performance tests

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

Build instructions
==================
The build system is based on `autotools`. First of all, you have to run the
following command that will generate the `Makefile` and the `configure` script:
```
$ autoreconf -i
```
The `configure` script supports the following options:
* `--prefix=$PREFIX`: install the library and the applications to
  `$PREFIX`
* `--with-kcapi-test`: compile and install the `kcapi` test program
* `--with-kcapi-speed`: compile and install `kcapi-speed` test program
* `--with-apps`: compile and install the applications

For instance, to compile the library with the `kcapi` test program and to
install them in `/usr/`:
```
$ ./configure --prefix=/usr/ --with-kcapi-test
```

Then, run `make` to compile and `make install` to install in the folder
specified by the `--prefix` option.

The Makefile compiles libkcapi as a shared library and as a static libary.

Build documentation
-------------------
`xmlto` is required to build the man pages and the documentation in doc/html.
`db2pdf` and `db2ps` are required to build the documentation in PDF or in PS format.

Use the following targets to generate the documentation in the appropriate format:
* `make man`
* `make pdf`
* `make ps`
* `make html`

To install the man pages run: `make install-man`.

Static Code analyzer
--------------------
If `clang` or `cppcheck` are installed, you can use the following targets to
run them on the source code:
* `make scan`
* `make cppcheck`

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
