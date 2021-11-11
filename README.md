libkcapi -- Linux Kernel Crypto API User Space Interface Library [![Build Status](https://github.com/smuellerDD/libkcapi/workflows/checks/badge.svg)](https://github.com/smuellerDD/libkcapi/actions?query=branch%3Amaster)
[![Code Quality: Cpp](https://img.shields.io/lgtm/grade/cpp/github/smuellerDD/libkcapi.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/smuellerDD/libkcapi/context:cpp)
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

`lib/` -- directory holding the library

`apps/` -- directory holding the applications discussed below; these
	 applications link the library code in.

`test/` -- functional verification code

`speed-test/` -- performance tests

`kernel-patches/` -- Linux kernel patches providing the interfaces for the asymmetric ciphers (akcipher) and the DH/ECDH ciphers (KPP). These patches must be applied to the Linux kernel if the respective configure options of either `--enable-lib-asym` or `--enable-lib-kpp` are used.

Applications
============

The libkcapi distribution contains the following applications which are
intended as a drop-in replacement for the respective applications commonly
available in all Linux distributions:

* coreutils: sha512sum, sha384sum, sha256sum, sha224sum, sha1sum, md5sum

* libfipscheck: fipscheck / fipshmac

* hmaccalc: sha512hmac, sha384hmac, sha256hmac, sha224hmac, sha1hmac, sm3hmac

The output as well as the command line options are modeled according to the
commands found in the coreutils package.

In addition, the following tool is available:

* `kcapi-rng`: This tool allows obtaining random numbers from the kernel
  crypto API RNGs. It shall allow users a similar operation as a
  `cat /dev/hwrand` call.

* `kcapi-enc`: This tool provides command line access to the symmetric ciphers
  of the kernel crypto API. It is conceptually similar to the openssl enc
  tool.

* `kcapi-dgst`: To generate message digests and keyed message digests using
  the kernel crypto API ciphers, this command line tool can be used. It is
  conceptually similar to openssl dgst.

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
* `--enable-kcapi-test`: compile and install the `kcapi` test program
* `--enable-kcapi-speed`: compile and install `kcapi-speed` test program
* `--enable-kcapi-hasher`: compile and install the drop-in replacement
  applications
* `--enable-kcapi-rngapp`: compile and install the kcapi-rng application
* `--enable-kcapi-encapp`: compile and install the kcapi-enc application
* `--enable-kcapi-dgstapp`: compile and install the kcapi-dgst application
* The various `--disable-lib-*` options allows the disabling of different
  library functions to allow minimizing the binary.
* The various `--enable-lib-*` options allow the enabling of the different
  library functions. All library functions referenced there do not have an
  equivalent kernel support in the upstream Linux kernel. Yet, patches are
  available in the `kernel-patches` directory that provide that interface
  which need to be added to the kernel if desired.

For instance, to compile the library with the `kcapi` test program and to
install them in `/usr/`:
```
$ ./configure --prefix=/usr/ --enable-kcapi-test
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


Integration of libkcapi into other projects
===========================================

The libkcapi library does not have any dependencies except to the C-library
(and the kernel, naturally). This allows developers to integrate the
library into their project either as a shared library or natively by simply
copying the required C and header files into the target project and compile
them along.

When compiling them as part of a project, no special compile time flags are
needed as the library is written in clean C. Though, the project author should
consider the COMMON_CPPFLAGS and COMMON_LDFLAGS in Makefile.am as they
collectively provide additional security checks offered by the compiler or
the underlying platform.

To integrate the library source code directly into projects, the following
files must always be copied into the target project irrespective of the cipher
operations the project wants to use:

* kcapi-kernel-if.c (this provides the basic kernel interface logic)

* all header files

Now, a project may selectively copy the following files as required for the
respective project. The listed files do not have mutual dependencies unless
explicitly noted:

* kcapi-aead.c (AEAD cipher support providing kcapi_aead_* functions)

* kcapi-asym.c (asymmetric cipher support providing all kcapi_akcipher_* functions)

* kcapi-md.c (message digest and keyed message digest support providing all kcapi_md_* functions)

* kcapi-rng.c (random number generator support providing all kcapi_rng_* functions)

* kcapi-sym.c (symmetric cipher support providing all kcapi_cipher_* functions)

* kcapi-kdf.c (depending on the presence of kcapi-md.c -- providing the KDF, HKDF and PBKDF implementations with the functions of kcapi_*kdf_*)

* kcapi-utils.c (small helper functions providing, including versioning APIs)

* kcapi-kpp.c (key protocol primitives (i.e. Diffie-Hellman and EC Diffie-Hellman) support providing all kcapi_kpp_* functions)

Author
======
Stephan Mueller <smueller@chronox.de>
