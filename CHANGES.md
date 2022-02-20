Changes 1.4.0:
 * fix: ensure that LTO is supported (by Simo Sorce)
 * fix: add LTO regression testing (by Ondrej Mosnacek)
 * enhancement: add sm3sum, sm3hmac tools, add APIs kcapi_md_sm3, kcapi_md_hmac_sm3
 * enhancement: add SM4 convenience functions
 * fix: support AEAD encryption of arbitrary size with kcapi-enc

Changes 1.3.1:
 * fix: fix -Wconversion warnings (by Ondrej Mosnacek)
 * fix: fix bad data types in _kcapi_common_send_meta (by Ondrej Mosnacek)
 * fix: Version symbols to maintain ABI compatibility (by Simo Sorce)

Changes 1.3.0:
 * fix: disable io_getevents on systems that do not support it (by Khem Raj)
 * fix: remove prctl PR_SET_DUMPABLE to allow library to be debugged - as the library does not store any sensitive data in data structures it owns, such security precautions may not be necessary considering the benefit of allowing regular debugging
 * fix: ensure that sendmsg is always used as fallback when vmsplice cannot be used
 * enhancement: add kcapi_set_maxsplicesize and kcapi_get_maxsplicesize
 * enhancement: the variable types are changed from int32_t to ssize_t and from uint32_t to size_t to match common POSIX and Linux APIs

Changes 1.2.1:
 * fix: MSG_MORE usage: With kernel 5.9, a precise use of MSG_MORE is mandatory
   to support a stream cipher approach (init -> update -> update -> ... ->
   final). All but the last update operations must use MSG_MORE, the last
   update operation must not use MSG_MORE.
 * add automated test for Linux kernel 5.8 and 5.9

Changes 1.2.0
 * enhancement: kcapi-hasher: add madvise and 64 bit support by Brandur Simonsen
 * fix: fix clang warnding in KDF implementation by Khem Raj
 * fix: fix inverted logic in kcapi-main test logic reported by Ondrej Mosnáček
 * fix: return error when iteration count is zero for PBKDF as reported by
   Guido Vranken
 * enhancement: add function kcapi_cipher_stream_update_last to indicate the
   last block of a symmetric cipher stream operation
 * disable XTS multithreaded tests as it triggers a race discussed in
   https://github.com/smuellerDD/libkcapi/issues/92. The conclusion is
   the following: xts(aes) doesn't support chaining requests like for other
   ciphers such as CBC (at least as implemented in the kernel Crypto API).
   That can be seen in `crypto/testmgr.h` - the ciphers that are expected to
   return IVs usable for chaining have the `.iv_out` entries filled in in their
   test vectors (and those that don't support it do not). One can see that only
   CTR and CBC test vectors have them, not XTS.
   Looking again at how XTS is defined, it seems one could implement
   transparent chaining by simply decrypting the final tweak using the tweak
   key and return it as the output IV... but I believe this has never been
   mandated nor implemented in the Crypto API (likely because of the overhead
   of the final tweak decryption, which would be pointless if you're not going
   to use the output IV - and there is currently no way to signal to the driver
   that you are going to need it).
 * disable AIO parallel tests due to undefined behavior

Changes 1.1.5
 * Fix invocation of ansi_cprng in FIPS mode during testing
 * Fix testing on kernels >= 5.0
 * Add virtualization test for kernel 5.1
 * Fix the limit between vmsplice() and sendmsg() by Christophe Leroy
 * Fix remove code duplication by Ondrej Mosnáček
 * Fix potential memleak in speed-test

Changes 1.1.4
 * Fix: use sendmsg when processing more than 1<<16 bytes input data which
   improves performance on some architectures

Changes 1.1.3
 * Fix: default location of FIPS 140-2 HMAC control file is .<orig file>.hmac
   (was accidentally moved to <orig file>.hmac with 1.1.2)

Changes 1.1.2
 * Fix: Bug fixes for GCC 8.1.0 regarding string length checks by
	Krzysztof Kozlowski
 * Enhancement: ensure that tests execute on architectures other than X86
	by Ondrej Mosnáček
 * Fix: Bug fix to initialize FDs at the correct time in kcapi-kernel-if.c
	by Ondrej Mosnáček
 * Test fix: Support test execution outside build environment by
	Ondrej Mosnáček

Changes 1.1.1
 * Fix: Bug fixes for kcapi_hasher by Ondrej Mosnáček

Changes 1.1.0
 * API Enhancement: Addition of kcapi_handle_reinit
 * Fix: simplify code by removing the internal *_fd functions from
   kcapi-kernel-if.c
 * Fix: add a loop around the read system call to always obtain all generated
   data
 * Fix: use host compiler for compiling docproc (reported by Christophe LEROY,
   fixed by Björn Esser)
 * Fix: make error handling of hashing applications consistent with coreutils
   applications (reported by Christophe LEROY)
 * Fix: support for zero length files (patched by Ondrej Mosnáček)
 * Fix: support for zero message hashes on kernels <= 4.9 (patched by
	Ondrej Mosnáček)
 * Fix: Add Travis CI test system provided by Ondrej Mosnáček
 * Fix: Add several fixes to kcapi-hasher by Ondrej Mosnáček
 * Fix: Add additional tests for kcapi-hasher by Ondrej Mosnáček
 * Fix: Apply unpadding only to last block of data by Ondrej Mosnáček
 * Fix: Fix resource leaks in error code paths suggested by Ondrej Mosnáček
 * Enhancement: achieve hmaccalc CLI equivalence by Ondrej Mosnáček

Changes 1.0.3
 * Fix: support STDIN and --tag of sha*sum applications
 * Enhancement: Add small enhancements to support integration with distros --
   reported by Björn Esser

Changes 1.0.2
 * Fix: hasher-test.sh on 32-bit systems
 * Fix: AIO return code handling on large number of requests -- reported by
   Jonathan Cameron
 * Enhancement: disable coredumps of library
 * Fix: remove unchecked -fstack-protector-strong from Makefile -- reported by
   Mathieu Malaterre
 * Fix: document that kcapi_cipher_stream_op must be called in a loop to collect
   all data in a multhreaded environment.
 * Test Fix: Update symmetric multithreaded stream test to invoke
   kcapi_cipher_stream_op in a loop to collect all data.
 * Fix: Initialize the cipher handle on stack with zeros as the library expects
   a zero-initialized cipher handle. This fixes a possible segfault where
   free() is called on a non-initialized memory location.
 * Fix: port algif_kpp and algif_akcipher to 4.15-rc3

Changes 1.0.1
 * Fix: constify AEAD cipher input data
 * Fix: use GCC byte swapping acceleration if present
 * Fix: KDF counter handling on little endian systems when generating more than
   255 blocks
 * Use LD_PRELOAD for execution of test cases to force using of the freshly
   compiled binaries
 * Fix: return code handling of _kcapi_common_vmsplice_chunk_fd as reported
   by Christophe Leroy
 * Fix: return code handling in _kcapi_md_update
 * Fix: kcapi-hasher now supports files larger than 2GB
 * Fix: kcapi-dgst now supports files larger than 2GB
 * Fix: use stack protector
 * Fix: rename header guards to remove leading underscore as pointed out
   by Markus Elfring
 * Test Fix: Allow compiing the test code without asymmetric and KPP support

Changes 1.0.0
 * Fix: Small compile fixes for new checks of GCC 7
 * API Change: Rename all LOG_* enums to KCAPI_LOG_* to prevent namespace
   poisoning
 * Fix: soname and file name of library now compiles with
   conventions (thanks to Marcus Meissner)
 * Fix: kcapi-rng.c: unify FD/syscall read code and fix
   __NR_getrandom resolution
 * Enhancement: add kcapi-enc application to access symmetric encryption on
   command line
 * Fix: consolidate duplicate code in kcapi-hasher
 * Enhancement: add kcapi-dgst application to access hashes on command line
 * Enhancement: add kcapi-rng man page
 * Enhancement: add kcapi-rng --hex command line option
 * Fix: enable full symmetric AIO support
 * Fix: consolidate all test code into test/ and invoke all tests
   with test-invocation.sh
 * Fix: fix memleaks in error code paths as reported by clang
 * Fix: reduce memory footprint by rearranging data structures
 * Fix: kcapi-hasher is now fully FIPS 140-2 compliant as it now
   includes the integrity test for libkcapi.so
 * Enhancement: Add speed tests for MV-CESA accelerated ciphers and hash
   algorithms (thanks to Bastian Stender)
 * Test Enhancement: add kcapi-enc-test-large.c test testing edge conditions of
   AF_ALG
 * Test Enhancement: add virttest.sh - use of test system based on
   eudyptula-boot to test on linux-4.3.6, linux-4.4.86, linux-4.5, linux-4.7,
   linux-4.10, linux-4.12
 * Test Enhancement: add kcapi-fuzz-test.sh to support fuzzing the AF_ALG
   interfaces
 * Enhancement: add RPM SPEC file (tested with Fedora 26)
 * API Change: replace --disable-lib-asym with --enable-lib-asym as the
   algif_akcipher.c kernel interface is not likely to be added to the kernel
   anytime soon
 * API Enhancement: add KPP API which is not compiled by default, use
   --enable-lib-kpp (the algif_kpp.c kernel interface is not likely to be
   added to the Linux kernel any time soon)
 * Test Enhancement: Add KPP tests
 * Enhancement: Re-enable AIO support for symmetric and AEAD ciphers down to
   Linux kernels 4.1 and 4.7, respectively. This is due to integrating a
   fix against a kernel crash when using AIO.
 * Fix: simply KDF code base
 * API Enhancement: add message digest convenience functions kcapi_md_*sha*
 * API Enhancement: add cipher convenience functions kcapi_cipher_*_aes_*
 * API Enhancement: add rng convenience function kcapi_rng_get_bytes
 * API Change: remove kcapi_aead_getdata, use kcapi_aead_getdata_input and
   kcapi_aead_getdata_output instead
 * API Change: remove kcapi_aead_outbuflen, use kcapi_aead_outbuflen_enc and
   kcapi_aead_outbuflen_dec instead

Changes 0.14.0
 * AIO: fix tracking of completed IOCBs
 * speed-test: fix AEAD handling
 * speed-test: fix time calculation
 * compiler now warns a user of deprecated API calls
 * AIO: handle kernel errors for algif_skcipher gracefully
 * AIO: using multiple IOCB if algif_aead interface supports it
 * ASYM: add PKCS1 tests
 * AIO: add ASYM AIO support
 * AIO: fix AEAD AIO fallback
 * AIO: add AIO fallback testing
 * replace enforcement of symmetric cipher limits with a log message only
   (the underlying kernel implementations should catch any errors)
 * add fuzzing tests
 * use autotools build system as provided by Georges Savoundararadj with
   additional considerations from Marcin Nowakowski (thanks a lot)
 * ALG_MAX_PAGES restriction is gone with current AF_ALG interface
 * add HKDF (RFC5869)
 * add apps/kcapi-rng
 * add support for multiple accepts where the caller maintains the opfd
 * fix memleak in error case in PBKDF
 * add multithreaded symmetric cipher tests
 * enable full AIO support for kernels 4.13 and higher (fallback AIO
   implementation using synchronous support for earlier kernels) -- this
   is due to the broken AIO support for earlier kernels
 * Add tests for the AAD copy operation to be supported for kernel 4.13

Changes 0.13.0
 * change kcapi_aead_encrypt_aio, kcapi_aead_decrypt_aio,
   kcapi_cipher_encrypt_aio and kcapi_cipher_decrypt_aio to require the
   user to provide IOVECs for input and output buffers separately
 * addition of kcapi_aead_inbuflen_enc, kcapi_aead_inbuflen_dec,
   kcapi_aead_outbuflen_enc, kcapi_aead_outbuflen_dec, kcapi_aead_getdata_input,
   kcapi_aead_getdata_output to allow apps to be programmed without specific
   code handling for old and new AEAD AF_ALG interface (AAD and tag handling).
   See the documentation section "AEAD Memory Structure" for an explanation
   on how to use the API in a way to make the calling application agnostic
   of the kernel interface differences.
 * significant addition to library to handle old / new AEAD AF_ALG interface
   without the caller being aware of that
 * change AEAD tests such to use the new API calls to make code independent
   of AEAD interface changes
 * split up of the library implementation into individual files to allow
   a more clear code management and to allow even to selectively disable
   code to make the library smaller
 * various small fixes suggested by Zbigniew Jędrzejewski-Szmek
 * fix memleak in kcapi_*_destroy suggested by Zbigniew Jędrzejewski-Szmek
 * use hard-links for the kcapi-hasher apps
 * add bi-arch tests
 * add check that AIO interface is only initialized if the kernel supports
   AIO (library requires kernel 4.1.0 or larger for skcipher AIO and
   4.7.0 or larger for AEAD AIO support)
 * add transparent fallback in case the caller requests AIO operation but
   the AIO interface was not or could not be initialized -- the AIO API can be
   used on systems without AIO support as the library transparently falls back
   to the non-AIO operation (however, the library complains at the beginning
   about the use of the AIO API on unsupported systems).

Changes 0.12.0
 * add version.lds
 * add KDF API
 * add PBKDF API
 * update Makefile to look for environment
 * bug fix speed test
 * add AIO support (this code is derived from the example code developed by
   Tadeusz Struk -- thanks a lot) together with AIO test cases
 * Move DSO_PUBLIC out of the public header file into the private header file
 * use _kcapi_cipher_crypt for AEAD operations - eliminate code duplication
 * update AEAD tests to verify that the kernel follows the memory and
   processing structure defined for in-kernel users. Note, the testing
   will assume the old AF_ALG interface handling up to and including 4.9.x.
   The new AF_ALG AEAD interface is assumed to be present starting with 4.10.0.
   Note, the interface differences are only visible in the return code of
   recv which is checked by the test cases. Otherwise, user space sees no
   difference.

Changes 0.11.1
 * move version information to kcapi.h to allow compile time tests for wrapping
   applications
 * fix error code path mem leaks in _kcapi_handle_init reported by cppcheck

Changes 0.11.0:
 * Convert all libkcapi data structures into opaque structures. This implies
   that the *_init functions require a reference to a pointer as these init
   functions now allocate the struct kcapi_handle data structure.
 * Add clean and consistent logging logic
 * fixed execution when CONFIG_CRYPTO_FIPS is disabled in kernel
 * mark all symbols except API as hidden
 * performance measurements for kcapi_md_updatn added
 * update speed tests for newer AVX/AVX2 kernel handling
 * update documentation to mark all parameters as [in] or [out]

Changes 0.10.2:
 * Fix kernel netlink parsing error message
 * doc: add hint for setting keys before sending data
 * fix compiler warnings about unsigned / signed comparisons

Changes 0.10.1:
 * Fix issues with the vmsplice usage in stream mode
 * Fix issues with the vmsplice usage in chunk mode
 * Any modification on the tfmfd must be performed before the accept() call as mandated
   by the update to kernel 4.4.
 * Add support for processing of arbitrary sized symmetric cipher input

Changes 0.10.0:
 * simplify kcapi_aead_encrypt and kcapi_aead_decrypt
 * comment out message truncation check
 * test.sh: fix RFC4106 IV handling for kernels >= 4.2 due to overhaul of
   AEAD support in the kernel
 * use zero-copy in stream operation if possible
 * Add set_pubkey API call
 * convert entire API to use data types with known sizes (i.e. stdint.h)
 * Add asymmetric tests to test.sh
 * Add asymmetric stream cipher API
 * update documentation to cover akcipher API

Changes 0.9.0:
 * Add asymmetric cipher API.

Changes 0.8.0:
 * Fix test.sh to invoke large AEAD test
 * All kcapi_*_destroy functions are void now
 * Update AEAD code to new kernel interface and update the AEAD API
 * Simplify the code for AEAD
 * Add and use kcapi_memset_secure
 * Add AIO logic
 * Add drop in replacements for sha1sum, sha224sum, sha256sum, sha384sum,
   sha512sum and md5sum
 * Remove the kernel-patch/ directory as its code is not consistent with
   the library any more. Use the current cryptodev-2.6 tree from Herbert Xu.

Change 0.7.2:
 * Move the library code into the directory lib/
 * Fix issues reported by cppcheck
 * AEAD: allow encrypt/decrypt invocations with NULL AAD and NULL PT/CT
 * AEAD: add test for NULL AAD and NULL PT/CT
 * RNG: always invoke seeding operation, even when seed is NULL

Change 0.7.1:
 * AEAD kernel interface is now upstreamed, reference the patches
   in the documentation appropriately and remove the patches from the
   kernel patch tree.
 * Test: add rfc4106(gcm(aes)) tests to general test and to speed test
 * Speed test: invoke the ciphers 10 times before time measurement to prime
   the caches.

Change 0.7.0:
 * AEAD kernel part does not relay MSG_TRUNC any more, thus using the
   read syscall is more efficient.
 * remove kcapi_cipher_setiv and add an IV parameter to all necessary
   API calls. This prevents the requirement for a function call
   and requiring the caller to maintain the IV buffer
 * add vmsplice tests to test framework to make sure vmsplice is really
   executed
 * fix documentation style
 * allow caller to specify which kernel interface (sendmsg / vmsplice)
   is used for one-shot API calls. This implies extension of one-shot
   API calls
 * Update stream API tests for AEAD to use 16 IOVECs to test the latest
   installment of the recvmsg interface of algif_aead

Change 0.6.5:
 * Measuring speed of vmsplice vs sendmsg interfaces and added heuristic
   to select the fastest implementation
 * Enhance documentation to explain usage of API better
 * added speed measuring tests in speed-test/
 * return errno for all syscalls through the API return codes
   for better error handling
 * process kernel flag of MSG_TRUNG for AEAD ciphers

Change 0.6.4:
 * Update AEAD interface patch
 * Add new test invoking cipher instance multiple times (-d flag of test
   application)

Change 0.6.3:
 * Remove several sanity checks in the API functions. This shall allow
   the invocation of edge conditions (like no plaintext, but AAD and tag).
   The kernel contains the appropriate sanity checks too. Therefore there
   is no harm in removing them.
 * Add testing of long AAD: fill 16 pages with 65504 bytes AAD and 32 bytes
   plaintext (stream API) and 15 pages AAD plus 16th page holding plaintext
   (one-shot API).
 * Update AEAD interface to allow arbitrary AAD sizes.

Change 0.6.2:
 * update all vmsplice invocations to consider the limitations of the pipe
   buffer of 16 pages (the limitation in the kernel is enforced by
   vmsplice_to_pipe setting nr_pages_max and splice_from_pipe_feed which
   iterates over the available pipe->nrbufs) - this fixes message digests and
   symmetric operations for input data larger than 16 pages; the AEAD
   cipher contains a sanity check that the input data size is not too large --
   thanks to Amit Uttamchandani <amit.uttam@gmail.com> for the bug report
 * update aead/rng kernel pages to match 3.19-rc1

Change 0.6.1:
 * fix compile error

Change 0.6.0:
 * add kcapi_md_blocksize
 * add stress / negative testing
 * add hint to NETLINK_CRYPTO patch requirement

Change 0.5.0:
 * kernel interface for AEAD and RNG changed
 * add kcapi_rng_seed API call

Change 0.4.0:
 * update AEAD cipher interface for current implemetation
 * remove nonalinged API
-* add one-shot and stream API
 * use zero copy interface for one-shot APi
 * add tests to cover one-shot and stream API
 * full documentation update
 * stress testing the library and the AEAD/RNG implementation

Change 0.3.0:
 * new kernel patch for AEAD/RNG interface
 * Support for updated AEAD kernel interface
 * Use of NETLINK_CRYPTO instead of getsockopt (code currently disabled due to
   a bug in crypto/crypto_user.c -- see TODO)

Changes 0.2.1:
 * Add automation to generate nicely formatted guidance documents out of source
   code comments. See README.md for make targets generating the respective
   guidance documents.

Changes 0.2.0:
 * Add kcapi_aead_[enc|dec]_* calls for non-aligned requests
 * Updated kernel patch to match what has been sent to LKML
 * Documentation of API calls and data structures completed
 * Add kcapi_md_digestsize
 * Add sanity checking to IV setting API
 * Add kcapi_pad_iv
 * Add sanity check around getsockopt wrapper API call
 * API documentation marks input / output parameters
 * API documentation explains AEAD decryption EBADMSG error code
 * Update of teets to cover all changed / new API calls
