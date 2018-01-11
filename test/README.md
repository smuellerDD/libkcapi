libkcapi test applications
==========================

For the different components of libkcapi there are several tests
as listed in the following:

* `test.sh`: The test script validates the correctness of the
  libkcapi shared library. The shell script uses FIPS 140-2
  CAVS test vectors to verify the correct operation of the interface.

* `kcapi-enc-test.sh`: The kcapi-enc application is tested with
  this script covering the processing of command line options and
  input data. The kcapi-enc operation is verified with openssl enc.

* `kcapi-dgst-test.sh`: The kcapi-dgst application is tested with
  this script covering the processing of command line options and
  input data. The kcapi-dsgt operation is verified with openssl dgst.

* `hasher-test.sh`: The kcapi-hasher application is tested to verify
  that it behaves consistently with the sha*sum and sha*hmac
  applications.

* `kcapi-enc-test-large.sh` invoking the kcapi-enc-test-large.c application:
  That test verifies edge conditions of the algif_skcipher when large
  data chunks are processed.

* `virttest.sh`: Use the eudyptula-boot tool to test older kernel versions
  with libkcapi. This test is only executed if ${HOME}/bin/eudyptula-boot
  is present. If it is present, please check the virttest.sh script for
  configuration of the kernel sources and directories. Example kernel
  configurations that can be used for this kind of testing are found
  in the directory `virttest-kernel-configs`.

* `compile-test.sh`: This script enables all configure options and
  performs a full compilation and installation.

* `libtest.sh`: This script is a library of functions used by the other
  test scripts. It is not intended to be called directly.

All tests are collectively invoked with the `test-invocation.sh` script.
In addition, the following tests are not integrated into the general
test run, but can be enabled by setting `ENABLE_FUZZ_TEST` to any value
before running `test-invocation.sh` :

* `kcapi-fuzz-test.sh`: Execute various fuzzing tests.

Bi-arch tests
-------------

To test both word sizes simultaneously, use `test-invocation.sh` which
compiles and executes the test cases.

You can disable the 32 bit tests by explicitly setting `NO_32BIT_TEST`
to any value before running `test-invocation.sh`.
