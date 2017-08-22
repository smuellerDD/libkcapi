libkcapi test applications
==========================

For the different components of libkcapi there are several tests
as listed in the following:

* test.sh: The test script validates the correctness of the
  libkcapi shared library. The shell script uses FIPS 140-2
  CAVS test vectors to verify the correct operation of the interface.

* kcapi-enc-test.sh: The kcapi-enc application is tested with
  this script covering the processing of command line options and
  input data. The kcapi-enc operation is verified with openssl enc.

* kcapi-dgst-test.sh: The kcapi-dgst application is tested with
  this script covering the processing of command line options and
  input data. The kcapi-dsgt operation is verified with openssl dgst.

* hasher-test.sh: The kcapi-hasher application is tested to verify
  that it behaves consistently with the sha*sum and sha*hmac
  applications.

* compile-test.sh: This script enables all configure options and
  performs a full compilation and installation.

All tests are collectively invoked with the test-invocation.sh script.

Bi-arch tests
-------------

On bi-arch systems, the Makefile.m32 can be used to compile the 32 bit
version of the test application.

To test both word sizes simultaneously, use test-invocation.sh which
compiles and executes the test cases. Again, the script shall
return with a return code of 0.
