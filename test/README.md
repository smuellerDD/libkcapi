libkcapi test application
=========================

Invoke the test using the test.sh shell script after building the
binary. The shell script uses FIPS 140-2 CAVS test vectors to verify
the correct operation of the interface.

Bi-arch tests
-------------

On bi-arch systems, the Makefile.m32 can be used to compile the 32 bit
version of the test application.

To test both word sizes simultaneously, use test-invocation.sh which
compiles and executes the test cases. Again, the script shall
return with a return code of 0.
