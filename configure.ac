dnl KCAPI_MAJVERSION API / ABI incompatible changes, functional
dnl 		     changes that require consumer to be updated
dnl 		     (as long as this number is zero, the API is
dnl 		     not considered stable and can change without
dnl 		     a bump of the major version)
dnl KCAPI_MINVERSION API compatible, ABI may change, functional
dnl 		     enhancements only, consumer can be left
dnl 		     unchanged if enhancements are not considered
dnl KCAPI_PATCHLEVEL API / ABI compatible, no functional changes, no
dnl 		     enhancements, bug fixes only. Versions with
dnl		     a decimal point are pre-releases.
m4_define([__KCAPI_MAJVERSION], [0])
m4_define([__KCAPI_MINVERSION], [13])
m4_define([__KCAPI_PATCHLEVEL], [0.8])
m4_define([KCAPI_VERSION], [__KCAPI_MAJVERSION.__KCAPI_MINVERSION.__KCAPI_PATCHLEVEL])

AC_INIT([libkcapi], [KCAPI_VERSION])
AC_DEFINE([KCAPI_MAJVERSION], [__KCAPI_MAJVERSION])
AC_DEFINE([KCAPI_MINVERSION], [__KCAPI_MINVERSION])
AC_DEFINE([KCAPI_PATCHLEVEL], [__KCAPI_PATCHLEVEL])
AM_INIT_AUTOMAKE([foreign])
LT_INIT
AC_PROG_CC
AC_CONFIG_FILES([Makefile])
AM_PROG_LIBTOOL
AC_CONFIG_MACRO_DIRS([m4])

AC_CHECK_PROG([CLANG], [clang], [yes])
AC_CHECK_PROG([CPPCHECK], [cppcheck], [yes])
AC_CHECK_PROG([XMLTO], [xmlto], [yes])
AC_CHECK_PROG([DB2PDF], [db2pdf], [yes])
AC_CHECK_PROG([DB2PS], [db2ps], [yes])
AC_CHECK_PROG([MKTEMP], [mktemp], [yes])
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_INSTALL
AC_PROG_LN_S

AM_CONDITIONAL([HAVE_CLANG], [test "x$CLANG" = "xyes" ])
AM_CONDITIONAL([HAVE_CPPCHECK], [test "x$CPPCHECK" = "xyes"])
AM_CONDITIONAL([HAVE_XMLTO], [test "x$XMLTO" = "xyes"])
AM_CONDITIONAL([HAVE_DB2PDF], [test "x$DB2PDF" = "xyes"])
AM_CONDITIONAL([HAVE_DB2PS], [test "x$DB2PS" = "xyes"])
AM_CONDITIONAL([HAVE_MKTEMP], [test "x$MKTEMP" = "xyes"])

AM_COND_IF([HAVE_CLANG], [], [AC_MSG_WARN([clang not installed])])
AM_COND_IF([HAVE_CPPCHECK], [], [AC_MSG_WARN([cppcheck not installed])])
AM_COND_IF([HAVE_XMLTO], [], [AC_MSG_WARN([xmlto not installed])])
AM_COND_IF([HAVE_DB2PDF], [], [AC_MSG_WARN([db2pdf not installed])])
AM_COND_IF([HAVE_DB2PS], [], [AC_MSG_WARN([db2ps not installed])])
AM_COND_IF([HAVE_MKTEMP], [], [AC_MSG_WARN([mktemp not installed])])

AC_CHECK_FUNCS(getrandom)
AC_CHECK_FUNCS(secure_getenv)

AC_CHECK_API_VERSION

AC_ARG_ENABLE([kcapi-test], [AS_HELP_STRING([--enable-kcapi-test], [Compile kcapi test program])], [with_kcapi_test=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_TEST], [test "x$with_kcapi_test" = "xyes"])

AC_ARG_ENABLE([kcapi-speed], [AS_HELP_STRING([--enable-kcapi-speed], [Compile kcapi-speed test program])], [with_kcapi_speed_test=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_SPEED], [test "x$with_kcapi_speed_test" = "xyes"])

AC_ARG_ENABLE([apps], [AS_HELP_STRING([--enable-apps], [Compile all applications])], [with_kcapi_hasher=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_HASHER], [test "x$with_kcapi_hasher" = "xyes"])

AC_ARG_ENABLE([lib-kdf], [AS_HELP_STRING([--disable-lib-kdf], [Disable KDF support in library to make it smaller])], [with_lib_kdf=$enableval])
AM_CONDITIONAL([DISABLE_LIB_KDF], [test "x$with_lib_kdf" = "xno"])

AC_ARG_ENABLE([lib-asym], [AS_HELP_STRING([--disable-lib-asym], [Disable asymmetric cipher support in library to make it smaller])], [with_lib_asym=$enableval])
AM_CONDITIONAL([DISABLE_LIB_ASYM], [test "x$with_lib_asym" = "xno"])

AC_ARG_ENABLE([lib-sym], [AS_HELP_STRING([--disable-lib-sym], [Disable symmetric cipher support in library to make it smaller])], [with_lib_sym=$enableval])
AM_CONDITIONAL([DISABLE_LIB_SYM], [test "x$with_lib_sym" = "xno"])

AC_ARG_ENABLE([lib-md], [AS_HELP_STRING([--disable-lib-md], [Disable message digest support in library to make it smaller])], [with_lib_md=$enableval])
AM_CONDITIONAL([DISABLE_LIB_MD], [test "x$with_lib_md" = "xno"])

AC_ARG_ENABLE([lib-aead], [AS_HELP_STRING([--disable-lib-aead], [Disable AEAD cipher support in library to make it smaller])], [with_lib_aead=$enableval])
AM_CONDITIONAL([DISABLE_LIB_AEAD], [test "x$with_lib_aead" = "xno"])

AC_ARG_ENABLE([lib-rng], [AS_HELP_STRING([--disable-lib-rng], [Disable random number generator support in library to make it smaller])], [with_lib_rng=$enableval])
AM_CONDITIONAL([DISABLE_LIB_RNG], [test "x$with_lib_rng" = "xno"])

AC_OUTPUT
