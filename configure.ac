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
m4_define([__KCAPI_PATCHLEVEL], [0.7])
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

AC_CHECK_API_VERSION

AC_ARG_WITH([kcapi-test], [AS_HELP_STRING([--with-kcapi-test], [Compile kcapi test program])], [with_kcapi_test=yes])
AM_CONDITIONAL([ENABLE_KCAPI_TEST], [test "x$with_kcapi_test" = "xyes"])

AC_ARG_WITH([kcapi-speed], [AS_HELP_STRING([--with-kcapi-speed-test], [Compile kcapi-speed test program])], [with_kcapi_speed_test=yes])
AM_CONDITIONAL([ENABLE_KCAPI_SPEED], [test "x$with_kcapi_speed_test" = "xyes"])

AC_ARG_WITH([apps], [AS_HELP_STRING([--with-apps], [Compile all applications])], [with_kcapi_hasher=yes])
AM_CONDITIONAL([ENABLE_KCAPI_HASHER], [test "x$with_kcapi_hasher" = "xyes"])

AC_OUTPUT
