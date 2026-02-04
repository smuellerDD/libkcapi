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
m4_define([__KCAPI_MAJVERSION], [1])
m4_define([__KCAPI_MINVERSION], [5])
m4_define([__KCAPI_PATCHLEVEL], [1])
m4_define([KCAPI_VERSION], [__KCAPI_MAJVERSION.__KCAPI_MINVERSION.__KCAPI_PATCHLEVEL])

AC_INIT([libkcapi], [KCAPI_VERSION])
AC_DEFINE([KCAPI_MAJVERSION], [__KCAPI_MAJVERSION])
AC_DEFINE([KCAPI_MINVERSION], [__KCAPI_MINVERSION])
AC_DEFINE([KCAPI_PATCHLEVEL], [__KCAPI_PATCHLEVEL])
AM_INIT_AUTOMAKE([foreign])
LT_INIT([pic-only])
AC_SUBST([LIBTOOL_DEPS])
AC_PROG_CC
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIR([m4])
AX_PROG_CC_FOR_BUILD
AX_CHECK_PIE

AC_PATH_PROG([OPENSSL], [openssl])
AC_PATH_PROG([CLANG], [clang])
AC_PATH_PROG([CPPCHECK], [cppcheck])
AC_PATH_PROG([XMLTO], [xmlto])
AC_PATH_PROG([DB2PDF], [docbook2pdf])
AC_PATH_PROG([DB2PS], [docbook2ps])
AC_PATH_PROG([MKTEMP], [mktemp])

AC_SEARCH_LIBS(clock_gettime,rt)
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PATH_PROG([CP], [cp])
AC_PATH_PROG([LN], [ln])
AC_PATH_PROG([MV], [mv])
AC_PATH_PROG([TOUCH], [touch])

AM_CONDITIONAL([HAVE_OPENSSL], [test "x$OPENSSL" != "x"])
AM_CONDITIONAL([HAVE_CLANG], [test "x$CLANG" != "x"])
AM_CONDITIONAL([HAVE_CPPCHECK], [test "x$CPPCHECK" != "x"])
AM_CONDITIONAL([HAVE_XMLTO], [test "x$XMLTO" != "x"])
AM_CONDITIONAL([HAVE_DB2PDF], [test "x$DB2PDF" != "x"])
AM_CONDITIONAL([HAVE_DB2PS], [test "x$DB2PS" != "x"])
AM_CONDITIONAL([HAVE_MKTEMP], [test "x$MKTEMP" != "x"])

AM_COND_IF([HAVE_OPENSSL], [], [AC_MSG_WARN([openssl not installed])])
AM_COND_IF([HAVE_CLANG], [], [AC_MSG_WARN([clang not installed])])
AM_COND_IF([HAVE_CPPCHECK], [], [AC_MSG_WARN([cppcheck not installed])])
AM_COND_IF([HAVE_XMLTO], [], [AC_MSG_WARN([xmlto not installed])])
AM_COND_IF([HAVE_DB2PDF], [], [AC_MSG_WARN([db2pdf not installed])])
AM_COND_IF([HAVE_DB2PS], [], [AC_MSG_WARN([db2ps not installed])])
AM_COND_IF([HAVE_MKTEMP], [], [AC_MSG_WARN([mktemp not installed])])

AC_CHECK_FUNCS(getrandom)
AC_CHECK_FUNCS(secure_getenv)

my_cflags="$CFLAGS"
CFLAGS="-Werror -fstack-protector-strong"
AC_MSG_CHECKING([whether CC supports -fstack-protector-strong])
AC_LINK_IFELSE([AC_LANG_PROGRAM([])],
	[AC_MSG_RESULT([yes])]
	CFLAGS="-fstack-protector-strong $my_cflags",
	[AC_MSG_RESULT([no])]
	CFLAGS="$my_cflags")
AX_ADD_FORTIFY_SOURCE

AC_CHECK_API_VERSION

AC_CHECK_ATTRIBUTE_SYMVER

AC_ARG_ENABLE([werror], [AS_HELP_STRING([--disable-werror], [Disable -Werror])], [with_werror=$enableval], [with_werror=yes])
AM_CONDITIONAL([ENABLE_WERROR], [test "x$with_werror" = "xyes"])

AC_ARG_ENABLE([kcapi-test], [AS_HELP_STRING([--enable-kcapi-test], [Compile kcapi test program])], [with_kcapi_test=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_TEST], [test "x$with_kcapi_test" = "xyes"])

AC_ARG_ENABLE([kcapi-speed], [AS_HELP_STRING([--enable-kcapi-speed], [Compile kcapi-speed test program])], [with_kcapi_speed_test=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_SPEED], [test "x$with_kcapi_speed_test" = "xyes"])

AC_ARG_ENABLE([kcapi-hasher], [AS_HELP_STRING([--enable-kcapi-hasher], [Compile hasher application])], [with_kcapi_hasher=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_HASHER], [test "x$with_kcapi_hasher" = "xyes"])

AC_ARG_ENABLE([kcapi-rngapp], [AS_HELP_STRING([--enable-kcapi-rngapp], [Compile rng read application])], [with_kcapi_rngapp=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_RNGAPP], [test "x$with_kcapi_rngapp" = "xyes"])

AC_ARG_ENABLE([kcapi-encapp], [AS_HELP_STRING([--enable-kcapi-encapp], [Compile enc application])], [with_kcapi_encapp=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_ENCAPP], [test "x$with_kcapi_encapp" = "xyes"])

AC_ARG_ENABLE([kcapi-dgstapp], [AS_HELP_STRING([--enable-kcapi-dgstapp], [Compile dgst application])], [with_kcapi_dgstapp=$enableval])
AM_CONDITIONAL([ENABLE_KCAPI_DGSTAPP], [test "x$with_kcapi_dgstapp" = "xyes"])

AC_ARG_ENABLE([lib-kdf], [AS_HELP_STRING([--disable-lib-kdf], [Disable KDF support in library to make it smaller])], [with_lib_kdf=$enableval])
AM_CONDITIONAL([DISABLE_LIB_KDF], [test "x$with_lib_kdf" = "xno"])

AC_ARG_ENABLE([lib-sym], [AS_HELP_STRING([--disable-lib-sym], [Disable symmetric cipher support in library to make it smaller])], [with_lib_sym=$enableval])
AM_CONDITIONAL([DISABLE_LIB_SYM], [test "x$with_lib_sym" = "xno"])

AC_ARG_ENABLE([lib-md], [AS_HELP_STRING([--disable-lib-md], [Disable message digest support in library to make it smaller])], [with_lib_md=$enableval])
AM_CONDITIONAL([DISABLE_LIB_MD], [test "x$with_lib_md" = "xno"])

AC_ARG_ENABLE([lib-aead], [AS_HELP_STRING([--disable-lib-aead], [Disable AEAD cipher support in library to make it smaller])], [with_lib_aead=$enableval])
AM_CONDITIONAL([DISABLE_LIB_AEAD], [test "x$with_lib_aead" = "xno"])

AC_ARG_ENABLE([lib-rng], [AS_HELP_STRING([--disable-lib-rng], [Disable random number generator support in library to make it smaller])], [with_lib_rng=$enableval])
AM_CONDITIONAL([DISABLE_LIB_RNG], [test "x$with_lib_rng" = "xno"])

AC_ARG_ENABLE([lib-asym], [AS_HELP_STRING([--enable-lib-asym], [Enable asymmetric cipher support in library])], [with_lib_asym=$enableval])
AM_CONDITIONAL([ENABLE_LIB_ASYM], [test "x$with_lib_asym" = "xyes"])
if test "$with_lib_asym" = "yes"; then
  AC_DEFINE([WITH_LIB_ASYM], 1, [Asymmetric support enabled])
fi

AC_ARG_ENABLE([lib-kpp], [AS_HELP_STRING([--enable-lib-kpp], [Enable key protocol primitives support in library])], [with_lib_kpp=$enableval])
AM_CONDITIONAL([ENABLE_LIB_KPP], [test "x$with_lib_kpp" = "xyes"])
if test "$with_lib_kpp" = "yes"; then
  AC_DEFINE([WITH_LIB_KPP], 1, [KPP support enabled])
fi

AC_ARG_ENABLE([sum-prefix],
	      AS_HELP_STRING([--enable-sum-prefix=PRE],[prefix to add to filenames when deriving the binary's checksum file's name (default ".")]),
	      if test x$enableval != xno ; then
		  CHECK_PREFIX="$enableval"
	      else
		  CHECK_PREFIX=
	      fi
	      ,CHECK_PREFIX=.)

AC_ARG_ENABLE([sum-suffix],
	      AS_HELP_STRING([--enable-sum-suffix=EXT],[suffix to add to filenames when deriving the binary's checksum file's name (default "hmac")]),
	      if test x$enableval != xno ; then
		  CHECK_SUFFIX="$enableval"
	      else
		  CHECK_SUFFIX=
	      fi
	      ,CHECK_SUFFIX=hmac)

AC_ARG_ENABLE([sum-dir],
	      AS_HELP_STRING([--enable-sum-dir=DIR],[directory where HMAC checksum files will be placed (default: place alongside binaries)]),
	      if test x$enableval != xno ; then
		  CHECK_DIR="$enableval"
	      else
		  CHECK_DIR=
	      fi
	      ,CHECK_DIR=)

AC_SUBST(CHECK_PREFIX)
AC_SUBST(CHECK_SUFFIX)
AC_SUBST(CHECK_DIR)

AC_DEFINE_UNQUOTED(CHECK_PREFIX,"$CHECK_PREFIX",[Define to the prefix which contains the hmac for a binary.])
AC_DEFINE_UNQUOTED(CHECK_SUFFIX,"$CHECK_SUFFIX",[Define to the suffix which contains the hmac for a binary.])
AS_IF([test "x$CHECK_DIR" != "x"], [
	AC_DEFINE_UNQUOTED(CHECK_DIR,"$CHECK_DIR",[Define to the directory which contains the hmac for a binary.])
])

AC_SYS_LARGEFILE
AC_TYPE_OFF_T
AC_FUNC_FSEEKO

PKG_INSTALLDIR
if test "x$pkgconfigdir" = "x"; then
  pkgconfigdir="${libdir}/pkgconfig"
fi
AC_SUBST([pkgconfigdir], [$pkgconfigdir])

AC_CONFIG_FILES([libkcapi.pc])

AC_OUTPUT
