AC_DEFUN([AX_CHECK_PIE], [
  AC_ARG_ENABLE([pie], AS_HELP_STRING([--disable-pie], [Disable Position-Independent Executable]), [], [enable_pie=yes])
  AS_IF([test "x$enable_pie" = "xyes"], [
    AC_MSG_CHECKING([if $CC supports PIE])
    BAKLDFLAGS="$LDFLAGS"
    BAKCFLAGS="$CFLAGS"
    LDFLAGS="$LDFLAGS -pie"
    CFLAGS="$CFLAGS -fpie -fPIE -DPIE"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [
      if $CC $CFLAGS $LDFLAGS -o conftest conftest.c 2>&1 | grep "warning: no debug symbols in executable" >/dev/null; then
        LDFLAGS="$BAKLDFLAGS"
        AC_MSG_RESULT(no)
      else
	AC_MSG_RESULT(yes)
      fi
      rm -f conftest conftest.c conftest.o
    ], [LDFLAGS="$BAKLDFLAGS" ; CFLAGS="$BAKCFLAGS" ; AC_MSG_RESULT(no)])
  ])
])
