AC_DEFUN([AC_CHECK_API_VERSION],
	 [AC_CHECK_PROG([TAIL], [tail], [yes])
	  AM_CONDITIONAL([CAN_CHECK_API_VERSION], [test "x$TAIL" = "xyes" -a -n $SED])
	  AM_COND_IF([CAN_CHECK_API_VERSION],
         [AC_SUBST([API_VERSION], [$($SED -n 's/^LIBKCAPI_\([[0-9.]]*\) {/\1/p' ${srcdir}/lib/version.lds | tail -1)])
	  AC_MSG_NOTICE([API version=$API_VERSION])
	  AC_MSG_NOTICE([library version=$VERSION])
	  AM_CONDITIONAL([CHECK_VERSION], [test "x$API_VERSION" != "x$VERSION"])
	  AM_COND_IF([CHECK_VERSION], [AC_MSG_ERROR([API version != library version])])],
         [AC_MSG_ERROR([API version != library version ])])])
