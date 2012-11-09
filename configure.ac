
AC_PREREQ(2.59)



AC_INIT([smcp],[0.5])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
LT_INIT()


AC_CONFIG_SRCDIR([src/])
AM_CONFIG_HEADER([src/config.h])

AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([curl], [curl_multi_perform],, )
AC_CHECK_LIB([readline], [readline],, )

AM_CONDITIONAL([HAVE_LIBCURL],$HAVE_LIBCURL)
AM_CONDITIONAL([HAVE_LIBREADLINE],$HAVE_LIBREADLINE)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h unistd.h string.h stdio.h errno.h stdbool.h stdarg.h stddef.h stdint.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES(Makefile src/smcpd/smcpd.conf src/Makefile docs/Makefile src/smcp/Makefile src/smcpctl/Makefile src/smcpd/Makefile)
AC_OUTPUT
