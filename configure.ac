
AC_PREREQ(2.59)



AC_INIT([smcp],[0.5])
AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
LT_INIT()

AC_LIBTOOL_DLOPEN_SELF
AC_PROG_LIBTOOL
#eval `libtool --tag=CC --config|grep '^wl='`

AC_CACHE_CHECK([for -rdynamic linker flag],[lt_cv_ld_rdynamic],[
	lt_cv_ld_rdynamic=no
	cat > conftest2.c << _LT_EOF
int symbol_to_look_for() { return 2;}
_LT_EOF
	echo "$LTCC $LTCFLAGS -c -o conftest2.o conftest2.c" >&AS_MESSAGE_LOG_FD
	$LTCC $LTCFLAGS -c -o conftest2.o conftest2.c 2>&AS_MESSAGE_LOG_FD
	cat > conftest.c << _LT_EOF
int main() { return 0;}
_LT_EOF
	cmd="$LTCC $LTCFLAGS $LDFLAGS -o conftest conftest.c -rdynamic conftest2.o"
	echo "$cmd" >&AS_MESSAGE_LOG_FD
	eval "$cmd" 2>conftest.err
	_lt_result=$?
	if test -f conftest && test ! -s conftest.err && test $_lt_result = 0 && $GREP symbol_to_look_for conftest 2>&1 >/dev/null; then
		lt_cv_ld_rdynamic=yes
	else
		cat conftest.err >&AS_MESSAGE_LOG_FD
	fi
	rm -f conftest.err libconftest.a conftest conftest.c conftest2.c conftest2.o
	rm -rf conftest.dSYM
])

AC_CACHE_CHECK([for -all_load linker flag],[lt_cv_ld_all_load],[
	lt_cv_ld_all_load=no
	cat > conftest.c << _LT_EOF
int symbol_to_look_for() { return 2;}
_LT_EOF
	echo "$LTCC $LTCFLAGS -c -o conftest.o conftest.c" >&AS_MESSAGE_LOG_FD
	$LTCC $LTCFLAGS -c -o conftest.o conftest.c 2>&AS_MESSAGE_LOG_FD
	echo "$AR cru libconftest.a conftest.o" >&AS_MESSAGE_LOG_FD
	$AR cru libconftest.a conftest.o 2>&AS_MESSAGE_LOG_FD
	echo "$RANLIB libconftest.a" >&AS_MESSAGE_LOG_FD
	$RANLIB libconftest.a 2>&AS_MESSAGE_LOG_FD
	cat > conftest.c << _LT_EOF
int main() { return 0;}
_LT_EOF
	cmd="$LTCC $LTCFLAGS $LDFLAGS -o conftest conftest.c -all_load libconftest.a"
	echo "$cmd" >&AS_MESSAGE_LOG_FD
	eval "$cmd" 2>conftest.err
	_lt_result=$?
	if test -f conftest && test ! -s conftest.err && test $_lt_result = 0 && $GREP symbol_to_look_for conftest 2>&1 >/dev/null; then
		lt_cv_ld_all_load=yes
	else
		cat conftest.err >&AS_MESSAGE_LOG_FD
	fi
	 rm -f conftest.err libconftest.a conftest conftest.c
	 rm -rf conftest.dSYM
])

LOAD_ALL_SYMBOLS_FLAG=
if test "$lt_cv_ld_all_load" = yes ; then
	LOAD_ALL_SYMBOLS_FLAG='-all_load'
elif test "$lt_cv_ld_rdynamic" = yes ; then
	LOAD_ALL_SYMBOLS_FLAG='-rdynamic' #' -Wl,--whole-archive'
fi
dnl echo LOAD_ALL_SYMBOLS_FLAG = $LOAD_ALL_SYMBOLS_FLAG
AC_SUBST(LOAD_ALL_SYMBOLS_FLAG)

AC_CONFIG_SRCDIR([src/smcp/smcp.c])
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
AC_CHECK_HEADERS([stdlib.h unistd.h string.h stdio.h errno.h stdarg.h stddef.h stdint.h])

AC_CHECK_HEADERS([alloca.h])
AC_FUNC_ALLOCA
dnl AC_FUNC_GETLOADAVG
AC_CHECK_HEADER_STDBOOL
AC_HEADER_TIME

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_C_INLINE
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([memset])




AC_CACHE_CHECK([for ge_rs232],[smcp_cv_have_ge_rs232],[
	smcp_cv_have_ge_rs232=no
	test -f "${srcdir}/../ge-rs232/ge-system-node.c" && smcp_cv_have_ge_rs232=yes
])
AM_CONDITIONAL([HAVE_GE_RS232],[test "$smcp_cv_have_ge_rs232" = yes])

AC_CONFIG_FILES(Makefile src/smcpd/smcpd.conf src/Makefile docs/Makefile src/smcp/Makefile src/smcpctl/Makefile src/smcpd/Makefile)
AC_OUTPUT
