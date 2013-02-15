
AC_PREREQ(2.59)

AC_INIT([smcp],[0.6.1])

AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_LIBOBJ_DIR([src/missing/])

AM_INIT_AUTOMAKE()
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
AC_CONFIG_HEADERS([src/config.h])

AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
HAVE_LIBCURL=false
AC_ARG_ENABLE(libcurl,
    [  --disable-libcurl  Do not use libcurl],
	smcp_check_for_libcurl="$enableval",
	smcp_check_for_libcurl=yes
)
if test x"$smcp_check_for_libcurl" = xyes
then
	AC_CHECK_HEADER([curl/curl.h],AC_CHECK_LIB([curl],[curl_multi_perform]))
	if test "x$ac_cv_lib_curl_curl_multi_perform" = xyes; then :
		HAVE_LIBCURL=true
	fi
fi
AM_CONDITIONAL([HAVE_LIBCURL],$HAVE_LIBCURL)

HAVE_LIBREADLINE=false
AC_ARG_ENABLE(libreadline,
    [  --disable-libreadline  Do not use libreadline],
	smcp_check_for_libreadline="$enableval",
	smcp_check_for_libreadline=yes
)
if test x"$smcp_check_for_libreadline" = xyes; then :
	AC_CHECK_HEADER([readline/readline.h],AC_CHECK_LIB([readline], [readline]))
	if test "x$ac_cv_lib_readline_readline" = xyes; then :
		HAVE_LIBREADLINE=true
	fi
fi
AM_CONDITIONAL([HAVE_LIBREADLINE],$HAVE_LIBREADLINE)
AC_CHECK_FUNCS([rl_set_prompt])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h dlfcn.h unistd.h string.h stdio.h errno.h stdarg.h stddef.h stdint.h stdbool.h])

HAVE_LIBDL=false
AC_ARG_ENABLE(libdl,
    [  --disable-libdl  Do not use libdl],
	smcp_check_for_libdl="$enableval",
	smcp_check_for_libdl=yes
)
if test x"$smcp_check_for_libdl" = xyes; then :
	AC_CHECK_HEADER([dlfcn.h],AC_CHECK_LIB([dl], [dlsym]))
	if test "x$ac_cv_lib_readline_readline" = xyes; then :
		HAVE_LIBDL=true
	fi
fi
AM_CONDITIONAL([HAVE_LIBDL],$HAVE_LIBDL)

AC_CHECK_HEADERS([alloca.h])
AC_HEADER_TIME

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_C_INLINE
AC_C_VOLATILE

# Checks for library functions.
AC_CHECK_FUNCS([alloca memcmp memset strtol strdup strndup strlcpy strlcat stpncpy vsnprintf vsprintf snprintf])

AC_REPLACE_FUNCS([getline])

dnl AC_CACHE_CHECK([for ge_rs232],[smcp_cv_have_ge_rs232],[
dnl 	smcp_cv_have_ge_rs232=no
dnl 	test -f "${srcdir}/../ge-rs232/ge-system-node.c" && smcp_cv_have_ge_rs232=yes
dnl ])
AM_CONDITIONAL([HAVE_GE_RS232],[test "$smcp_cv_have_ge_rs232" = yes])

AC_CONFIG_FILES(Makefile src/smcpd/smcpd.conf doxygen.cfg src/Makefile docs/Makefile src/plugtest/Makefile src/smcp/Makefile src/smcpctl/Makefile src/smcpd/Makefile src/examples/Makefile)
AC_OUTPUT

$HAVE_LIBREADLINE || echo "warning: libreadline was disabled or not found, interactive smcpctl command line interface will not be enabled."
$HAVE_LIBDL || echo "warning: libdl was disabled or not found, smcpd will not be built."

