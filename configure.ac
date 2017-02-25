
AC_PREREQ(2.59)

AC_INIT([smcp],[0.07.00])

AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_LIBOBJ_DIR([src/missing/])
AC_CONFIG_SRCDIR([src/smcp/smcp.c])
AC_CONFIG_HEADERS([src/config.h src/smcp/smcp-config.h])

SOURCE_VERSION=m4_esyscmd([
	configver="$PACKAGE_VERSION"
	(test -d .git && gitver=`git describe --dirty` && printf "$gitver") ||
	(test -d .git && gitver=`git describe --always` && printf "$configver-g$gitver") ||
	printf "$configver"
])


AM_INIT_AUTOMAKE()

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_GNU_SOURCE
AC_LIBTOOL_DLOPEN_SELF
AC_PROG_LIBTOOL
LT_INIT

AC_DEFINE_UNQUOTED([SOURCE_VERSION], ["`eval echo "$SOURCE_VERSION"`"], [Source version])

m4_ifdef([AX_CODE_COVERAGE], [AX_CODE_COVERAGE], [AC_SUBST([CODE_COVERAGE_RULES])])

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
AC_SUBST(LOAD_ALL_SYMBOLS_FLAG)

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
            [enable compiling with debugging information]), [
    if (test "${enableval}" = "yes" &&
                test "${ac_cv_prog_cc_g}" = "yes"); then
        CFLAGS="$CFLAGS -g -DDEBUG=1"
        CXXFLAGS="$CXXFLAGS -g -DDEBUG=1"
    fi
    if (test "${enableval}" = "verbose" &&
                test "${ac_cv_prog_cc_g}" = "yes"); then
        CFLAGS="$CFLAGS -g -DDEBUG=1 -DVERBOSE_DEBUG=1"
        CXXFLAGS="$CXXFLAGS -g -DDEBUG=1 -DVERBOSE_DEBUG=1"
    fi
])


AC_ARG_ENABLE(embedded, AC_HELP_STRING([--enable-embedded], [enable embedded mode (instance is singleton)]), [])
AC_ARG_ENABLE(examples, AC_HELP_STRING([--disable-examples], [Disable building examples and plugtests]), [])
AC_ARG_ENABLE(smcpctl, AC_HELP_STRING([--disable-smcpctl], [Disable building smcpctl]), [])
AC_ARG_ENABLE(smcpd, AC_HELP_STRING([--disable-smcpd], [Disable building smcpd]), [])
AC_ARG_ENABLE(plugtest, AC_HELP_STRING([--disable-plugtest], [Disable building plugtest]), [])
AC_ARG_ENABLE(dtls, AC_HELP_STRING([--enable-dtls], [Enable experimental DTLS support]), [])

case "${enable_dtls-no}" in
	no)  SMCP_DTLS=0 ;;
	yes) SMCP_DTLS=1 ;;
	*)   AC_MSG_ERROR([Invalid value ${enableval} for --enable-dtls]) ;;
esac

if test "${enable_embedded}" = "yes"
then
	SMCP_EMBEDDED=1
	SMCP_USE_BSD_SOCKETS=${SMCP_USE_BSD_SOCKETS-1}
	SMCP_CONF_NODE_ROUTER=${SMCP_CONF_NODE_ROUTER-1}
	enable_smcpctl=${enable_smcpctl-no}
	enable_smcpd=${enable_smcpd-no}
fi

AM_CONDITIONAL([BUILD_EXAMPLES],test "${enable_examples}" != "no")
AM_CONDITIONAL([BUILD_SMCPCTL],test "${enable_smcpctl}" != "no")
AM_CONDITIONAL([BUILD_SMCPD],test "${enable_smcpd}" != "no")
AM_CONDITIONAL([BUILD_PLUGTEST],test "${enable_plugtest}" != "no")

AC_ARG_WITH(address-family, AC_HELP_STRING([--with-address-family=[inet|inet6]],
            [Specify address family (inet6 is the default)]), [
    if test "${withval}" = "inet"
	then SMCP_BSD_SOCKETS_NET_FAMILY=AF_INET
	     SMCP_USE_BSD_SOCKETS=1
    elif test "${withval}" = "inet6"
	then SMCP_BSD_SOCKETS_NET_FAMILY=AF_INET6
	     SMCP_USE_BSD_SOCKETS=1
	else AC_MSG_ERROR(["Unknown family '${withval}'"])
    fi
])

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
		AC_CACHE_CHECK([libedit rl_completion_entry_function bug], rl_cv_libedit_completion_entry_bug,
		tmp_CFLAGS="${CFLAGS}"
		CFLAGS+=" -Werror"
		AC_TRY_COMPILE(
			[
			#include <stdio.h>
			#include <readline/readline.h>
			],
			[
			const char *res = (*rl_completion_entry_function)(0,0);
			],
			[rl_cv_libedit_completion_entry_bug=no],
			[
			rl_cv_libedit_completion_entry_bug=yes
					AC_DEFINE_UNQUOTED([HAS_LIBEDIT_COMPLETION_ENTRY_BUG], [1],
									   [rl_completion_entry_function has the wrong return type])
			],
			)
		)
		CFLAGS="${tmp_CFLAGS}"
	fi
fi
AM_CONDITIONAL([HAVE_LIBREADLINE],$HAVE_LIBREADLINE)
AC_CHECK_FUNCS([rl_set_prompt])

AX_PTHREAD

if test "${SMCP_DTLS}" == "1"
then
enable_dtls=yes
AX_CHECK_OPENSSL([
	SMCP_DTLS=1
	SMCP_DTLS_OPENSSL=1

	AC_DEFINE_UNQUOTED([HAVE_OPENSSL],[1],[Set if OpenSSL is present])

	tmp_LIBS="${LIBS}"
	LIBS="${OPENSSL_LIBS}"
	AC_CHECK_FUNC([DTLSv1_method],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_DTLSV1_METHOD],[1],[Set if OpenSSL has DTLSv1_method()])])
	AC_CHECK_FUNC([DTLS_method],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_DTLS_METHOD],[1],[Set if OpenSSL has DTLS_method()])])
	AC_CHECK_FUNC([SSL_CONF_CTX_new],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_SSL_CONF_CTX_NEW],[1],[Set if OpenSSL has SSL_CONF_CTX_new()])])
	AC_CHECK_FUNC([SSL_CONF_finish],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_SSL_CONF_FINISH],[1],[Set if OpenSSL has SSL_CONF_finish()])])

	LIBS="${tmp_LIBS}"
],[
	SMCP_DTLS_OPENSSL=0
])
fi

if test "${SMCP_DTLS}" == "1" && test "${SMCP_DTLS_OPENSSL-0}" == "0"
then AC_MSG_ERROR(["DTLS was enabled, but couldn't find OpenSSL"])
fi

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
AC_CHECK_FUNCS([alloca memcmp memset strtol strdup strndup strlcpy strlcat stpncpy vsnprintf vsprintf snprintf getloadavg])

AC_REPLACE_FUNCS([getline])

AM_CONDITIONAL([HAVE_GE_RS232],[test "$smcp_cv_have_ge_rs232" = yes])

if test "${SMCP_EMBEDDED+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_EMBEDDED], [$SMCP_EMBEDDED], [.])
fi
if test "${SMCP_CONF_NODE_ROUTER+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_CONF_NODE_ROUTER], [$SMCP_CONF_NODE_ROUTER], [.])
fi
if test "${SMCP_DTLS+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_DTLS], [$SMCP_DTLS], [.])
fi
if test "${SMCP_DTLS_OPENSSL+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_DTLS_OPENSSL], [$SMCP_DTLS_OPENSSL], [.])
fi
if test "${SMCP_USE_BSD_SOCKETS+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_USE_BSD_SOCKETS], [$SMCP_USE_BSD_SOCKETS], [.])
fi
if test "${SMCP_USE_UIP+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_USE_UIP], [$SMCP_USE_UIP], [.])
fi
if test "${SMCP_BSD_SOCKETS_NET_FAMILY+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_BSD_SOCKETS_NET_FAMILY], [$SMCP_BSD_SOCKETS_NET_FAMILY], [.])
fi
if test "${SMCP_AVOID_MALLOC+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_AVOID_MALLOC], [$SMCP_AVOID_MALLOC], [.])
fi
if test "${SMCP_AVOID_PRINTF+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_AVOID_PRINTF], [$SMCP_AVOID_PRINTF], [.])
fi
if test "${SMCP_MAX_VHOSTS+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_MAX_VHOSTS], [$SMCP_MAX_VHOSTS], [.])
fi
if test "${SMCP_CONF_TRANS_ENABLE_BLOCK2+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_CONF_TRANS_ENABLE_BLOCK2], [$SMCP_CONF_TRANS_ENABLE_BLOCK2], [.])
fi
if test "${SMCP_CONF_TRANS_ENABLE_OBSERVING+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_CONF_TRANS_ENABLE_OBSERVING], [$SMCP_CONF_TRANS_ENABLE_OBSERVING], [.])
fi
if test "${SMCP_MAX_OBSERVERS+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_MAX_OBSERVERS], [$SMCP_MAX_OBSERVERS], [.])
fi
if test "${SMCP_CONF_NODE_ROUTER+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_CONF_NODE_ROUTER], [$SMCP_CONF_NODE_ROUTER], [.])
fi
if test "${SMCP_USE_CASCADE_COUNT+set}" = "set"
then AC_DEFINE_UNQUOTED([SMCP_USE_CASCADE_COUNT], [$SMCP_USE_CASCADE_COUNT], [.])
fi

AC_CONFIG_FILES(
	Makefile
	src/smcpd/smcpd.conf
	doxygen.cfg
	src/Makefile
	docs/Makefile
	src/plugtest/Makefile
	src/smcp/Makefile
	src/smcpctl/Makefile
	src/smcpd/Makefile
	src/examples/Makefile
	src/tests/Makefile
)

AC_OUTPUT

echo ""
echo "= Summary ====================================================================="
echo ""
echo "Building smcpctl ............... ${enable_smcpctl-yes}"
echo "Building smcpd ................. ${enable_smcpd-yes}"
echo "Building examples .............. ${enable_examples-yes}"
echo "Building plugtest .............. ${enable_plugtest-yes}"
echo "Embedded mode .................. ${enable_embedded-no}"
echo "DTLS Support ................... ${enable_dtls-no}"
echo ""

$HAVE_LIBREADLINE ||
	echo "warning: libreadline was disabled or not found, interactive smcpctl command line interface will not be enabled."


