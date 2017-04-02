
AC_PREREQ(2.59)

AC_INIT([smcp],[0.10.00a])

AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_LIBOBJ_DIR([src/missing/])
AC_CONFIG_SRCDIR([src/smcp/smcp.h])
AC_CONFIG_HEADERS([src/config.h src/smcp/smcp-config.h])

SOURCE_VERSION=m4_esyscmd([
	configver="$PACKAGE_VERSION"
	(test -d .git && gitver=`git describe --dirty` && printf "$gitver") ||
	(test -d .git && gitver=`git describe --always` && printf "$configver-g$gitver") ||
	printf "$configver"
])

AM_INIT_AUTOMAKE()

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AX_CODE_COVERAGE], [AX_CODE_COVERAGE], [AC_SUBST([CODE_COVERAGE_RULES])])

AC_GNU_SOURCE
AC_LIBTOOL_DLOPEN_SELF
AC_PROG_LIBTOOL
LT_INIT

AC_DEFINE_UNQUOTED([SOURCE_VERSION], ["`eval echo "$SOURCE_VERSION"`"], [Source version])

# Checks for programs.
AC_PROG_CC
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([LIBNYOCI],[libnyoci, libnyociextra],[],[
	AC_MSG_ERROR([Unable to find libnyoci and/or libnyociextra])
])


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

AC_ARG_ENABLE(examples, AC_HELP_STRING([--disable-examples], [Disable building examples]))
AC_ARG_ENABLE(smcpd, AC_HELP_STRING([--disable-smcpd], [Disable building smcpd]))

AM_CONDITIONAL([BUILD_EXAMPLES],[test "${enable_examples}" != "no"])
AM_CONDITIONAL([BUILD_SMCPD],[test "${enable_smcpd}" != "no"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h dlfcn.h unistd.h string.h stdio.h errno.h stdarg.h stddef.h stdint.h stdbool.h])

AC_ARG_WITH(libdl,AC_HELP_STRING([--without-libdl],[Do not use libdl]))
AS_IF([test "${with_libdl}" != no],[
	AC_CHECK_HEADER([dlfcn.h],AC_CHECK_LIB([dl], [dlsym], [],[
		AS_IF([test "${with_libdl}" != yes],[
			with_libdl=no
		],[
			AC_MSG_ERROR([could not find libdl])
		])
	]))
])
AM_CONDITIONAL([HAVE_LIBDL],[test "${with_libdl}" != "no"])

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

dnl ###########################################################################

AC_DEFUN([REPLACE_MISSING_FUNC], [
    AC_CHECK_FUNC($1, [], [
        nl_cv_missing_$1=yes
        MISSING_CPPFLAGS="${MISSING_CPPFLAGS} "'-include $(top_srcdir)/src/missing/$1/$1.h'
        MISSING_LIBADD="${MISSING_LIBADD} "'$(top_builddir)/src/missing/$1/lib$1.la'
    ])
    AM_CONDITIONAL(m4_toupper(MISSING_$1), [test "${nl_cv_missing_$1}" = "yes"])
])
AC_SUBST(MISSING_CPPFLAGS)
AC_SUBST(MISSING_LIBADD)

REPLACE_MISSING_FUNC([strlcpy])
REPLACE_MISSING_FUNC([strlcat])

dnl ###########################################################################

AC_CONFIG_FILES(
	Makefile
	doxygen.cfg
	src/Makefile
	doc/Makefile
	src/smcp/Makefile
	src/smcpd/Makefile
	src/smcpd/smcpd.conf
	src/examples/Makefile
	src/tests/Makefile
	src/missing/Makefile
	src/missing/strlcat/Makefile
	src/missing/strlcpy/Makefile
)

AC_OUTPUT

echo ""
echo "= Summary ====================================================================="
echo ""
echo "Building smcpd ................. ${enable_smcpd-yes}"
echo "Building examples .............. ${enable_examples-yes}"
echo ""



