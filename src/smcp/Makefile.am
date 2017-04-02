
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libsmcp.la

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = -I.. -I$(top_srcdir)/src

libsmcp_la_SOURCES = \
	assert-macros.h \
	smcp-pairing.c smcp-pairing.h \
	smcp-group.c smcp-group.h \
	$(NULL)

pkginclude_HEADERS = \
	smcp.h \
	smcp-pairing.h \
	smcp-defaults.h \
	smcp-group.h \
	$(top_builddir)/src/smcp/smcp-config.h \
	$(NULL)

EXTRA_DIST = smcp-config.h.in

libsmcp_la_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS) $(LIBNYOCI_CFLAGS)
libsmcp_la_LIBADD = $(LIBOBJS) $(ALLOCA) $(PTHREAD_LIBS) $(OPENSSL_LIBS) $(LIBNYOCI_LIBS)
libsmcp_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES) $(LIBNYOCI_INCLUDES) $(MISSING_CPPFLAGS)
libsmcp_la_LDFLAGS = $(AM_LDFLAGS) $(OPENSSL_LDFLAGS) $(LIBNYOCI_LDFLAGS) $(MISSING_LIBADD)

DISTCLEANFILES = .deps Makefile

