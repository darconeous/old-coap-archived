
AUTOMAKE_OPTIONS = subdir-objects

lib_LTLIBRARIES = libsmcp.la

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = -I.. -I$(top_srcdir)/src

libsmcp_la_SOURCES = \
	smcp.c \
	smcp-timer.c \
	coap.c coap.h \
	smcp-outbound.c \
	smcp-inbound.c \
	smcp-observable.c \
	smcp-transaction.c \
	smcp-dupe.c \
	smcp-missing.c \
	smcp-session.c \
	smcp-async.c \
	$(NULL)

libsmcp_la_SOURCES += \
	smcp-plat-bsd.c \
	smcp-plat-openssl.c \
	smcp-plat-openssl.h \
	$(NULL)

libsmcp_la_SOURCES += \
	btree.c btree.h \
	ll.h \
	url-helpers.c \
	fasthash.c \
	string-utils.c \
	$(NULL)

libsmcp_la_SOURCES += \
	smcp-helpers.h \
	smcp-internal.h \
	smcp-logging.h \
	url-helpers.h \
	fasthash.h \
	smcp-dupe.h \
	string-utils.h \
	smcp-missing.h \
	smcp-async.h \
	smcp-defaults.h \
	assert-macros.h \
	$(NULL)

pkginclude_HEADERS = \
	smcp-timer.h \
	smcp.h \
	smcp-transaction.h \
	smcp-opts.h \
	smcp-observable.h \
	btree.h \
	coap.h \
	ll.h \
	smcp-helpers.h \
	smcp-session.h \
	smcp-async.h \
	smcp-defaults.h \
	smcp-plat.h \
	smcp-plat-bsd.h \
	smcp-plat-ssl.h \
	$(top_builddir)/src/smcp/smcp-config.h \
	$(NULL)

# Extras
libsmcp_la_SOURCES += \
	smcp-node-router.c smcp-node-router.h \
	smcp-list.c \
	smcp-variable_handler.c smcp-variable_handler.h \
	smcp-pairing.c smcp-pairing.h \
	smcp-group.c smcp-group.h \
	$(NULL)

pkginclude_HEADERS += \
	smcp-node-router.h \
	smcp-variable_handler.h \
	smcp-pairing.h \
	smcp-group.h \
	$(NULL)

EXTRA_DIST = smcp-config.h.in smcp-plat-bsd-internal.h smcp-plat-uip-internal.h smcp-plat-uip.c smcp-plat-uip.h

libsmcp_la_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
libsmcp_la_LIBADD = $(LIBOBJS) $(ALLOCA) $(PTHREAD_LIBS) $(OPENSSL_LIBS)
libsmcp_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)
libsmcp_la_LDFLAGS = $(AM_LDFLAGS) $(OPENSSL_LDFLAGS)


if HAVE_LIBCURL
libsmcp_la_SOURCES += smcp-curl_proxy.c
pkginclude_HEADERS +=  smcp-curl_proxy.h
endif

check_PROGRAMS = btreetest
btreetest_SOURCES = btree.c
btreetest_CFLAGS = $(AM_CFLAGS) -DBTREE_SELF_TEST=1

DISTCLEANFILES = .deps Makefile

TESTS = btreetest
