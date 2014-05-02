INCLUDES =  -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

AUTOMAKE_OPTIONS = subdir-objects

noinst_LIBRARIES = libsmcp.a

libsmcp_a_SOURCES = smcp.c smcp-timer.c coap.c smcp-outbound.c smcp-inbound.c smcp-observable.c smcp-auth.c smcp-transaction.c

libsmcp_a_SOURCES += smcp-plat-bsd.c

libsmcp_a_SOURCES += btree.c url-helpers.c fasthash.c

libsmcp_a_SOURCES += smcp-node-router.c smcp-node-router.h smcp-list.c

#libsmcp_a_SOURCES += smcp-timer_node.c smcp-timer_node.h

libsmcp_a_SOURCES += smcp-variable_node.c smcp-variable_node.h

libsmcp_a_SOURCES += assert-macros.h btree.h coap.h ll.h smcp-curl_proxy.h smcp-helpers.h smcp-internal.h smcp-logging.h smcp-opts.h smcp-observable.h smcp-timer.h smcp.h url-helpers.h smcp-auth.h smcp-transaction.h fasthash.h smcp-plat-bsd.h

EXTRA_DIST = smcp-plat-bsd-internal.h smcp-plat-uip-internal.h smcp-plat-uip-internal.c

libsmcp_a_LIBADD = $(LIBOBJS) $(ALLOCA)

if HAVE_LIBCURL
libsmcp_a_SOURCES += smcp-curl_proxy.c
endif

noinst_PROGRAMS = btreetest
btreetest_SOURCES = btree.c
btreetest_CFLAGS = -DBTREE_SELF_TEST=1

DISTCLEANFILES = .deps Makefile

TESTS = btreetest
