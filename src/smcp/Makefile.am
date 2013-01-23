INCLUDES =  -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

AUTOMAKE_OPTIONS = subdir-objects

noinst_LIBRARIES = libsmcp.a

libsmcp_a_SOURCES = smcp.c smcp-timer.c coap.c smcp-outbound.c smcp-observable.c smcp-auth.c smcp-transaction.c

libsmcp_a_SOURCES += btree.c url-helpers.c fasthash.c

libsmcp_a_sources += smcp-node.c smcp-list.c

libsmcp_a_SOURCES += smcp-timer_node.c smcp-variable_node.c

libsmcp_a_SOURCES += assert_macros.h btree.h coap.h ll.h smcp-curl_proxy.h smcp-helpers.h smcp-internal.h smcp-logging.h smcp-node.h smcp-opts.h smcp-observable.h smcp-timer.h smcp-timer_node.h smcp-variable_node.h smcp.h url-helpers.h smcp-auth.h smcp-transaction.h fasthash.h

libsmcp_a_LIBADD = $(LIBOBJS) $(ALLOCA)

if HAVE_LIBCURL
libsmcp_a_SOURCES += smcp-curl_proxy.c
endif

DISTCLEANFILES = .deps Makefile

