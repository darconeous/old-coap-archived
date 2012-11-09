INCLUDES =  -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

noinst_LTLIBRARIES = libsmcp.la

libsmcp_la_SOURCES = smcp.c smcp-list.c smcp-send.c smcp-node.c smcp-pairing.c btree.c url-helpers.c coap.c smcp-timer.c smcp-timer_node.c smcp-variable_node.c
libsmcp_la_SOURCES += assert_macros.h btree.h coap.h ll.h smcp-curl_proxy.h smcp-helpers.h smcp-internal.h smcp-logging.h smcp-node.h smcp-opts.h smcp-pairing.h smcp-timer.h smcp-timer_node.h smcp-variable_node.h smcp.h url-helpers.h

if HAVE_LIBCURL
#libsmcp_la_LIBADD = curl
libsmcp_la_SOURCES += smcp-curl_proxy.c
endif



DISTCLEANFILES = .deps Makefile

