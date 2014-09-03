AM_CPPFLAGS = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS)

bin_PROGRAMS = smcp-plugtest-server

smcp_plugtest_server_SOURCES = main-server.c plugtest-server.c plugtest-server.h
smcp_plugtest_server_LDADD = ../smcp/libsmcp.la

bin_PROGRAMS += smcp-plugtest-client
smcp_plugtest_client_SOURCES = main-client.c
smcp_plugtest_client_LDADD = ../smcp/libsmcp.la

TESTS = selftest.sh

EXTRA_DIST = selftest.sh
DISTCLEANFILES = .deps Makefile
