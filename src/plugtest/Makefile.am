AM_CPPFLAGS = -I.. -I$(top_srcdir)/src

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS)

if BUILD_PLUGTEST
bin_PROGRAMS = smcp-plugtest-server smcp-plugtest-client
TESTS = selftest.sh
endif

smcp_plugtest_server_SOURCES = main-server.c plugtest-server.c plugtest-server.h
smcp_plugtest_server_LDADD = ../smcp/libsmcp.la

smcp_plugtest_client_SOURCES = main-client.c
smcp_plugtest_client_LDADD = ../smcp/libsmcp.la


TESTS_ENVIRONMENT = builddir='$(builddir)'

EXTRA_DIST = selftest.sh README.md
DISTCLEANFILES = .deps Makefile
