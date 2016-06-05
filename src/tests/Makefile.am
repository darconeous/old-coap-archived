AM_CPPFLAGS = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

noinst_PROGRAMS =

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

noinst_PROGRAMS += test-concurrency
test_concurrency_SOURCES = test-concurrency.c
test_concurrency_LDADD = ../smcp/libsmcp.la

TESTS = test-concurrency

DISTCLEANFILES = .deps Makefile
