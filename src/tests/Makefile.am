AM_CPPFLAGS = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

check_PROGRAMS =

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

#check_PROGRAMS += test-concurrency
#test_concurrency_SOURCES = test-concurrency.c
#test_concurrency_LDADD = ../libsmcp/libsmcp.la

#TESTS = test-concurrency

DISTCLEANFILES = .deps Makefile
