AM_CPPFLAGS = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = @CFLAGS@ $(CODE_COVERAGE_CFLAGS)

if BUILD_EXAMPLES
noinst_PROGRAMS = \
	example-1 \
	example-2 \
	example-3 \
	example-4 \
	example-multicast-request \
	$(NULL)
endif

example_1_SOURCES = example-1.c
example_1_LDADD = ../smcp/libsmcp.la

example_2_SOURCES = example-2.c
example_2_LDADD = ../smcp/libsmcp.la

example_3_SOURCES = example-3.c
example_3_LDADD = ../smcp/libsmcp.la

example_4_SOURCES = example-4.c
example_4_LDADD = ../smcp/libsmcp.la

example_multicast_request_SOURCES = example-multicast-request.c
example_multicast_request_LDADD = ../smcp/libsmcp.la

DISTCLEANFILES = .deps Makefile
