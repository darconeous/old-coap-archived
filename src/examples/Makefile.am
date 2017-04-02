AM_CPPFLAGS = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = @CFLAGS@ $(CODE_COVERAGE_CFLAGS)

#if BUILD_EXAMPLES
#noinst_PROGRAMS = \
#	example-1 \
#	$(NULL)
#endif

#example_1_SOURCES = example-1.c
#example_1_LDADD = ../smcp/libsmcp.la $(NYOCI_LIBS)
#example_1_CFLAGS = $(AM_CFLAGS) $(NYOCI_CFLAGS)

DISTCLEANFILES = .deps Makefile
