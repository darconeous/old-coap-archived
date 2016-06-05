SUBDIRS = smcp smcpctl smcpd plugtest examples tests
DISTCLEANFILES = .deps Makefile

EXTRA_DIST = missing/fgetln.h missing/fls.h

@CODE_COVERAGE_RULES@
AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

EXTRA_DIST += version.c.in version.h
CLEANFILES = $(top_builddir)/$(subdir)/version.c
SOURCE_VERSION=$(shell git describe --dirty --always --match "[0-9].*" 2> /dev/null)
BUILT_SOURCES  = $(top_builddir)/$(subdir)/version.c
.INTERMEDIATE: $(top_builddir)/$(subdir)/version.c
$(top_builddir)/$(subdir)/version.c: version.c.in Makefile
	sed 's/SOURCE_VERSION/"$(SOURCE_VERSION)"/' < $< > $@
