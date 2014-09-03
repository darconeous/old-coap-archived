AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src docs

DISTCLEANFILES = config.log config.status Makefile libtool make.out

EXTRA_DIST = bootstrap.sh README.md NEWS.md

# Metafiles
EXTRA_DIST += .gitignore .uncrustify.cfg .travis.yml

# Make sure the contiki bits make it into the archive.
EXTRA_DIST += contiki-src/examples/smcp-simple/.gitignore contiki-src/examples/smcp-simple/Makefile contiki-src/examples/smcp-simple/smcp-simple.c
EXTRA_DIST += contiki-src/examples/smcp-plugtest/.gitignore contiki-src/examples/smcp-plugtest/Makefile contiki-src/examples/smcp-plugtest/smcp-plugtest.c
EXTRA_DIST += contiki-src/examples/smcp-complex/.gitignore contiki-src/examples/smcp-complex/Makefile contiki-src/examples/smcp-complex/smcp-complex.c
EXTRA_DIST += contiki-src/led-node.c contiki-src/led-node.h contiki-src/Makefile.smcp contiki-src/sensor-node.c contiki-src/sensor-node.h contiki-src/smcp-task.c contiki-src/smcp-task.h

HASH_VERSION=$(shell git describe --dirty --match __poison__ --always 2> /dev/null)
EXTRA_VERSION=$(shell git describe --all --contains 62f798c26a12182abe7e8531606a661ee66baed3 1> /dev/null 2> /dev/null && (test `git describe` = $(VERSION) || echo -g$(HASH_VERSION)))
distdir = $(PACKAGE)-$(VERSION)$(EXTRA_VERSION)

@CODE_COVERAGE_RULES@
