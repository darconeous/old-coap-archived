AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src docs

DISTCLEANFILES = config.log config.status Makefile libtool make.out

EXTRA_DIST = bootstrap.sh README.md TODO.md

# Metafiles
EXTRA_DIST += .gitignore .uncrustify.cfg

# Make sure the contiki bits make it into the archive.
EXTRA_DIST += contiki-src/examples/smcp-simple/.gitignore contiki-src/examples/smcp-simple/Makefile contiki-src/examples/smcp-simple/smcp-simple.c contiki-src/examples/smcp-test/.gitignore contiki-src/examples/smcp-test/Makefile contiki-src/examples/smcp-test/smcp-test.c contiki-src/led-node.c contiki-src/led-node.h contiki-src/Makefile.smcp contiki-src/sensor-node.c contiki-src/sensor-node.h contiki-src/smcp-task.c contiki-src/smcp-task.h

