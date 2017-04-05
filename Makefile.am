AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src doc

DISTCLEANFILES = config.log config.status Makefile libtool make.out

EXTRA_DIST = bootstrap.sh README.md NEWS.md LICENSE etc/Dockerfile etc/build-in-docker.sh etc/run-in-docker.sh TODO.md CONTRIBUTING.md

# Metafiles
EXTRA_DIST += .gitignore .uncrustify.cfg

HASH_VERSION=$(shell git describe --dirty --match __poison__ --always 2> /dev/null)
EXTRA_VERSION=$(shell git describe --all --contains 62f798c26a12182abe7e8531606a661ee66baed3 1> /dev/null 2> /dev/null && (test `git describe` = $(VERSION) || echo -g$(HASH_VERSION)))
distdir = $(PACKAGE)-$(VERSION)$(EXTRA_VERSION)

@CODE_COVERAGE_RULES@
