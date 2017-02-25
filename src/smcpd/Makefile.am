
AM_CPPFLAGS = -I.. -I$(top_srcdir)/src

if HAVE_LIBDL
AM_LDFLAGS = -export-dynamic @LOAD_ALL_SYMBOLS_FLAG@
endif

CFLAGS += -DASSERT_MACROS_USES_SYSLOG=1

if BUILD_SMCPD
bin_PROGRAMS = smcpd
endif

smcpd_SOURCES = main.c help.h
smcpd_SOURCES += cgi-node.c cgi-node.h
smcpd_SOURCES += system-node.c system-node.h
smcpd_SOURCES += ud-var-node.c ud-var-node.h
smcpd_SOURCES += pairing-node.c pairing-node.h
smcpd_SOURCES += group-node.c group-node.h
smcpd_LDADD = ../smcp/libsmcp.la

smcpd_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)

# Commented out for now, until we get configuration directory support added.
#sysconf_DATA = smcpd.conf

DISTCLEANFILES = .deps Makefile

