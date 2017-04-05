
AM_CPPFLAGS = $(CPPFLAGS) -I.. -I$(top_srcdir)/src

if HAVE_LIBDL
AM_LDFLAGS = $(LDFLAGS) -export-dynamic $(LOAD_ALL_SYMBOLS_FLAG)
endif

if BUILD_SMCPD
bin_PROGRAMS = smcpd
sysconf_DATA = smcpd.conf
endif

smcpd_SOURCES = main.c help.h
smcpd_SOURCES += cgi-node.c cgi-node.h
smcpd_SOURCES += system-node.c system-node.h
smcpd_SOURCES += ud-var-node.c ud-var-node.h
smcpd_SOURCES += pairing-node.c pairing-node.h
smcpd_SOURCES += group-node.c group-node.h
smcpd_LDADD = $(AM_LDADD) ../smcp/libsmcp.la $(LIBNYOCI_LIBS) $(MISSING_LIBADD)
smcpd_CFLAGS = $(AM_CFLAGS) $(LIBNYOCI_CFLAGS)
smcpd_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES) $(LIBNYOCI_CPPFLAGS) -DASSERT_MACROS_USES_SYSLOG=1 $(MISSING_CPPFLAGS)


DISTCLEANFILES = .deps Makefile

