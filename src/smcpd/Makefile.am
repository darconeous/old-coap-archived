INCLUDES = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

AM_LDFLAGS = @LDFLAGS@ -all_load

bin_PROGRAMS = smcpd

smcpd_SOURCES = main.c system-node.c
smcpd_SOURCES += help.h
smcpd_LDADD = ../smcp/libsmcp.la

# Commented out for now, until we get configuration directory support added.
#sysconf_DATA = smcpd.conf

DISTCLEANFILES = .deps Makefile

