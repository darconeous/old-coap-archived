INCLUDES = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

AM_LDFLAGS = -export-dynamic @LOAD_ALL_SYMBOLS_FLAG@

CFLAGS += -DASSERT_MACROS_USES_SYSLOG=1

bin_PROGRAMS = smcpd

smcpd_SOURCES = main.c system-node.c cgi-node.c
smcpd_SOURCES += help.h
smcpd_LDADD = ../smcp/libsmcp.a

if HAVE_GE_RS232
smcpd_LDADD += ge-rs232.o ge-system-node.o

ge-rs232.o: $(top_srcdir)/../ge-rs232/ge-rs232.c
@am__fastdepCC_TRUE@	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/`basename $*`.Tpo -c -o $@ $<
@am__fastdepCC_TRUE@	$(am__mv) $(DEPDIR)/`basename $*`.Tpo $(DEPDIR)/`basename $*`.Po
@AMDEP_TRUE@@am__fastdepCC_FALSE@	source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
@AMDEP_TRUE@@am__fastdepCC_FALSE@	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
@am__fastdepCC_FALSE@	$(COMPILE) -c $<

ge-system-node.o: $(top_srcdir)/../ge-rs232/ge-system-node.c
@am__fastdepCC_TRUE@	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/`basename $*`.Tpo -c -o $@ $<
@am__fastdepCC_TRUE@	$(am__mv) $(DEPDIR)/`basename $*`.Tpo $(DEPDIR)/`basename $*`.Po
@AMDEP_TRUE@@am__fastdepCC_FALSE@	source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
@AMDEP_TRUE@@am__fastdepCC_FALSE@	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
@am__fastdepCC_FALSE@	$(COMPILE) -c $<
endif


# Commented out for now, until we get configuration directory support added.
#sysconf_DATA = smcpd.conf

DISTCLEANFILES = .deps Makefile

