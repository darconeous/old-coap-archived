INCLUDES = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

bin_PROGRAMS = smcp-plugtest-server smcp-plugtest-client

smcp_plugtest_server_SOURCES = main-server.c plugtest-server.c
smcp_plugtest_server_LDADD = ../smcp/libsmcp.a

smcp_plugtest_client_SOURCES = main-client.c
smcpctl_LDADD = ../smcp/libsmcp.a

DISTCLEANFILES = .deps Makefile
