INCLUDES = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

bin_PROGRAMS = smcpctl

smcpctl_SOURCES = main.c cmd_list.c cmd_test.c cmd_get.c cmd_post.c cmd_pair.c help.c cmd_repeat.c cmd_delete.c cmd_monitor.c
smcpctl_SOURCES += cmd_delete.h cmd_get.h cmd_list.h cmd_monitor.h cmd_pair.h cmd_post.h cmd_repeat.h cmd_test.h help.h smcpctl.h
smcpctl_LDADD = ../smcp/libsmcp.la

DISTCLEANFILES = .deps Makefile

