AM_CPPFLAGS = -I.. -I$(top_srcdir)/src
#AM_CFLAGS = @CFLAGS@ @WARN_CFLAGS@

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

bin_PROGRAMS = smcpctl

smcpctl_SOURCES = main.c cmd_list.c cmd_get.c cmd_post.c help.c cmd_repeat.c cmd_delete.c
smcpctl_SOURCES += cmd_delete.h cmd_get.h cmd_list.h cmd_post.h cmd_repeat.h help.h smcpctl.h
smcpctl_LDADD = ../smcp/libsmcp.la

DISTCLEANFILES = .deps Makefile

