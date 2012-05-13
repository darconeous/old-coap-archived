
HAS_LIBREADLINE=1
HAS_LIBCURL=1

INSTALL=install

PREFIX=/usr/local

SMCP_SOURCE_PATH=src/smcp/
SMCP_SOURCE_FILES=smcp.c smcp_send.c smcp_node.c smcp_pairing.c btree.c url-helpers.c coap.c smcp_timer.c smcp_timer_node.c smcp_variable_node.c

ifdef HAS_LIBREADLINE
CFLAGS+=-DHAS_LIBREADLINE=1
LFLAGS+=-lreadline
endif

ifdef HAS_LIBCURL
CFLAGS+=-DHAS_LIBREADLINE=1
LFLAGS+=-lreadline
SMCP_SOURCE_FILES=smcp_curl_proxy.c
endif

ifdef HAS_ASSERTMACROS_H
CFLAGS+=-DHAS_ASSERTMACROS_H=$(HAS_ASSERTMACROS_H)
endif

ifdef VERBOSE_DEBUG
CFLAGS+=-DVERBOSE_DEBUG=$(VERBOSE_DEBUG)
endif

ifdef DEBUG
CFLAGS+=-DDEBUG=$(DEBUG)
else
CFLAGS+=-DDEBUG=1
endif


CFLAGS+=-O0 -g

CFLAGS+=-Isrc

SMCP_OBJECT_FILES=${addprefix $(SMCP_SOURCE_PATH),${subst .c,.o,$(SMCP_SOURCE_FILES)}}


SMCPCTL_SOURCE_PATH=src/smcpctl/
SMCPCTL_SOURCE_FILES=main.c cmd_list.c cmd_test.c cmd_get.c cmd_post.c cmd_pair.c help.c cmd_repeat.c cmd_delete.c cmd_monitor.c
SMCPCTL_OBJECT_FILES=${addprefix $(SMCPCTL_SOURCE_PATH),${subst .c,.o,$(SMCPCTL_SOURCE_FILES)}}

.PHONY: install uninstall clean

smcpctl: $(SMCPCTL_OBJECT_FILES) $(SMCP_OBJECT_FILES)
	$(CXX) -o $@ $+ -lpthread $(LFLAGS)

clean:
	$(RM) $(SMCPCTL_OBJECT_FILES) $(SMCP_OBJECT_FILES) smcpctl

install: smcpctl
	$(INSTALL) smcpctl $(PREFIX)/bin
	$(INSTALL) smcpctl.1 $(PREFIX)/share/man/man1

uninstall:
	$(RM) $(PREFIX)/bin/smcpctl $(PREFIX)/share/man/man1/smcpctl.1

