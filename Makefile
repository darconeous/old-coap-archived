
HAS_LIBREADLINE=1
INSTALL=install

PREFIX=/usr/local

ifdef HAS_LIBREADLINE
CFLAGS+=-DHAS_LIBREADLINE=1
LFLAGS+=-lreadline
endif

CFLAGS+=-DDEBUG=1
#CFLAGS+=-DHAS_ASSERTMACROS_H=1

CFLAGS+=-O0 -g

CFLAGS+=-Isrc

SMCP_SOURCE_PATH=src/smcp/
SMCP_SOURCE_FILES=smcp.c smcp_node.c smcp_pairing.c btree.c url-helpers.c coap.c smcp_timer.c smcp_timer_node.c smcp_variable_node.c
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

