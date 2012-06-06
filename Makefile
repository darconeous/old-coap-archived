
SMCP_VERSION=0.5

HAS_LIBREADLINE=1
HAS_LIBCURL=1

INSTALL=install
PREFIX=/usr/local

SMCP_SOURCE_PATH=src/smcp
SMCP_SOURCE_FILES=smcp.c smcp-list.c smcp-send.c smcp-node.c smcp-pairing.c btree.c url-helpers.c coap.c smcp-timer.c smcp-timer_node.c smcp-variable_node.c

ifeq ($(HAS_LIBREADLINE),1)
CFLAGS+=-DHAS_LIBREADLINE=1
LFLAGS+=-lreadline
endif

ifeq ($(HAS_LIBCURL),1)
CFLAGS+=-DHAS_LIBCURL=1
LFLAGS+=-lcurl
SMCP_SOURCE_FILES+=smcp-curl_proxy.c
endif

ifeq ($(HAS_ASSERTMACROS_H),1)
CFLAGS+=-DHAS_ASSERTMACROS_H=$(HAS_ASSERTMACROS_H)
endif

ifdef VERBOSE_DEBUG
CFLAGS+=-DVERBOSE_DEBUG=$(VERBOSE_DEBUG)
endif

ifeq ($(DEBUG),1)
CFLAGS+=-O0 -g
CFLAGS+=-DDEBUG=1
endif

CFLAGS+=-Isrc

SMCP_OBJECT_FILES=${addprefix $(SMCP_SOURCE_PATH)/,${subst .c,.o,$(SMCP_SOURCE_FILES)}}

SMCPCTL_SOURCE_PATH=src/smcpctl
SMCPCTL_SOURCE_FILES=main.c cmd_list.c cmd_test.c cmd_get.c cmd_post.c cmd_pair.c help.c cmd_repeat.c cmd_delete.c cmd_monitor.c
SMCPCTL_OBJECT_FILES=${addprefix $(SMCPCTL_SOURCE_PATH)/,${subst .c,.o,$(SMCPCTL_SOURCE_FILES)}}

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
