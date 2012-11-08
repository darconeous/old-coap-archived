
SMCP_VERSION=0.5

HAS_LIBREADLINE=1
HAS_LIBCURL=1

INCLUDE_GE_SYSTEM_NODE=0

INSTALL=install
PREFIX=/usr/local

SMCP_SOURCE_PATH=src/smcp
SMCP_SOURCE_FILES=smcp.c smcp-list.c smcp-send.c smcp-node.c smcp-pairing.c btree.c url-helpers.c coap.c smcp-timer.c smcp-timer_node.c smcp-variable_node.c

GE_SYSTEM_SOURCE_FILES=ge-rs232.c ge-system-node.c

GE_SYSTEM_SOURCE_PATH=../ge-rs232
GE_SYSTEM_OBJECT_FILES=${addprefix $(GE_SYSTEM_SOURCE_PATH)/,${subst .c,.o,$(GE_SYSTEM_SOURCE_FILES)}}

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

#LFLAGS+=-shared
LFLAGS+=-rdynamic

SMCP_OBJECT_FILES=${addprefix $(SMCP_SOURCE_PATH)/,${subst .c,.o,$(SMCP_SOURCE_FILES)}}

SMCPD_SOURCE_PATH=src/smcpd
SMCPD_SOURCE_FILES=main.c system-node.c
SMCPD_OBJECT_FILES=${addprefix $(SMCPD_SOURCE_PATH)/,${subst .c,.o,$(SMCPD_SOURCE_FILES)}}

ifeq ($(INCLUDE_GE_SYSTEM_NODE),1)
SMCPD_OBJECT_FILES+=$(GE_SYSTEM_OBJECT_FILES)
endif

SMCPCTL_SOURCE_PATH=src/smcpctl
SMCPCTL_SOURCE_FILES=main.c cmd_list.c cmd_test.c cmd_get.c cmd_post.c cmd_pair.c help.c cmd_repeat.c cmd_delete.c cmd_monitor.c
SMCPCTL_OBJECT_FILES=${addprefix $(SMCPCTL_SOURCE_PATH)/,${subst .c,.o,$(SMCPCTL_SOURCE_FILES)}}

.PHONY: all test install uninstall clean

all: smcpctl smcpd

test: btreetest

smcpctl: $(SMCPCTL_OBJECT_FILES) $(SMCP_OBJECT_FILES)
	$(CXX) -o $@ $+ -lpthread $(LFLAGS)

smcpd: $(SMCPD_OBJECT_FILES) $(SMCP_OBJECT_FILES)
	$(CXX) -o $@ $+ -lpthread $(LFLAGS)

btreetest: src/smcp/btree.c
	$(CC) -o $@ $+ -Wall -DBTREE_SELF_TEST=1
	./btreetest

clean:
	$(RM) $(SMCPD_OBJECT_FILES) $(SMCPCTL_OBJECT_FILES) $(SMCP_OBJECT_FILES) smcpd smcpctl btreetest

install: smcpctl smcpd
	$(INSTALL) smcpctl $(PREFIX)/bin
	$(INSTALL) smcpctl.1 $(PREFIX)/share/man/man1
	$(INSTALL) smcpd $(PREFIX)/bin

uninstall:
	$(RM) $(PREFIX)/bin/smcpd $(PREFIX)/bin/smcpctl $(PREFIX)/share/man/man1/smcpctl.1
