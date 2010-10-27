
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

SMCP_OBJECT_FILES=src/smcp/smcp.o src/smcp/smcp_node.o src/smcp/smcp_pairing.o src/smcp/btree.o src/smcp/url-helpers.o src/smcp/coap.o src/smcp/smcp_timer.o src/smcp/smcp_timer_node.o src/smcp/smcp_variable_node.o
SMCPCTL_OBJECT_FILES=src/smcpctl/main.o src/smcpctl/cmd_list.o src/smcpctl/cmd_test.o src/smcpctl/cmd_get.o src/smcpctl/cmd_post.o src/smcpctl/cmd_pair.o src/smcpctl/help.o

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

