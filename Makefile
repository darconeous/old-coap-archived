
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

SMCP_OBJECT_FILES=smcp.o smcp_node.o smcp_pairing.o btree.o url-helpers.o coap.o smcp_timer.o smcp_timer_node.o
SMCPCTL_OBJECT_FILES=main.o cmd_list.o cmd_test.o cmd_get.o cmd_post.o cmd_pair.o help.o

.PHONY: install uninstall clean

smcpctl: $(SMCPCTL_OBJECT_FILES) $(SMCP_OBJECT_FILES)
	$(CXX) -o $@ $+ -lpthread $(LFLAGS)

clean:
	$(RM) *.o smcpctl

install: smcpctl
	$(INSTALL) smcpctl $(PREFIX)/bin
	$(INSTALL) smcpctl.1 $(PREFIX)/share/man/man1

uninstall:
	$(RM) $(PREFIX)/bin/smcpctl $(PREFIX)/share/man/man1/smcpctl.1

