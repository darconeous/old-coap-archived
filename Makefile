
HAS_LIBREADLINE=1

ifdef HAS_LIBREADLINE
CFLAGS+=-DHAS_LIBREADLINE=1
LFLAGS+=-lreadline
endif

CFLAGS+=-DDEBUG=1
#CFLAGS+=-DHAS_ASSERTMACROS_H=1

SMCP_OBJECT_FILES=smcp.o smcp_node.o smcp_pairing.o btree.o url-helpers.o coap.o

smcp: main.o cmd_list.o cmd_test.o cmd_get.o cmd_post.o cmd_pair.o help.o $(SMCP_OBJECT_FILES)
	$(CXX) -o $@ $+ -lpthread $(LFLAGS)

clean:
	$(RM) *.o smcp

