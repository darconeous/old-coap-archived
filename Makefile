

SMCP_OBJECT_FILES=smcp.o smcp_node.o smcp_pairing.o btree.o url-helpers.o

smcp: main.o cmd_list.o cmd_test.o cmd_get.o cmd_post.o cmd_pair.o help.o $(SMCP_OBJECT_FILES)
	$(CXX) -o $@ $+ -lpthread

clean:
	$(RM) *.o smcp

