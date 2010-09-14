

SMCP_OBJECT_FILES=smcp.o smcp_node.o smcp_pairing.o btree.o

smcp: main.o cmd_list.o cmd_test.o help.o $(SMCP_OBJECT_FILES)
	$(CXX) -o $@ $+ -lpthread

clean:
	$(RM) *.o smcp

