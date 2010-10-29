#ifndef __SMCP_VARIABLE_NODE_H__
#define __SMCP_VARIABLE_NODE_H__ 1

#include "smcp_node.h"

struct smcp_variable_node_s;
typedef struct smcp_variable_node_s *smcp_variable_node_t;

struct smcp_variable_node_s {
	struct smcp_node_s	node;
	smcp_status_t		(*get_func)(
		smcp_variable_node_t node, char* content, size_t* content_length,
		coap_content_type_t* content_type);
	smcp_status_t		(*post_func)(
		smcp_variable_node_t node, char* content, size_t content_length,
		coap_content_type_t content_type);
};


#define smcp_node_init_variable smcp_variable_node_init

extern smcp_variable_node_t smcp_variable_node_init(
	smcp_variable_node_t self, smcp_node_t parent, const char* name);

extern smcp_status_t smcp_daemon_refresh_variable(
	smcp_daemon_t daemon, smcp_variable_node_t node);

#endif //__SMCP_TIMER_NODE_H__
