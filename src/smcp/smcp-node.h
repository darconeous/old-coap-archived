/*	@file smcp-node.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef __SMCP_NODE_HEADER__
#define __SMCP_NODE_HEADER__ 1

#include "smcp.h"

#if SMCP_CONF_NODE_ROUTER

__BEGIN_DECLS

struct smcp_node_s;
typedef struct smcp_node_s* smcp_node_t;

typedef smcp_status_t (*smcp_node_inbound_handler_func)(
	smcp_node_t node
//	, smcp_method_t method
);

// Struct size: 8*sizeof(void*)
struct smcp_node_s {
	struct bt_item_s			bt_item;
	const char*					name;
	smcp_node_t					parent;
	smcp_node_t					children;

	uint8_t						has_link_content:1,
								is_observable:1,
								should_free_name:1;

	void						(*finalize)(smcp_node_t node);
	smcp_node_inbound_handler_func	request_handler;
	void*						context;
};

extern bt_compare_result_t smcp_node_compare(smcp_node_t lhs, smcp_node_t rhs);

#if SMCP_EMBEDDED
//#define smcp_get_root_node(x)		((smcp_node_t)smcp_get_current_instance())
#define smcp_node_get_root(x)		((smcp_node_t)smcp_get_current_instance())
#else
//extern smcp_node_t smcp_get_root_node(smcp_t self);
extern smcp_node_t smcp_node_get_root(smcp_node_t node);
#endif

extern smcp_status_t smcp_node_router_handler(void* context);
extern smcp_status_t smcp_node_route(smcp_node_t node, smcp_request_handler_func* func, void** context);

extern smcp_node_t smcp_node_alloc();

extern smcp_node_t smcp_node_init(
	smcp_node_t self,
	smcp_node_t parent,
	const char* name		// Unescaped.
);

extern void smcp_node_delete(smcp_node_t node);


extern smcp_status_t smcp_node_get_path(
	smcp_node_t node,
	char* path,
	size_t max_path_len
);

extern smcp_node_t smcp_node_find(
	smcp_node_t node,
	const char* name,		// Unescaped.
	int name_len
);

extern smcp_node_t smcp_node_find_with_path(
	smcp_node_t node,
	const char* path		// Fully escaped path.
);

extern int smcp_node_find_closest_with_path(
	smcp_node_t node,
	const char* path,		// Fully escaped path.
	smcp_node_t* closest
);

extern int smcp_node_find_next_with_path(
	smcp_node_t node,
	const char* path,		// Fully escaped path.
	smcp_node_t* next
);

extern smcp_status_t smcp_default_request_handler(
	smcp_node_t		node
);

extern smcp_status_t smcp_handle_list(smcp_node_t node);


__END_DECLS

#endif // #if SMCP_CONF_NODE_ROUTER

#endif
