/*!	@file smcp-node-router.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Node router functions
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

#if SMCP_NODE_ROUTER_USE_BTREE
#include "btree.h"
#else
#include "ll.h"
#endif

#if SMCP_CONF_NODE_ROUTER

__BEGIN_DECLS

/*!	@addtogroup smcp-extras
**	@{
*/

/*!	@defgroup smcp-node-router Node Router
**	@{
**
**	The node router is a way to dispatch inbound packets to a specific
**	packet handler based on a hierarchical interpretation of the path
**	options. When an inbound packet is being processed, it starts out
**	being evaluated at the root node. If the next path option of the
**	inbound packet matches the name of one of the children of the current
**	node, we descent into that child and move forward to the next path
**	element. We continue to descend and follow this process until we get
**	to a node where we don't have a match. Once this happens—even if
**	there are additional path elements which haven't matched—the packet
**	is processed by the handler of the current node.
**
**	Keep in mind that this parsing of the path and descending into child
**	nodes happens if there is a handler specified for that node or not.
**
**	If a handler isn't specified, the list handler is used. The list
**	handler is simply a convenience function which returns a link list of
**	that node's children. It's handy and easy to use, but in exchange you
**	give up a little flexibility. For example, with the exception of
**	adding child nodes, you currently can't programmatically add entries
**	to the list, nor can you easily add additional attributes to items in
**	the list.
**
**	As a convenience (that, by the way, is actually built into the list
**	node), if the root doesn't have a handler (and neither does
**	"/.well-known/core"), then a request for "/.well-known/core" is
**	interpreted as a request for the root (but will yield absolute URIs in
**	the link list instead of relative URIs). But this is really only
**	useful for quick prototyping: to do proper service discovery, you'll
**	need to list more than just the contents of your root node: so unless
**	you are doing something very simple, you will likely need a custom
**	handler for "/.well-known" or "/.well-known/core".
**
**	If your device is really constrained, you may want to consider not
**	using the node router, writing your own request router instead. You
**	would have an inbound packet handler that would simply examine the
**	path options and optionally call other handlers directly depending on
**	whatever criteria you want. You don't get the convenience of the
**	"list" handler, but you do get something that is much smaller and
**	flexible.
**
**	The convention of the node router (which is also followed by the
**	"variable node") is that when your handler is called that the next
**	option you fetch will be the option immediately after the path that
**	was evaluated to get you to that handler. So if you want to use the
**	variable node handler to wrap around getting and setting variables
**	("a", "b", and "c") that lives at "/mydevice/blah/", when the variable
**	node handles a GET for "/mydevice/blah/a", the first option it fetches
**	will be the urlpath option "a".
**
**	@sa @ref smcp-example-3
*/

struct smcp_node_s;
typedef struct smcp_node_s* smcp_node_t;

typedef smcp_status_t (*smcp_node_inbound_handler_func)(smcp_node_t node);

struct smcp_node_s {
#if SMCP_NODE_ROUTER_USE_BTREE
	struct bt_item_s			bt_item;
#else
	struct ll_item_s			ll_item;
#endif
	const char*					name;
	smcp_node_t					parent;
	smcp_node_t					children;

	void						(*finalize)(smcp_node_t node);
	smcp_request_handler_func	request_handler;
	void*						context;
	uint8_t						has_link_content:1,
								is_observable:1,
								should_free_name:1;

};

SMCP_API_EXTERN bt_compare_result_t smcp_node_compare(smcp_node_t lhs, smcp_node_t rhs);

#if SMCP_EMBEDDED
#define smcp_node_get_root(x)		((smcp_node_t)smcp_get_current_instance())
#else
SMCP_API_EXTERN smcp_node_t smcp_node_get_root(smcp_node_t node);
#endif

SMCP_API_EXTERN smcp_status_t smcp_node_router_handler(void* context);
SMCP_API_EXTERN smcp_status_t smcp_node_route(smcp_node_t node, smcp_request_handler_func* func, void** context);

SMCP_API_EXTERN smcp_node_t smcp_node_alloc();

SMCP_API_EXTERN smcp_node_t smcp_node_init(
	smcp_node_t self,
	smcp_node_t parent,
	const char* name		//!< [IN] Unescaped.
);

SMCP_API_EXTERN void smcp_node_delete(smcp_node_t node);

SMCP_API_EXTERN smcp_status_t smcp_node_get_path(
	smcp_node_t node,
	char* path,			//!< [OUT] Pointer to where the path will be written.
	coap_size_t max_path_len
);

SMCP_API_EXTERN smcp_node_t smcp_node_find(
	smcp_node_t node,
	const char* name,		//!< [IN] Unescaped.
	int name_len
);

SMCP_API_EXTERN smcp_node_t smcp_node_find_with_path(
	smcp_node_t node,
	const char* path		//!< [IN] Fully escaped path.
);

SMCP_API_EXTERN int smcp_node_find_closest_with_path(
	smcp_node_t node,
	const char* path,		//!< [IN] Fully escaped path.
	smcp_node_t* closest
);

SMCP_API_EXTERN int smcp_node_find_next_with_path(
	smcp_node_t node,
	const char* path,		//!< [IN] Fully escaped path.
	smcp_node_t* next
);

SMCP_API_EXTERN smcp_status_t smcp_default_request_handler(
	smcp_node_t		node
);

SMCP_API_EXTERN smcp_status_t smcp_handle_list(smcp_node_t node);

/*!	@} */
/*!	@} */

__END_DECLS

#endif // #if SMCP_CONF_NODE_ROUTER

#endif
