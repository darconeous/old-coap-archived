/*	Simple Monitoring and Control Protocol (SMCP)
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/


#ifndef __SMCP_NODE_HEADER__
#define __SMCP_NODE_HEADER__ 1

#if !defined(__BEGIN_DECLS) || !defined(__END_DECLS)
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS \
	}
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#include <stdbool.h>

#include "smcp.h"

__BEGIN_DECLS

// Struct size: 8*sizeof(void*)
struct smcp_node_s {
	struct bt_item_s			bt_item;
	const char*					name;
	smcp_node_t					parent;
	smcp_node_t					children;

	void						(*finalize)(smcp_node_t node);
	smcp_inbound_handler_func	request_handler;

	void* context; // DEPRECATED, TO BE REMOVED!
};

extern bt_compare_result_t smcp_node_compare(smcp_node_t lhs, smcp_node_t rhs);

__END_DECLS


#endif
