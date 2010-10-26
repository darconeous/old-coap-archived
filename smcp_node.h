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

struct smcp_node_s {
	struct bt_item_s	bt_item;
	smcp_node_type_t	type;
	const char*			name;
	smcp_node_t			parent;
	void*				context;
	void				(*finalize)(smcp_node_t node);
	// ---
	smcp_status_t		(*unhandled_request)(
		smcp_daemon_t self, smcp_node_t node, smcp_method_t method,
		const char* relative_path, coap_header_item_t headers[],
		const char* content, size_t content_length);
	void*				padding[3];
};

struct smcp_device_node_s {
	struct bt_item_s	bt_item;
	smcp_node_type_t	type;
	const char*			name;
	smcp_node_t			parent;
	void*				context;
	void				(*finalize)(smcp_node_t node);
	// ---
	smcp_status_t		(*unhandled_request)(
		smcp_daemon_t self, smcp_node_t node, smcp_method_t method,
		const char* relative_path, coap_header_item_t headers[],
		const char* content, size_t content_length);
//	smcp_node_t actions;
	smcp_node_t			subdevices;
	smcp_node_t			variables;
};

/*
   struct smcp_variable_node_s {
    struct bt_item_s bt_item;
    smcp_node_type_t type;
    const char* name;
    smcp_node_t parent;
    void* context;
    void (*finalize)(smcp_node_t node);
    // ---
    smcp_status_t (*unhandled_request)(smcp_daemon_t self,smcp_node_t node,smcp_method_t method, const char* relative_path,  coap_header_item_t headers[], const char* content, size_t content_length);
    smcp_node_t actions;

    smcp_status_t (*get_func)(smcp_variable_node_t node,coap_header_item_t headers[], char* content, size_t* content_length, smcp_content_type_t* content_type, void* context);
   };

   struct smcp_action_node_s {
    struct bt_item_s bt_item;
    smcp_node_type_t type;
    const char* name;
    smcp_node_t parent;
    void* context;
    void (*finalize)(smcp_node_t node);
    // ---
    smcp_status_t (*unhandled_request)(smcp_daemon_t self,smcp_node_t node,smcp_method_t method, const char* relative_path,  coap_header_item_t headers[], const char* content, size_t content_length);

    smcp_status_t (*post_func)(struct smcp_action_node_s* node,coap_header_item_t headers[], const char* content, size_t content_length,smcp_content_type_t content_type, void* context) SMCP_DEPRECATED;
   } SMCP_DEPRECATED;
 */

bt_compare_result_t
smcp_node_compare(
	smcp_node_t lhs, smcp_node_t rhs);

__END_DECLS


#endif
