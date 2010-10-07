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
	void				(*finalize)(
		smcp_node_t node, void* context);
	// ---
	void*				padding[5];
};

struct smcp_device_node_s {
	struct bt_item_s	bt_item;
	smcp_node_type_t	type;
	const char*			name;
	smcp_node_t			parent;
	void*				context;
	void				(*finalize)(
		smcp_node_t node, void* context);
	// ---
	smcp_status_t		(*unhandled_request)(
		smcp_daemon_t self, smcp_method_t method, const char* path,
		smcp_header_item_t headers[], const char* content,
		size_t content_length, SMCP_SOCKET_ARGS, void* context);
	smcp_node_t			actions;
	smcp_node_t			events;
	smcp_node_t			variables;
	smcp_node_t			subdevices;
};

struct smcp_variable_node_s {
	struct bt_item_s	bt_item;
	smcp_node_type_t	type;
	const char*			name;
	smcp_node_t			parent;
	void*				context;
	void				(*finalize)(
		smcp_node_t node, void* context);
	// ---
	smcp_status_t		(*unhandled_request)(
		smcp_daemon_t self, smcp_method_t method, const char* path,
		smcp_header_item_t headers[], const char* content,
		size_t content_length, SMCP_SOCKET_ARGS, void* context);
	smcp_node_t			actions;
	smcp_node_t			events;

	smcp_status_t		(*get_func)(
		smcp_variable_node_t node, smcp_header_item_t headers[],
		char* content, size_t* content_length,
		smcp_content_type_t* content_type, SMCP_SOCKET_ARGS, void* context);
};

struct smcp_event_node_s {
	struct bt_item_s	bt_item;
	smcp_node_type_t	type;
	const char*			name;
	smcp_node_t			parent;
	void*				context;
	void				(*finalize)(
		smcp_node_t node, void* context);
	// ---
	smcp_pairing_t		pairings;
};

struct smcp_action_node_s {
	struct bt_item_s	bt_item;
	smcp_node_type_t	type;
	const char*			name;
	smcp_node_t			parent;
	void*				context;
	void				(*finalize)(
		smcp_node_t node, void* context);
	// ---
	smcp_pairing_t		pairings;
	smcp_status_t		(*post_func)(
		smcp_action_node_t node, smcp_header_item_t headers[],
		const char* content, size_t content_length,
		smcp_content_type_t content_type, SMCP_SOCKET_ARGS, void* context);
};

__END_DECLS


#endif
