/*	Simple Monitoring and Control Protocol (SMCP)
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/


#ifndef __SMCP_PAIRING_HEADER__
#define __SMCP_PAIRING_HEADER__ 1

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


#define PAIRING_STATE   struct smcp_pairing_s* pairings

__BEGIN_DECLS
typedef uint32_t smcp_pairing_seq_t;

struct smcp_pairing_s {
	struct bt_item_s	bt_item;
	int					flags;
	smcp_pairing_seq_t	seq;
	smcp_pairing_seq_t	ack;

	const char*			path; // Local path

	const char*			dest_uri;
};

__END_DECLS

#pragma mark -
#pragma mark Pairing Functions

extern smcp_status_t smcp_daemon_pair_with_uri(
	smcp_daemon_t	self,
	const char*		path,
	const char*		uri,
	int				flags,
	uintptr_t*		idVal);
extern smcp_status_t smcp_daemon_trigger_event(
	smcp_daemon_t		self,
	const char*			path,
	const char*			content,
	size_t				content_length,
	coap_content_type_t content_type);
extern smcp_status_t smcp_daemon_trigger_event_with_node(
	smcp_daemon_t		self,
	smcp_node_t			node,
	const char*			subpath,
	const char*			content,
	size_t				content_length,
	coap_content_type_t content_type);

extern smcp_status_t smcp_daemon_pair_path_with_sockaddr(
	smcp_daemon_t	self,
	const char*		path,
	const char*		dest_path,
	SMCP_SOCKET_ARGS,
	int				flags);
extern smcp_pairing_t smcp_daemon_get_first_pairing_for_path(
	smcp_daemon_t self, const char* path);
extern smcp_pairing_t smcp_daemon_next_pairing(
	smcp_daemon_t self, smcp_pairing_t pairing);

extern smcp_status_t smcp_daemon_handle_pair(
	smcp_daemon_t	self,
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length);

static inline int
smcp_pairing_get_next_seq(smcp_pairing_t pairing) {
	return ++(pairing->seq);
}

#endif
