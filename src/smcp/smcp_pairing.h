/*	Simple Monitoring and Control Protocol (SMCP)
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/


#ifndef __SMCP_PAIRING_HEADER__
#define __SMCP_PAIRING_HEADER__ 1

#include <stdbool.h>
#include "smcp.h"
#include "smcp_node.h"
#include "smcp_timer.h"

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

#define PAIRING_STATE   struct smcp_pairing_node_s* pairings; smcp_root_pairing_node_t root_pairing_node

#ifndef SMCP_CONF_PAIRING_STATS
#define SMCP_CONF_PAIRING_STATS 1
#endif

__BEGIN_DECLS


struct smcp_pairing_node_s;
typedef struct smcp_pairing_node_s *smcp_pairing_node_t;

enum {
	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_MASK
	**	@abstract Bitmask for obtaining the reliability from
	**	          pairing flags.
	*/
	SMCP_PARING_FLAG_RELIABILITY_MASK = (3 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_NONE
	**	@abstract Events are transmitted unreliably.
	*/
	SMCP_PARING_FLAG_RELIABILITY_NONE = (0 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_ASAP
	**	@abstract Events are transmitted reliably out-of-order.
	**	          Order-of-events is maintained per-pairing.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_ASAP = (1 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_PART
	**	@abstract Events transmitted and will be retransmitted
	**	          until either the event is ACKed or the event
	**	          is superceded by a more recent event.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_PART = (2 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_FULL
	**	@abstract Events are transmitted reliably and in-order.
	**	          Order-of-events is maintained per-pairing.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_FULL = (3 << 0),

	/*!	@enum SMCP_PARING_FLAG_TEMPORARY
	**	@abstract Pairing is not to be comitted to
	**	          non-volatile storage.
	*/
	SMCP_PARING_FLAG_TEMPORARY = (1 << 2),
};


typedef uint32_t smcp_pairing_seq_t;

typedef smcp_status_t (*smcp_content_fetcher_func)(
	void* context,
	char* content,
	size_t* content_length,
	coap_content_type_t* content_type
);

#define SMCP_PAIRING_EXPIRATION_INFINITE    (0x7FFFFFFF)

struct smcp_event_tracker_s {
	int refCount;
	smcp_content_fetcher_func contentFetcher;
	void* contentFetcherContext;
};

typedef struct smcp_event_tracker_s* smcp_event_tracker_t;

#define smcp_pairing_get_uri_cstr(pairing) (pairing)->node.name
#define smcp_pairing_get_path_cstr(pairing) ((smcp_node_t)(pairing)->node.parent)->name

struct smcp_pairing_node_s {
	struct smcp_node_s	node;
	// Local pairng path comes from parent node name.
	// Remote pairing URI comes from this node's name.

	uint8_t				flags;

	smcp_pairing_seq_t	seq;
	smcp_pairing_seq_t	ack;

	coap_transaction_id_t last_tid;
	smcp_event_tracker_t currentEvent;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr;
#elif CONTIKI
    const uip_ipaddr_t toaddr;
    uint16_t toport;
#endif

#if SMCP_CONF_PAIRING_STATS
	uint16_t			fire_count;
	uint16_t			errors;
	uint16_t			send_count;
	smcp_status_t		last_error;
#endif
};

typedef smcp_node_t smcp_root_pairing_node_t;

#pragma mark -
#pragma mark Pairing Functions

extern smcp_status_t smcp_daemon_pair_with_uri(
	smcp_daemon_t	self,
	const char*		path,
	const char*		dest_uri,
	int				flags,
	uintptr_t*		idVal
);

extern smcp_status_t smcp_daemon_pair_with_sockaddr(
	smcp_daemon_t	self,
	const char*		path,
	const char*		dest_uri,
	SMCP_SOCKET_ARGS,
	int				flags,
	uintptr_t*		idVal
);

extern smcp_status_t smcp_daemon_trigger_event(
	smcp_daemon_t self,
	const char* path
);

extern smcp_status_t smcp_daemon_trigger_event_with_node(
	smcp_daemon_t		self,
	smcp_node_t			node,
	const char*			subpath
);

extern smcp_status_t smcp_daemon_trigger_custom_event(
	smcp_daemon_t		self,
	const char*			path,
	smcp_content_fetcher_func contentFetcher,
	void* context
);

extern smcp_status_t smcp_daemon_trigger_custom_event_with_node(
	smcp_daemon_t		self,
	smcp_node_t			node,
	const char*			subpath,
	smcp_content_fetcher_func contentFetcher,
	void* context
);

extern smcp_status_t smcp_daemon_delete_pairing(
	smcp_daemon_t self,
	smcp_pairing_node_t pairing
);

extern smcp_pairing_node_t smcp_daemon_get_first_pairing_for_path(
	smcp_daemon_t self,
	const char* path
);

extern smcp_pairing_node_t smcp_daemon_next_pairing(
	smcp_daemon_t self,
	smcp_pairing_node_t pairing
);

extern smcp_status_t smcp_daemon_handle_pair(
	smcp_node_t		node,
	smcp_method_t	method
);

extern smcp_root_pairing_node_t smcp_pairing_init(
	smcp_daemon_t self,
	smcp_node_t parent,
	const char* name
);

static inline int
smcp_pairing_get_next_seq(smcp_pairing_node_t pairing) {
	return ++(pairing->seq);
}

__END_DECLS

#endif
