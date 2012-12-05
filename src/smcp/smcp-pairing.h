/*	@file smcp-pairing.h
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

#ifndef __SMCP_PAIRING_HEADER__
#define __SMCP_PAIRING_HEADER__ 1

#include <stdbool.h>
#include "smcp.h"
#include "smcp-node.h"
#include "smcp-timer.h"
#include "smcp-variable_node.h"
#include "smcp-transaction.h"

#if SMCP_ENABLE_PAIRING

#define PAIRING_STATE   smcp_root_pairing_node_t root_pairing_node;
#define SMCP_PAIRING_EXPIRATION_INFINITE    (0x7FFFFFFF)

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

	/*!	@enum SMCP_PARING_FLAG_OBSERVE
	**	@abstract This is an observation-style pairing.
	*/
	SMCP_PARING_FLAG_OBSERVE = (1 << 3),
};


typedef uint16_t smcp_pairing_seq_t;

typedef smcp_status_t (*smcp_content_fetcher_func)(
	void* context,
	char* content,
	size_t* content_length,
	coap_content_type_t* content_type
);

struct smcp_event_tracker_s {
	int refCount;
	smcp_content_fetcher_func contentFetcher;
	void* contentFetcherContext;
#if SMCP_CONF_USE_SEQ
	smcp_pairing_seq_t	seq;
#endif
};

typedef struct smcp_event_tracker_s* smcp_event_tracker_t;

#define smcp_pairing_get_uri_cstr(pairing) (pairing)->node.node.name
#define smcp_pairing_get_path_cstr(pairing) ((smcp_node_t)(pairing)->node.node.parent)->name

struct smcp_pairing_node_s {
	struct smcp_variable_node_s	node;
	// Local pairng path comes from parent node name.
	// Remote pairing URI comes from this node's name.

	smcp_event_tracker_t currentEvent;
	struct smcp_transaction_s transaction;

#if SMCP_CONF_USE_SEQ
	smcp_pairing_seq_t	seq;
	smcp_pairing_seq_t	ack;
#endif

	uint8_t				flags;

	uint8_t				token[8];

	union {
		struct smcp_async_response_s async_response;
#if !SMCP_CONF_OBSERVING_ONLY
		struct {
#if SMCP_USE_BSD_SOCKETS
			struct sockaddr_in6 saddr;
#elif CONTIKI
			const uip_ipaddr_t toaddr;
			uint16_t toport;
#endif
		};
#endif // #if !SMCP_CONF_OBSERVING_ONLY
	};


#if SMCP_CONF_PAIRING_STATS
	uint16_t			fire_count;
	uint16_t			send_count;
	uint16_t			errors;
	smcp_status_t		last_error;
#endif
};

typedef smcp_node_t smcp_root_pairing_node_t;

#pragma mark -
#pragma mark Pairing Functions

#if !SMCP_CONF_OBSERVING_ONLY
extern smcp_status_t smcp_pair_with_uri(
	smcp_t	self,
	const char*		path,
	const char*		dest_uri,
	int				flags,
	uintptr_t*		idVal
);

extern smcp_status_t smcp_pair_with_sockaddr(
	smcp_t	self,
	const char*		path,
	const char*		dest_uri,
	SMCP_SOCKET_ARGS,
	int				flags,
	uintptr_t*		idVal
);
#endif // !SMCP_CONF_OBSERVING_ONLY

extern smcp_status_t smcp_pair_inbound_observe_update();

extern smcp_status_t smcp_trigger_event(
	smcp_t self,
	const char* path
);

extern smcp_status_t smcp_trigger_event_with_node(
	smcp_t		self,
	smcp_node_t			node,
	const char*			subpath
);

extern smcp_status_t smcp_trigger_custom_event(
	smcp_t		self,
	const char*			path,
	smcp_content_fetcher_func contentFetcher,
	void* context
);

extern smcp_status_t smcp_trigger_custom_event_with_node(
	smcp_node_t			node,
	const char*			subpath,
	smcp_content_fetcher_func contentFetcher,
	void* context
);

extern smcp_status_t smcp_delete_pairing(smcp_pairing_node_t pairing);

extern smcp_pairing_node_t smcp_get_first_pairing_for_path(
	smcp_t self,
	const char* path
);

extern smcp_pairing_node_t smcp_next_pairing(
	smcp_pairing_node_t pairing
);

extern smcp_status_t smcp_handle_pair(
	smcp_node_t		node,
	smcp_method_t	method
);

extern smcp_root_pairing_node_t smcp_pairing_init(
	smcp_node_t parent,
	const char* name
);

#if SMCP_CONF_USE_SEQ
#if defined(__SDCC)
#define smcp_pairing_get_next_seq(pairing) (++(pairing->seq))
#else
static inline int
smcp_pairing_get_next_seq(smcp_pairing_node_t pairing) {
	return ++(pairing->seq);
}
#endif
#endif

__END_DECLS

#else
#define smcp_trigger_event(a,b)	(SMCP_STATUS_NOT_IMPLEMENTED)
#define smcp_trigger_event_with_node(a,b,c)	(SMCP_STATUS_NOT_IMPLEMENTED)
#define smcp_trigger_custom_event(a,b,c,d)	(SMCP_STATUS_NOT_IMPLEMENTED)
#define smcp_trigger_custom_event_with_node(a,b,c,d,e)	(SMCP_STATUS_NOT_IMPLEMENTED)
#define smcp_pairing_init(a,b,c)	(NULL)
#define PAIRING_STATE
#endif // #if SMCP_ENABLE_PAIRING

#endif
