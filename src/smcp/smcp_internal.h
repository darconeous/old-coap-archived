/*
 *  smcp_internal.h
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 10/15/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include "smcp.h"
#include "smcp_timer.h"

#include "smcp_pairing.h"

#if CONTIKI
// Contiki only supports one daemon.
#define smcp_set_current_daemon(x)
#else
extern void smcp_set_current_daemon(smcp_daemon_t x);
#endif

#pragma mark -
#pragma mark Class Definitions

struct smcp_transaction_s {
	struct bt_item_s			bt_item;
	smcp_inbound_resend_func	resendCallback;
	smcp_response_handler_func	callback;
	void*						context;
	coap_transaction_id_t		tid;
	uint8_t						flags;
	uint8_t						attemptCount;
	struct timeval				expiration;
	struct smcp_timer_s			timer;

	uint16_t token;
	bool waiting_for_async_response;
};

typedef struct smcp_transaction_s *smcp_transaction_t;

// Consider members of this struct to be private!
struct smcp_daemon_s {
	struct smcp_node_s		root_node;
	void*					reserved_for_root_node_use;

#if SMCP_USE_BSD_SOCKETS
	int						fd;
	int						mcfd;	// For multicast
#elif CONTIKI
	struct uip_udp_conn*	udp_conn;
#endif

	smcp_timer_t			timers;

	smcp_transaction_t		transactions;

	uint8_t					cascade_count;

	// Operational Flags
	bool					is_responding:1,
							did_respond:1,
							is_processing_message:1,
							has_cascade_count:1,
							force_current_outbound_code:1;

	// Inbound packet variables.
	struct {
		const struct coap_header_s*	packet;
		size_t					packet_len;

		coap_option_key_t		last_option_key;
		const uint8_t*			this_option;
		uint8_t					options_left;

		const uint8_t*			token_option;

		const char*				content_ptr;
		size_t					content_len;
		coap_content_type_t		content_type;

		coap_transaction_id_t	last_tid;

		bool					was_sent_to_multicast:1,
								is_fake:1;
#if SMCP_USE_BSD_SOCKETS
		struct sockaddr*		saddr;
		socklen_t				socklen;
#elif CONTIKI
		uip_ipaddr_t			toaddr;
		uint16_t				toport;	// Always in network order.
#endif
	} inbound;

	// Outbound packet variables.
	struct {
		struct coap_header_s*	packet;

		char*					content_ptr;
		size_t					content_len;

		coap_transaction_id_t	next_tid;

		coap_option_key_t		last_option_key;

#if SMCP_USE_BSD_SOCKETS
		char					packet_bytes[SMCP_MAX_PACKET_LENGTH+1];
		struct sockaddr_in6		saddr;
		socklen_t				socklen;
#endif
	} outbound;

	const char* proxy_url;

	PAIRING_STATE;
};


extern smcp_status_t
smcp_daemon_handle_request(
	smcp_daemon_t	self
);
extern smcp_status_t smcp_daemon_handle_list(
	smcp_node_t		node,
	smcp_method_t	method
);

extern smcp_status_t smcp_daemon_handle_response(smcp_daemon_t	self);


