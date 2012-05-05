/*
 *  smcp_internal.h
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 10/15/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#if CONTIKI && !CONTIKI_TARGET_MINIMAL_NET
#if !defined(timeval)
#define timeval timeval
struct timeval {
	time_t		tv_sec;
	suseconds_t tv_usec;
};
#endif
#else
#include <sys/time.h>
#endif

#include "smcp_pairing.h"

#pragma mark -
#pragma mark Class Definitions

struct smcp_transaction_s {
	struct bt_item_s			bt_item;
	coap_transaction_id_t		tid;
	struct timeval				expiration;
	uint8_t						flags;
	uint8_t						attemptCount;
	struct smcp_timer_s			timer;
	smcp_request_resend_func	resendCallback;
	smcp_response_handler_func	callback;
	void*						context;
};

typedef struct smcp_transaction_s *smcp_transaction_t;

// Consider members of this struct to be private!
struct smcp_daemon_s {
#if SMCP_USE_BSD_SOCKETS
	int						fd;
	int						mcfd;	// For multicast
#elif CONTIKI
	struct uip_udp_conn*	udp_conn;
#endif

	struct smcp_node_s		root_node;

	smcp_timer_t			timers;

	smcp_transaction_t		transactions;

	uint8_t					cascade_count;

	// Operational Flags
	bool					is_responding:1,
							did_respond:1,
							is_processing_message:1,
							has_cascade_count:1,
							force_current_outbound_code:1;

	coap_code_t				current_inbound_code;
	coap_transaction_id_t	current_inbound_request_tid;
	char*					current_inbound_request_token;
	uint16_t				current_inbound_request_token_len;
	coap_header_item_t		current_inbound_headers[SMCP_MAX_HEADERS+1];
	uint8_t					current_inbound_header_count;
	coap_header_item_t*		current_header;
	char*					current_inbound_content_ptr;
	size_t					current_inbound_content_len;
	coap_content_type_t		current_inbound_content_type;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr*		current_inbound_saddr;
	socklen_t				current_inbound_socklen;
#elif CONTIKI
	uip_ipaddr_t			current_inbound_toaddr;
	uint16_t				current_inbound_toport;	// Always in network order.
#endif

#pragma mark -
#pragma mark Constrained sending state

	coap_header_item_t		current_outbound_headers[SMCP_MAX_HEADERS+1];
	uint8_t					current_outbound_header_count;
	coap_transaction_type_t current_outbound_tt;
	coap_code_t				current_outbound_code;
	coap_transaction_id_t	current_outbound_tid;
	size_t					current_outbound_header_len;
	size_t					current_outbound_content_len;

#if SMCP_USE_BSD_SOCKETS
	char					current_outbound_packet[SMCP_MAX_PACKET_LENGTH+1];
	struct sockaddr_in6		current_outbound_saddr;
	socklen_t				current_outbound_socklen;
#endif

	PAIRING_STATE;
};


extern smcp_status_t
smcp_daemon_handle_request(
	smcp_daemon_t	self
);
