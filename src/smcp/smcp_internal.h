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
	int							flags;
	char						attemptCount;
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
	struct sockaddr*		current_inbound_saddr;
	socklen_t				current_inbound_socklen;
#elif defined(CONTIKI)
	struct uip_udp_conn*	udp_conn;
	uip_ipaddr_t			current_inbound_toaddr;
	uint16_t				current_inbound_toport;
#endif

	uint16_t				port;

	struct smcp_node_s		root_node;
	smcp_timer_t			timers;
	smcp_transaction_t handlers;
	PAIRING_STATE;

	coap_transaction_id_t	current_inbound_request_tid;
	char*					current_inbound_request_token;
	uint16_t				current_inbound_request_token_len;
	uint8_t					cascade_count;

	// Operational Flags
	bool					is_responding,
							did_respond,
							is_processing_message,
							has_cascade_count,
							force_current_outbound_code;

	coap_header_item_t		current_inbound_headers[SMCP_MAX_HEADERS + 1];
	uint8_t					current_inbound_header_count;

#pragma mark -
#pragma mark Constrained sending state
	// TODO: writeme!

	coap_header_item_t		current_outbound_headers[SMCP_MAX_HEADERS + 1];
	uint8_t					current_outbound_header_count;
	coap_transaction_type_t current_outbound_tt;
	coap_code_t				current_outbound_code;
	coap_transaction_id_t	current_outbound_tid;
	size_t					current_outbound_header_len;
	size_t					current_outbound_content_len;

#if SMCP_USE_BSD_SOCKETS
	char					current_outbound_packet[SMCP_MAX_PACKET_LENGTH
	    + 1];
	struct sockaddr_in6		current_outbound_saddr;
	socklen_t				current_outbound_socklen;
#endif
};


extern smcp_status_t
smcp_daemon_handle_request(
	smcp_daemon_t	self,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
);
