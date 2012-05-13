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

#if CONTIKI
#define smcp_set_current_daemon(x)
#else
extern void smcp_set_current_daemon(smcp_daemon_t x);
#endif


#pragma mark -
#pragma mark Class Definitions

struct smcp_transaction_s {
	struct bt_item_s			bt_item;
	coap_transaction_id_t		tid;
	struct timeval				expiration;
	uint8_t						flags;
	bool waiting_for_async_response;
	uint8_t						attemptCount;
	struct smcp_timer_s			timer;
	smcp_request_resend_func	resendCallback;
	smcp_response_handler_func	callback;
	void*						context;
	uint16_t token;
};

typedef struct smcp_transaction_s *smcp_transaction_t;

// Consider members of this struct to be private!
struct smcp_daemon_s {
	struct smcp_node_s		root_node;

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

		coap_option_key_t		last_option_key;
		const uint8_t*			this_option;
		uint8_t					options_left;

		const uint8_t*			token_option;

		const char*				content_ptr;
		size_t					content_len;
		coap_content_type_t		content_type;

		coap_transaction_id_t	last_tid;

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

		uint8_t					real_option_count;
		coap_option_key_t		last_option_key;

		coap_transaction_id_t	next_tid;

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



