/*	@file smcp_internal.c
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

#include "smcp.h"
#include "smcp-timer.h"

#include "smcp-pairing.h"


#ifndef SMCP_FUNC_RANDOM_UINT32
#if defined(__APPLE__)
#define SMCP_FUNC_RANDOM_UINT32()   arc4random()
#elif CONTIKI
#define SMCP_FUNC_RANDOM_UINT32() \
        ((uint32_t)random_rand() ^ \
            ((uint32_t)random_rand() << 16))
#else
#define SMCP_FUNC_RANDOM_UINT32() \
        ((uint32_t)random() ^ \
            ((uint32_t)random() << 16))
#endif
#endif

#if SMCP_EMBEDDED
// Embedded platforms only support one instance.
#define smcp_set_current_instance(x)
#else
extern void smcp_set_current_instance(smcp_t x);
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
	uint8_t waiting_for_async_response:1;
};

typedef struct smcp_transaction_s *smcp_transaction_t;

// Consider members of this struct to be private!
struct smcp_s {
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
	smcp_transaction_t		current_transaction;

#if SMCP_USE_CASCADE_COUNT
	uint8_t					cascade_count;
#endif

	// Operational Flags
	uint8_t					is_responding:1,
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

		int32_t					max_age;

		uint8_t					was_sent_to_multicast:1,
								is_fake:1,
								has_observe_option:1;
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

	PAIRING_STATE
};


extern smcp_status_t smcp_handle_request(smcp_t	self);

extern smcp_status_t smcp_handle_response(smcp_t self);

extern smcp_status_t smcp_handle_list(smcp_node_t node,smcp_method_t method);

