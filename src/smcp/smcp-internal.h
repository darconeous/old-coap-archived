/*!	@file smcp_internal.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Internal structures and functions
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

#ifndef __SMCP_INTERNAL_H__
#define __SMCP_INTERNAL_H__ 1

#include <stdbool.h>

#include "smcp.h"
#include "smcp-timer.h"
#include "fasthash.h"
#include "smcp-auth.h"

#ifndef SMCP_FUNC_RANDOM_UINT32
#if defined(__APPLE__)
#define SMCP_FUNC_RANDOM_UINT32()   arc4random()
#define SMCP_RANDOM_MAX			(uint32_t)(0xFFFFFFFF)
#elif CONTIKI
#include "lib/random.h"
#define SMCP_FUNC_RANDOM_UINT32() \
        ((uint32_t)random_rand() ^ \
            ((uint32_t)random_rand() << 16))
#define SMCP_RANDOM_MAX			RAND_MAX
#else
#define SMCP_FUNC_RANDOM_UINT32() \
        ((uint32_t)random() ^ \
            ((uint32_t)random() << 16))
#define SMCP_RANDOM_MAX			RAND_MAX
#endif
#endif

__BEGIN_DECLS

#if SMCP_EMBEDDED
// Embedded platforms only support one instance.
#define smcp_set_current_instance(x)
#else
extern void smcp_set_current_instance(smcp_t x);
#endif


#ifndef SMCP_HOOK_TIMER_NEEDS_REFRESH
#define SMCP_HOOK_TIMER_NEEDS_REFRESH(x)	do { } while (0)
#endif

#pragma mark -
#pragma mark Class Definitions

#if SMCP_CONF_ENABLE_VHOSTS
struct smcp_vhost_s {
	char name[64];
	smcp_request_handler_func func;
	void* context;
};
#endif

// Consider members of this struct to be private!
struct smcp_s {
	smcp_request_handler_func	request_handler;
	void*						request_handler_context;

#if SMCP_USE_BSD_SOCKETS
	int						fd;
	int						mcfd;	// For multicast
#elif SMCP_USE_UIP
	struct uip_udp_conn*	udp_conn;
#endif

	smcp_timer_t			timers;

	smcp_transaction_t		transactions;
	smcp_transaction_t		current_transaction;

	// Operational Flags
	uint8_t					is_responding:1,
							did_respond:1,
							is_processing_message:1,
							has_cascade_count:1,
							force_current_outbound_code:1;

	//! Inbound packet variables.
	struct {
		const struct coap_header_s*	packet;
		coap_size_t					packet_len;

		coap_option_key_t		last_option_key;
		const uint8_t*			this_option;

		const char*				content_ptr;
		coap_size_t					content_len;
		coap_content_type_t		content_type;

		uint8_t					was_sent_to_multicast:1,
								is_fake:1,
								is_dupe:1,
								has_observe_option:1;

		uint32_t				transaction_hash;

		int32_t					max_age;
		uint32_t				observe_value;
		uint32_t				block2_value;


#if SMCP_USE_BSD_SOCKETS
		struct sockaddr_in6		saddr;
		socklen_t				socklen;
		struct in6_pktinfo		pktinfo;
#elif SMCP_USE_UIP
		uip_ipaddr_t			toaddr;
		uint16_t				toport;	//!^ Always in network order.
#endif

#if SMCP_USE_EXPERIMENTAL_DIGEST_AUTH
		struct smcp_auth_inbound_s     auth;
#endif

	} inbound;

	//! Outbound packet variables.
	struct {
		struct coap_header_s*	packet;
		coap_size_t				max_packet_len;

		char*					content_ptr;
		coap_size_t					content_len;

		coap_msg_id_t	next_tid;

		coap_option_key_t		last_option_key;

#if SMCP_DTLS
		bool					use_dtls;
#endif

#if SMCP_USE_BSD_SOCKETS
		char					packet_bytes[SMCP_MAX_PACKET_LENGTH+1];
		struct sockaddr_in6		saddr;
		socklen_t				socklen;
#endif

#if SMCP_USE_EXPERIMENTAL_DIGEST_AUTH
		struct smcp_auth_outbound_s	auth;
#endif

	} outbound;

	struct {
		uint32_t hash;
		coap_code_t code;
	} dupe[SMCP_CONF_DUPE_BUFFER_SIZE];

#if SMCP_CONF_DUPE_BUFFER_SIZE<=256
	uint8_t dupe_index;
#else
	uint16_t dupe_index;
#endif

#if SMCP_CONF_ENABLE_VHOSTS
	struct smcp_vhost_s		vhost[SMCP_MAX_VHOSTS];
	uint8_t					vhost_count;
#endif

#if SMCP_USE_CASCADE_COUNT
	uint8_t					cascade_count;
#endif

	const char* proxy_url;
};


extern smcp_status_t smcp_handle_request();

extern smcp_status_t smcp_handle_response();


__END_DECLS

#endif // __SMCP_INTERNAL_H__
