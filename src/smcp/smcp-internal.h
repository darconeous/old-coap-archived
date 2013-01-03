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

#ifndef __SMCP_INTERNAL_H__
#define __SMCP_INTERNAL_H__ 1

#include "smcp.h"
#include "smcp-timer.h"

#include "smcp-pairing.h"
#include <stdbool.h>
#include "fasthash.h"

#ifndef SMCP_FUNC_RANDOM_UINT32
#if defined(__APPLE__)
#define SMCP_FUNC_RANDOM_UINT32()   arc4random()
#define SMCP_RANDOM_MAX			(uint32_t)(0xFFFFFFFF)
#elif CONTIKI
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


#pragma mark -
#pragma mark Class Definitions

#if SMCP_CONF_ENABLE_GROUPS
struct smcp_group_s {
	char name[64];
#if SMCP_USE_BSD_SOCKETS
	struct in6_addr	addr;
#elif CONTIKI
	uip_ipaddr_t addr;
#endif
	smcp_node_t root;
};
#endif

// Consider members of this struct to be private!
struct smcp_s {
	struct smcp_node_s		root_node;
	void*					reserved_for_root_node_use;

#if SMCP_CONF_ENABLE_GROUPS
	struct smcp_group_s		group[SMCP_MAX_GROUPS];
	uint8_t					group_count;
#endif

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

		const char*				content_ptr;
		size_t					content_len;
		coap_content_type_t		content_type;

		int32_t					max_age;

		uint8_t					was_sent_to_multicast:1,
								is_fake:1,
								is_dupe:1,
								has_observe_option:1;

		uint32_t				observe_value;
		uint32_t				block2_value;

		uint32_t				transaction_hash;

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

		coap_msg_id_t	next_tid;

		coap_option_key_t		last_option_key;

#if SMCP_USE_BSD_SOCKETS
		char					packet_bytes[SMCP_MAX_PACKET_LENGTH+1];
		struct sockaddr_in6		saddr;
		socklen_t				socklen;
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

	const char* proxy_url;

	PAIRING_STATE
};


extern smcp_status_t smcp_handle_request();

extern smcp_status_t smcp_handle_response();

extern smcp_status_t smcp_handle_list(smcp_node_t node,smcp_method_t method);

__END_DECLS

#endif // __SMCP_INTERNAL_H__
