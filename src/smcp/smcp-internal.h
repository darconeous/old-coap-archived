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

#include "smcp.h"
#include "smcp-timer.h"
#include "fasthash.h"

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

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

#include "smcp-missing.h"
#include "string-utils.h"

__BEGIN_DECLS


#if SMCP_EMBEDDED
// Embedded platforms only support one instance.
#define smcp_set_current_instance(x)
#else
SMCP_INTERNAL_EXTERN void smcp_set_current_instance(smcp_t x);
#endif


#ifndef SMCP_HOOK_TIMER_NEEDS_REFRESH
#define SMCP_HOOK_TIMER_NEEDS_REFRESH(x)	do { } while (0)
#endif

// MARK: -
// MARK: Class Definitions

#if SMCP_USE_BSD_SOCKETS
#include "smcp-plat-bsd-internal.h"
#elif SMCP_USE_UIP
#include "smcp-plat-uip-internal.h"
#endif

#include "smcp-dupe.h"

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

	struct smcp_plat_s		plat;

	smcp_timer_t			timers;

	smcp_transaction_t		transactions;
	smcp_transaction_t		current_transaction;

	// Operational Flags
	uint8_t					is_responding:1,
							did_respond:1,
							is_processing_message:1,
#if SMCP_USE_CASCADE_COUNT
							has_cascade_count:1,
#endif
							force_current_outbound_code:1;

	coap_msg_id_t			last_msg_id;

	//! Inbound packet variables.
	struct {
		const struct coap_header_s*	packet;
		coap_size_t					packet_len;

		coap_option_key_t		last_option_key;
		const uint8_t*			this_option;

		const char*				content_ptr;
		coap_size_t				content_len;
		coap_content_type_t		content_type;

		uint8_t					was_sent_to_multicast:1,
								is_fake:1,
								is_dupe:1,
								has_observe_option:1;

		uint32_t				transaction_hash;

		int32_t					max_age;
		uint32_t				observe_value;
		uint32_t				block2_value;
	} inbound;

	//! Outbound packet variables.
	struct {
		struct coap_header_s*	packet;
		coap_size_t				max_packet_len;

		char*					content_ptr;
		coap_size_t				content_len;

		coap_msg_id_t           next_tid;

		coap_option_key_t		last_option_key;
	} outbound;

	struct smcp_dupe_info_s dupe_info;

	const char* proxy_url;

#if SMCP_CONF_ENABLE_VHOSTS
	struct smcp_vhost_s		vhost[SMCP_MAX_VHOSTS];
	uint8_t					vhost_count;
#endif

#if SMCP_USE_CASCADE_COUNT
	uint8_t					cascade_count;
#endif
};


//! Initializes an SMCP instance. Does not allocate any memory.
SMCP_API_EXTERN smcp_t smcp_init(smcp_t self);


SMCP_INTERNAL_EXTERN smcp_status_t smcp_handle_request();

SMCP_INTERNAL_EXTERN smcp_status_t smcp_handle_response();

SMCP_INTERNAL_EXTERN smcp_t smcp_plat_init(smcp_t self);
SMCP_INTERNAL_EXTERN void smcp_plat_finalize(smcp_t self);

SMCP_INTERNAL_EXTERN smcp_status_t smcp_outbound_set_var_content_int(int v);
SMCP_INTERNAL_EXTERN smcp_status_t smcp_outbound_set_var_content_unsigned_int(unsigned int v);
SMCP_INTERNAL_EXTERN smcp_status_t smcp_outbound_set_var_content_unsigned_long_int(unsigned long int v);


__END_DECLS

#endif // __SMCP_INTERNAL_H__
