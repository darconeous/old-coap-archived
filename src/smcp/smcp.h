/*	@file smcp.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Primary header
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


#ifndef __SMCP_HEADER__
#define __SMCP_HEADER__ 1

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

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "smcp-opts.h"
#include "coap.h"

#include "btree.h"

#ifdef CONTIKI
#include "contiki.h"
#include "net/uip.h"
#endif

#if SMCP_USE_BSD_SOCKETS
#include <netinet/in.h>
#include <arpa/inet.h>
#define SMCP_SOCKET_ARGS	struct sockaddr* saddr, socklen_t socklen
#elif defined(CONTIKI)
#define SMCP_SOCKET_ARGS	const uip_ipaddr_t *toaddr, uint16_t toport
#include "net/uip.h"
#endif

#define HEADER_CSTR_LEN     ((size_t)-1)

__BEGIN_DECLS

typedef int smcp_method_t;

enum {
	SMCP_STATUS_OK                  = 0,
	SMCP_STATUS_FAILURE             = -1,
	SMCP_STATUS_INVALID_ARGUMENT    = -2,
	SMCP_STATUS_BAD_NODE_TYPE       = -3,
	SMCP_STATUS_UNSUPPORTED_URI     = -4,
	SMCP_STATUS_ERRNO               = -5,
	SMCP_STATUS_MALLOC_FAILURE      = -6,
	SMCP_STATUS_TRANSACTION_INVALIDATED = -7,
	SMCP_STATUS_TIMEOUT             = -8,
	SMCP_STATUS_NOT_IMPLEMENTED     = -9,
	SMCP_STATUS_NOT_FOUND           = -10,
	SMCP_STATUS_H_ERRNO             = -11,
	SMCP_STATUS_RESPONSE_NOT_ALLOWED = -12,
	SMCP_STATUS_BAD_HOSTNAME        = -13,
	SMCP_STATUS_LOOP_DETECTED       = -14,
	SMCP_STATUS_BAD_ARGUMENT        = -15,
	SMCP_STATUS_HOST_LOOKUP_FAILURE = -16,
	SMCP_STATUS_MESSAGE_TOO_BIG     = -17,
	SMCP_STATUS_NOT_ALLOWED			= -18,
	SMCP_STATUS_URI_PARSE_FAILURE	= -19,
	SMCP_STATUS_WAIT_FOR_DNS        = -20,
	SMCP_STATUS_BAD_OPTION			= -21,
	SMCP_STATUS_DUPE				= -22,
	SMCP_STATUS_RESET				= -23,
	SMCP_STATUS_ASYNC_RESPONSE		= -24,
};

typedef int smcp_status_t;

struct smcp_s;
typedef struct smcp_s *smcp_t;

struct smcp_node_s;
typedef struct smcp_node_s *smcp_node_t;


enum {
	SMCP_TRANSACTION_ALWAYS_TIMEOUT = (1 << 0),
	SMCP_TRANSACTION_OBSERVE = (1 << 1),
	SMCP_TRANSACTION_DELAY_START = (1 << 8),
};

typedef int32_t cms_t;

#define CMS_DISTANT_FUTURE		(cms_t)((1<<(8*sizeof(cms_t)-1))-1)

typedef void (*smcp_response_handler_func)(
	int statuscode,
	void* context
);

typedef smcp_status_t (*smcp_inbound_handler_func)(
	smcp_node_t node,
    smcp_method_t method
);

typedef smcp_status_t (*smcp_inbound_resend_func)(void* context);

#pragma mark -
#pragma mark SMCP Daemon methods

#if !SMCP_NO_MALLOC && !SMCP_EMBEDDED
extern smcp_t smcp_create(uint16_t port);
#endif

extern smcp_t smcp_init(smcp_t self, uint16_t port);

extern void smcp_release(smcp_t self);

extern uint16_t smcp_get_port(smcp_t self);


#if SMCP_EMBEDDED
extern struct smcp_s smcp_global_instance;
#define smcp_get_current_instance() (&smcp_global_instance)
#define smcp_get_root_node(x)		((smcp_node_t)&smcp_global_instance)
#define smcp_node_get_root(x)		((smcp_node_t)&smcp_global_instance)
#else
extern smcp_t smcp_get_current_instance(); // Used from callbacks
extern smcp_node_t smcp_get_root_node(smcp_t self);
extern smcp_node_t smcp_node_get_root(smcp_node_t node);
#endif

extern smcp_status_t smcp_process(smcp_t self, cms_t cms);

/*!	Returns the maximum amount of time that can pass before
**	smcp_process() must be called again. */
extern cms_t smcp_get_timeout(smcp_t self);

extern void smcp_set_proxy_url(smcp_t self,const char* url);

#pragma mark -
#pragma mark Network Interface

#if SMCP_USE_BSD_SOCKETS
/*!	Useful for implementing asynchronous operation using select(),
**	poll(), or other async mechanisms. */
extern int smcp_get_fd(smcp_t self);
#elif defined(CONTIKI)
extern struct uip_udp_conn* smcp_get_udp_conn(smcp_t self);
#endif

extern smcp_status_t smcp_handle_inbound_packet(
	smcp_t	self,
	char*			packet,
	size_t			packet_length,
	SMCP_SOCKET_ARGS
);

#pragma mark -
#pragma mark Transaction API

extern smcp_status_t smcp_begin_transaction(
	smcp_t self,
	coap_transaction_id_t tid,
	cms_t cmsExpiration,
	int	flags,
	smcp_inbound_resend_func requestResend,
	smcp_response_handler_func responseHandler,
	void* context
);

extern smcp_status_t smcp_invalidate_transaction(
	smcp_t self,
	coap_transaction_id_t tid
);

#pragma mark -
#pragma mark Inbound Message Parsing API

extern const struct coap_header_s* smcp_inbound_get_packet();

#define smcp_inbound_get_tid()	(smcp_inbound_get_packet()->tid)

/*! Guaranteed to be NUL-terminated */
extern const char* smcp_inbound_get_content_ptr();

extern size_t smcp_inbound_get_content_len();

extern coap_content_type_t smcp_inbound_get_content_type();

#if SMCP_USE_BSD_SOCKETS
extern struct sockaddr* smcp_inbound_get_saddr();
extern socklen_t smcp_inbound_get_socklen();
#elif CONTIKI
extern const uip_ipaddr_t* smcp_inbound_get_ipaddr();
extern const uint16_t smcp_inbound_get_ipport();
#endif

extern coap_option_key_t smcp_inbound_next_option(const uint8_t** ptr, size_t* len);

extern coap_option_key_t smcp_inbound_peek_option(const uint8_t** ptr, size_t* len);

//!	Reset the option pointer to the start of the options.
extern void smcp_inbound_reset_next_option();

//!	Compares the key and value of the current option to specific values.
extern bool smcp_inbound_option_strequal(coap_option_key_t key,const char* str);

#define smcp_inbound_option_strequal_const(key,const_str)	\
	smcp_inbound_option_strequal(key,const_str)

#pragma mark -
#pragma mark Outbound Message Composing API

extern smcp_status_t smcp_outbound_begin(
	smcp_t self,
	coap_code_t code,
	coap_transaction_type_t tt
);

extern void smcp_outbound_drop();

extern smcp_status_t smcp_outbound_begin_response(coap_code_t code);

extern smcp_status_t smcp_outbound_set_tid(coap_transaction_id_t tid);

extern smcp_status_t smcp_outbound_set_code(coap_code_t code);

extern smcp_status_t smcp_outbound_set_content_type(coap_content_type_t t);

/*! Note that options MUST be added in order! */
extern smcp_status_t smcp_outbound_add_option(coap_option_key_t key,const char* value,size_t len);

extern smcp_status_t smcp_outbound_set_destaddr(
#if SMCP_USE_BSD_SOCKETS
	struct sockaddr *sockaddr,
	socklen_t socklen
#elif defined(CONTIKI)
	const uip_ipaddr_t *toaddr,
	uint16_t toport
#endif
);

#define SMCP_MSG_SKIP_DESTADDR		(1<<0)
#define SMCP_MSG_SKIP_AUTHORITY		(1<<1)
#define SMCP_MSG_SKIP_PATH			(1<<2)
#define SMCP_MSG_SKIP_QUERY			(1<<3)

extern smcp_status_t smcp_outbound_set_uri(const char* uri,char flags);

/*!	After the following function is called you cannot add any more headers
**	without loosing the content. */
extern char* smcp_outbound_get_content_ptr(size_t* max_len);

extern smcp_status_t smcp_outbound_set_content_len(size_t len);

extern smcp_status_t smcp_outbound_append_content(const char* value,size_t len);

extern smcp_status_t smcp_outbound_set_content_formatted(const char* fmt, ...);

#define smcp_outbound_set_content_formatted_const(fmt,...)	\
	smcp_outbound_set_content_formatted(fmt,__VA_ARGS__)

extern smcp_status_t smcp_outbound_set_var_content_int(int v);

extern smcp_status_t smcp_outbound_set_var_content_unsigned_int(unsigned int v);

extern smcp_status_t smcp_outbound_set_var_content_unsigned_long_int(unsigned long int v);

extern smcp_status_t smcp_outbound_send();

#pragma mark -
#pragma mark Asynchronous response support API

#define SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK		(1<<0)

struct smcp_async_response_s {
#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6		saddr;
	socklen_t				socklen;
#elif CONTIKI
	uip_ipaddr_t			toaddr;
	uint16_t				toport;	// Always in network order.
#endif

	coap_transaction_id_t original_tid;
	coap_transaction_type_t tt;

	uint8_t token_len;
	uint8_t token_value[COAP_MAX_TOKEN_SIZE];
};

typedef struct smcp_async_response_s* smcp_async_response_t;

extern smcp_status_t smcp_start_async_response(struct smcp_async_response_s* x,int flags);

extern smcp_status_t smcp_finish_async_response(struct smcp_async_response_s* x);

extern smcp_status_t smcp_outbound_set_async_response(struct smcp_async_response_s* x);

#pragma mark -
#pragma mark Node Functions

extern smcp_node_t smcp_node_alloc();

extern smcp_node_t smcp_node_init(
	smcp_node_t self,
	smcp_node_t parent,
	const char* name		// Unescaped.
);

extern void smcp_node_delete(smcp_node_t node);


extern smcp_status_t smcp_node_get_path(
	smcp_node_t node,
	char* path,
	size_t max_path_len
);

extern smcp_node_t smcp_node_find(
	smcp_node_t node,
	const char* name,		// Unescaped.
	int name_len
);

extern smcp_node_t smcp_node_find_with_path(
	smcp_node_t node,
	const char* path		// Fully escaped path.
);

extern int smcp_node_find_closest_with_path(
	smcp_node_t node,
	const char* path,		// Fully escaped path.
	smcp_node_t* closest
);

extern int smcp_node_find_next_with_path(
	smcp_node_t node,
	const char* path,		// Fully escaped path.
	smcp_node_t* next
);

extern smcp_status_t smcp_default_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
);

#pragma mark -
#pragma mark Helper Functions

extern coap_transaction_id_t smcp_get_next_tid(smcp_t self, void* context);

extern int smcp_convert_status_to_result_code(smcp_status_t status);

extern const char* smcp_status_to_cstr(smcp_status_t x);

__END_DECLS

#endif

#include "smcp-helpers.h"
