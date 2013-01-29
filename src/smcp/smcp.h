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

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "smcp-opts.h"
#include "smcp-helpers.h"

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
	SMCP_STATUS_UNAUTHORIZED		= -25,
	SMCP_STATUS_BAD_PACKET			= -26,
};

typedef int smcp_status_t;

struct smcp_s;
typedef struct smcp_s *smcp_t;

struct smcp_node_s;
typedef struct smcp_node_s *smcp_node_t;


typedef int32_t cms_t;

#define CMS_DISTANT_FUTURE		(cms_t)((1<<(8*sizeof(cms_t)-1))-1)


// Returning pretty much anything here except SMCP_STATUS_OK will
// cause the handler to invalidate.
typedef smcp_status_t (*smcp_response_handler_func)(
	int statuscode,
	void* context
);

typedef smcp_status_t (*smcp_inbound_handler_func)(
	smcp_node_t node,
    smcp_method_t method
);

typedef smcp_status_t (*smcp_inbound_resend_func)(void* context);

struct smcp_transaction_s;
typedef struct smcp_transaction_s *smcp_transaction_t;

#pragma mark -
#pragma mark SMCP Daemon methods

#if SMCP_EMBEDDED
// On embedded systems, we know we will always only have
// a single smcp instance, so we can save a considerable
// amount of stack spaces by simply removing the first argument
// from many functions. In order to make things as maintainable
// as possible, these macros do all of the work for us.
#define SMCP_EMBEDDED_SELF_HOOK 	smcp_t const self = smcp_get_current_instance()
#define smcp_init(self,...)		smcp_init(__VA_ARGS__)
#define smcp_release(self)		smcp_release()
#define smcp_get_next_msg_id(self)		smcp_get_next_msg_id()
#define smcp_get_port(self)		smcp_get_port()
#define smcp_process(self,...)		smcp_process(__VA_ARGS__)
#define smcp_handle_request(self,...)		smcp_handle_request(__VA_ARGS__)
#define smcp_handle_response(self,...)		smcp_handle_response(__VA_ARGS__)
#define smcp_get_timeout(self)		smcp_get_timeout()
#define smcp_set_proxy_url(self,...)		smcp_set_proxy_url(__VA_ARGS__)
#define smcp_get_fd(self)		smcp_get_fd()
#define smcp_get_udp_conn(self)		smcp_get_udp_conn()
#define smcp_handle_inbound_packet(self,...)		smcp_handle_inbound_packet(__VA_ARGS__)
#define smcp_outbound_begin(self,...)		smcp_outbound_begin(__VA_ARGS__)
#define smcp_inbound_start_packet(self,...)		smcp_inbound_start_packet(__VA_ARGS__)
#define smcp_add_group(self,...)		smcp_add_group(__VA_ARGS__)
#else
#define SMCP_EMBEDDED_SELF_HOOK
#endif


extern smcp_t smcp_init(smcp_t self, uint16_t port);

extern void smcp_release(smcp_t self);

extern uint16_t smcp_get_port(smcp_t self);

#if SMCP_CONF_ENABLE_GROUPS
extern smcp_status_t smcp_add_group(smcp_t self,const char* name,smcp_node_t root_node,const char* addr);
#endif

#if SMCP_EMBEDDED
extern struct smcp_s smcp_global_instance;
#define smcp_get_current_instance() (&smcp_global_instance)
#define smcp_get_root_node(x)		((smcp_node_t)&smcp_global_instance)
#define smcp_node_get_root(x)		((smcp_node_t)&smcp_global_instance)
#else
extern smcp_t smcp_get_current_instance(); // Used from callbacks
extern smcp_node_t smcp_get_root_node(smcp_t self);
extern smcp_node_t smcp_node_get_root(smcp_node_t node);
extern smcp_t smcp_create(uint16_t port);
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

//! Start describing the inbound packet.
extern smcp_status_t smcp_inbound_start_packet(
	smcp_t	self,
	char*			packet,
	size_t			packet_length
);

//! Sets the address from where this packet originated.
extern smcp_status_t smcp_inbound_set_srcaddr(SMCP_SOCKET_ARGS);

//! Sets the address to where this packet was sent to.
/*!	This method is optional in describing the inbound packet,
**	but it is necessary to correctly implement multicast behavior. */
extern smcp_status_t smcp_inbound_set_destaddr(SMCP_SOCKET_ARGS);

//! Indicate that we are finished describing the inbound packet.
extern smcp_status_t smcp_inbound_finish_packet();

//! Deprecated.
extern smcp_status_t smcp_handle_inbound_packet(
	smcp_t	self,
	char*			packet,
	size_t			packet_length,
	SMCP_SOCKET_ARGS
);

#pragma mark -
#pragma mark Inbound Message Parsing API

extern const struct coap_header_s* smcp_inbound_get_packet();
extern size_t smcp_inbound_get_packet_length();

#define smcp_inbound_get_msg_id()	(smcp_inbound_get_packet()->msg_id)

extern bool smcp_inbound_is_dupe();

extern bool smcp_inbound_origin_is_local();

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

#define SMCP_GET_PATH_REMAINING			(1<<0)
#define SMCP_GET_PATH_LEADING_SLASH		(1<<1)
#define SMCP_GET_PATH_INCLUDE_QUERY		(1<<2)

extern char* smcp_inbound_get_path(char* where,uint8_t flags);

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

extern smcp_status_t smcp_outbound_set_msg_id(coap_msg_id_t tid);

extern smcp_status_t smcp_outbound_set_code(coap_code_t code);

extern smcp_status_t smcp_outbound_set_content_type(coap_content_type_t t);

/*! Note that options MUST be added in order!
**	OK, that's a lie, but it's much faster if done this way! */
extern smcp_status_t smcp_outbound_add_option(coap_option_key_t key,const char* value,size_t len);

extern smcp_status_t smcp_outbound_add_option_uint(coap_option_key_t key,uint32_t value);

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

	union {
		struct coap_header_s header;
		uint8_t bytes[128];
	} request;
	size_t request_len;
};

typedef struct smcp_async_response_s* smcp_async_response_t;

extern smcp_status_t smcp_start_async_response(struct smcp_async_response_s* x,int flags);

extern smcp_status_t smcp_finish_async_response(struct smcp_async_response_s* x);

extern smcp_status_t smcp_outbound_set_async_response(struct smcp_async_response_s* x);

extern smcp_status_t smcp_outbound_set_token(const uint8_t *token,uint8_t token_length);

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

extern coap_msg_id_t smcp_get_next_msg_id(smcp_t self);

extern int smcp_convert_status_to_result_code(smcp_status_t status);

extern const char* smcp_status_to_cstr(smcp_status_t x);

__END_DECLS

#endif

#include "smcp-transaction.h"
#include "smcp-helpers.h"
