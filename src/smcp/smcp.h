/*!	@file smcp.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Primary header
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

/*!	@mainpage SMCP - A C-Based CoAP Stack
**	SMCP is a C-based CoAP stack which is suitable for embedded environments.
**	Features include:
**
**	 * Supports draft-ietf-core-coap-13.
**	 * Fully asynchronous I/O.
**	 * Supports both BSD sockets and [UIP](http://en.wikipedia.org/wiki/UIP_(micro_IP%29).
**	 * Supports sending and receiving asynchronous CoAP responses.
**	 * Supports observing resources and offering observable resources.
**	 * Supports retransmission of confirmable transactions.
**	 * `smcpctl` - a powerful command line tool for browsing and configuring CoAP nodes.
**
**	Initial focus is on correctness of implementation. Stack usage and other
**	performance optimizations will become the focus later on.
**
**	## Why is it called *SMCP*? ##
**
**	Historical reasons. Don't think about it too much.
**
**	## Contiki Support ##
**
**	SMCP fully supports [Contiki](http://contiki-os.org/). To build the Contiki examples, just make
**	sure that the `CONTIKI` environment variable is set point to your Contiki
**	root, like so:
**
**		$ cd contiki-src/examples/smcp-simple
**		$ make CONTIKI=~/Projects/contiki TARGET=minimal-net
**
*/

#ifndef __SMCP_HEADER__
#define __SMCP_HEADER__ 1

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if !defined(__BEGIN_DECLS) || !defined(__END_DECLS)
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS		}
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#include "smcp-opts.h"
#include "smcp-helpers.h"

#include "coap.h"
#include "btree.h"

#ifdef CONTIKI
#include "contiki.h"
#endif

#if SMCP_USE_BSD_SOCKETS
#define __USE_GNU	1
#include <netinet/in.h>
#include <arpa/inet.h>
#define SMCP_SOCKET_ARGS	struct sockaddr* saddr, socklen_t socklen

#elif SMCP_USE_UIP
#define SMCP_SOCKET_ARGS	const uip_ipaddr_t *toaddr, uint16_t toport
#include "net/ip/uip.h"

#endif

#define SMCP_CSTR_LEN     ((size_t)-1)

/*!	@defgroup smcp SMCP
**	@{
*/


__BEGIN_DECLS

typedef int smcp_method_t;

enum {
	SMCP_STATUS_OK                  = 0,	//!< Success. No error.
	SMCP_STATUS_FAILURE             = -1,	//!< Unspecified failure.
	SMCP_STATUS_INVALID_ARGUMENT    = -2,	//!< An argument or parameter was out of spec.
	SMCP_STATUS_UNSUPPORTED_URI     = -4,	//!< The given URI is unsupported.
	SMCP_STATUS_ERRNO               = -5,	//!< Unix socket error. (errno)
	SMCP_STATUS_MALLOC_FAILURE      = -6,	//!< Out of memory.
	SMCP_STATUS_TRANSACTION_INVALIDATED = -7,
	SMCP_STATUS_TIMEOUT             = -8,	//!< Operation was taking too long.
	SMCP_STATUS_NOT_IMPLEMENTED     = -9,	//!< Feature hasn't been implemented.
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

/*!	@addtogroup smcp_timer
**	@{
*/

//!	Relative time period, in milliseconds.
typedef int32_t cms_t;

//!	Special `cms` value representing the distant future.
/*!	Note that this value does not refer to a specific time. */
#define CMS_DISTANT_FUTURE		(cms_t)((1<<(8*sizeof(cms_t)-1))-1)

/*!	@} */

typedef smcp_status_t (*smcp_callback_func)(void* context);

typedef smcp_callback_func smcp_request_handler_func;
typedef smcp_callback_func smcp_inbound_resend_func;

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
#define smcp_vhost_add(self,...)		smcp_vhost_add(__VA_ARGS__)
#define smcp_set_default_request_handler(self,...)		smcp_set_default_request_handler(__VA_ARGS__)
#else
#define SMCP_EMBEDDED_SELF_HOOK
#endif

#pragma mark -
#pragma mark SMCP Instance Methods

/*!	@defgroup smcp-instance Instance Methods
**	@{
**	@brief Initializing, Configuring, and Releasing the SMCP instance.
*/

//! Initializes an SMCP instance
extern smcp_t smcp_init(smcp_t self, uint16_t port);

//! Releases an SMCP instance, closing all ports and ending all transactions.
extern void smcp_release(smcp_t self);

//! Returns the current listening port of the instance in host order.
extern uint16_t smcp_get_port(smcp_t self);

#if SMCP_EMBEDDED
extern struct smcp_s smcp_global_instance;
#define smcp_get_current_instance() (&smcp_global_instance)
#else
//! Used from inside of callbacks to obtain a reference to the current instance.
extern smcp_t smcp_get_current_instance();

//! Allocates and initializes an SMCP instance.
extern smcp_t smcp_create(uint16_t port);
#endif

//!	Sets the URL to use as a CoAP proxy.
/*!	The proxy is used whenever the scheme is
**	unrecognised or the host does not appear
**	to be directly reachable. */
extern void smcp_set_proxy_url(smcp_t self,const char* url);

//!	Sets the default request handler.
/*!	Whenever the instance receives a request that isn't
**	directed at a recognised VHost or is intended for
**	a proxy, this callback will be called.
**
**	If the inbound message is confirmable and you don't
**	end up sending a response from the callback, a
**	response packet is generated based on the return
**	value of the callback. */
extern void smcp_set_default_request_handler(
	smcp_t self,
	smcp_request_handler_func request_handler,
	void* context
);

#if SMCP_CONF_ENABLE_VHOSTS
/*!	Adds a virtual host that will use the given request handler
**	instead of the default one.
**
**	This can also be used to implement groups. */
extern smcp_status_t smcp_vhost_add(
	smcp_t self,
	const char* name, //!^ Hostname of the virtual host
	smcp_request_handler_func request_handler,
	void* context
);
#endif

/*!	@} */

#pragma mark -
#pragma mark Async IO

/*!	@defgroup smcp-asyncio Asynchronous IO
**	@{
**	@brief Functions supporting non-blocking asynchronous IO.
*/

//!	Processes one event and (if using BSD sockets) processes one packet if available.
/*!	This function must be called periodically for SMCP to handle events and packets.
**	When using with BSD sockets, smcp_process() will wait for `cms` milliseconds
**	to see if a packet arrives. */
extern smcp_status_t smcp_process(smcp_t self, cms_t cms);

//!	Maximum amount of time that can pass before smcp_process() must be called again.
extern cms_t smcp_get_timeout(smcp_t self);

#if SMCP_USE_BSD_SOCKETS
//!	Gets the file descriptor for the UDP socket.
/*!	Useful for implementing asynchronous operation using select(),
**	poll(), or other async mechanisms. */
extern int smcp_get_fd(smcp_t self);

#elif SMCP_USE_UIP
extern struct uip_udp_conn* smcp_get_udp_conn(smcp_t self);
#endif

/*!	@} */

#pragma mark -
#pragma mark Inbound Packet Interface

/*!	@defgroup smcp-net Network Interface
**	@{
**	@brief Functions for manually handling inbound packets.
*/

//! Start describing the inbound packet.
/*!	If you are using BSD sockets, you don't need to use this function. */
extern smcp_status_t smcp_inbound_start_packet(
	smcp_t	self,
	char*	packet,
	size_t	packet_length
);

//! Sets the address from where this packet originated.
/*!	Must be called between smcp_inbound_start_packet() and smcp_inbound_finish_packet(). */
/*!	If you are using BSD sockets, you don't need to use this function. */
extern smcp_status_t smcp_inbound_set_srcaddr(SMCP_SOCKET_ARGS);

//! Sets the address to where this packet was sent to.
/*!	This method is optional in describing the inbound packet,
**	but it is necessary to correctly implement multicast behavior. */
/*!	Must be called between smcp_inbound_start_packet() and smcp_inbound_finish_packet(). */
/*!	If you are using BSD sockets, you don't need to use this function. */
extern smcp_status_t smcp_inbound_set_destaddr(SMCP_SOCKET_ARGS);

//! Call this function if the inbound packet has been truncated.
/*!	Calling this will instruct the instance to not process
**	this message and to only attempt to send back a 4.13 ENTITY_TOO_LARGE
**	response, if appropriate. You must still call smcp_inbound_set_srcaddr()
**	and smcp_inbound_finish_packet().
**
**	@note Not currently implemented. */
/*!	Must be called between smcp_inbound_start_packet() and smcp_inbound_finish_packet(). */
/*!	If you are using BSD sockets, you don't need to use this function. */
extern void smcp_inbound_packet_was_truncated(void);

//! Indicate that we are finished describing the inbound packet.
/*!	Must be called after smcp_inbound_start_packet(). */
/*!	If you are using BSD sockets, you don't need to use this function. */
extern smcp_status_t smcp_inbound_finish_packet();

/*!	@} */

#pragma mark -
#pragma mark Inbound Message Parsing API

/*!	@defgroup smcp-inbound Inbound Message Parsing API
**	@{
**	@brief These functions allow callbacks to examine the current inbound packet.
**
**	Calling these functions from outside
**	of an SMCP callback is an error.
*/

//!	Returns a pointer to the start of the current inbound CoAP packet.
extern const struct coap_header_s* smcp_inbound_get_packet();

//!	Returns the length of the inbound packet.
extern size_t smcp_inbound_get_packet_length();

//! Convenience macro for getting the code of the inbound packet.
#define smcp_inbound_get_code()		(smcp_inbound_get_packet()->code)

//! Convenience macro for getting the msg_id of the inbound packet.
#define smcp_inbound_get_msg_id()	(smcp_inbound_get_packet()->msg_id)

//! Returns true if SMCP thinks the inbound packet is a dupe.
extern bool smcp_inbound_is_dupe();

//! Returns true if the inbound packet is fake (to trigger updates for observers)
extern bool smcp_inbound_is_fake();

//! Returns true if SMCP thinks the inbound packet originated locally.
extern bool smcp_inbound_origin_is_local();

//!	Returns a pointer to the start of the inbound packet's content.
/*! Guaranteed to be NUL-terminated */
extern const char* smcp_inbound_get_content_ptr();

//!	Returns the length of the inbound packet's content.
extern size_t smcp_inbound_get_content_len();

//!	Convenience function for getting the content type of the inbound packet.
extern coap_content_type_t smcp_inbound_get_content_type();

#if SMCP_USE_BSD_SOCKETS
extern struct sockaddr* smcp_inbound_get_saddr();
extern socklen_t smcp_inbound_get_socklen();
#elif SMCP_USE_UIP
extern const uip_ipaddr_t* smcp_inbound_get_ipaddr();
extern const uint16_t smcp_inbound_get_ipport();
#endif

//! Retrieve the value and type of the next option in the header and move to the next header.
extern coap_option_key_t smcp_inbound_next_option(const uint8_t** ptr, size_t* len);

//! Retrieve the value and type of the next option in the header, WITHOUT moving to the next header.
extern coap_option_key_t smcp_inbound_peek_option(const uint8_t** ptr, size_t* len);

//!	Reset the option pointer to the start of the options.
extern void smcp_inbound_reset_next_option();

//!	Compares the key and value of the current option to specific c-string values.
extern bool smcp_inbound_option_strequal(coap_option_key_t key,const char* str);

#define smcp_inbound_option_strequal_const(key,const_str)	\
	smcp_inbound_option_strequal(key,const_str)

#define SMCP_GET_PATH_REMAINING			(1<<0)
#define SMCP_GET_PATH_LEADING_SLASH		(1<<1)
#define SMCP_GET_PATH_INCLUDE_QUERY		(1<<2)

//!	Get a string representation of the destination path in the inbound packet.
extern char* smcp_inbound_get_path(char* where,uint8_t flags);

/*!	@} */

#pragma mark -
#pragma mark Outbound Message Composing API

/*!	@defgroup smcp-outbound Outbound Message Composing API
**	@{
**	@brief These functions are for constructing outbound CoAP messages from an
**	       SMCP callback.
**
**	Calling these functions from outside of an SMCP callback is an error.
*/

extern smcp_status_t smcp_outbound_begin(
	smcp_t self,
	coap_code_t code,
	coap_transaction_type_t tt
);

//! Sets up the outbound packet as a response to the current inbound packet.
/*!	This function automatically makes sure that the destination address,
**	msg_id, and token are properly set up. */
extern smcp_status_t smcp_outbound_begin_response(coap_code_t code);

//!	Changes the code on the current outbound packet.
extern smcp_status_t smcp_outbound_set_code(coap_code_t code);

/*! Note that options MUST be added in order!
**	OK, that's a lie, but it's much faster if done this way! */
extern smcp_status_t smcp_outbound_add_option(coap_option_key_t key,const char* value,size_t len);

//!	Adds an option with a CoAP-encoded unsigned integer value.
extern smcp_status_t smcp_outbound_add_option_uint(coap_option_key_t key,uint32_t value);

//!	Sets the destination address and port.
/*!	Not necessary if you called smcp_outbound_begin_response(). */
extern smcp_status_t smcp_outbound_set_destaddr(
#if SMCP_USE_BSD_SOCKETS
	struct sockaddr *sockaddr,
	socklen_t socklen
#elif SMCP_USE_UIP
	const uip_ipaddr_t *toaddr,
	uint16_t toport
#endif
);

// These next four flags are for smcp_outbound_set_uri().
#define SMCP_MSG_SKIP_DESTADDR		(1<<0)
#define SMCP_MSG_SKIP_AUTHORITY		(1<<1)
#define SMCP_MSG_SKIP_PATH			(1<<2)
#define SMCP_MSG_SKIP_QUERY			(1<<3)

//!	Sets the destination URI for the outbound packet.
/*!	If the URL is not directly reachable and a proxy URL has been
**	defined, this function will automatically use the proxy. */
extern smcp_status_t smcp_outbound_set_uri(const char* uri,char flags);

/*!	After the following function is called you cannot add any more options
**	without loosing the content. */
extern char* smcp_outbound_get_content_ptr(
	size_t* max_len //^< [OUT] maximum content length
);

//!	Sets the actual length of the content. Called after smcp_outbound_get_content_ptr().
extern smcp_status_t smcp_outbound_set_content_len(size_t len);

extern smcp_status_t smcp_outbound_append_content(const char* value,size_t len);

#if !SMCP_AVOID_PRINTF
extern smcp_status_t smcp_outbound_set_content_formatted(const char* fmt, ...);

#define smcp_outbound_set_content_formatted_const(fmt,...)	\
	smcp_outbound_set_content_formatted(fmt,__VA_ARGS__)
#endif

//!	Sends the outbound packet.
/*!	After calling this function, you are done for this callback. You may not
**	call any other smcp_outbound_* functions. You may only send one outbound
**	packet per callback. */
extern smcp_status_t smcp_outbound_send();

//!	Convenience function to simply drop a packet.
extern void smcp_outbound_drop();

extern void smcp_outbound_reset();

//!	Sets the msg_id on the outbound packet.
/*!	@note In most cases msg_ids are handled automatically. You
**	      do not normally need to call this.
*/
extern smcp_status_t smcp_outbound_set_msg_id(coap_msg_id_t tid);

//!	Sets the token on the outbound packet.
/*!	@note In most cases tokens are handled automatically. You
**	      do not normally need to call this.
*/
extern smcp_status_t smcp_outbound_set_token(const uint8_t *token,uint8_t token_length);

//!	Useful for indicating errors.
extern smcp_status_t smcp_outbound_quick_response(coap_code_t code, const char* body);

//extern smcp_status_t smcp_outbound_set_var_content_int(int v) SMCP_DEPRECATED;
//extern smcp_status_t smcp_outbound_set_var_content_unsigned_int(unsigned int v) SMCP_DEPRECATED;
//extern smcp_status_t smcp_outbound_set_var_content_unsigned_long_int(unsigned long int v) SMCP_DEPRECATED;

/*!	@} */

#pragma mark -
#pragma mark Asynchronous response support API

/*!	@defgroup smcp_async Asynchronous response support API
**	@{
*/

#define SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK		(1<<0)

struct smcp_async_response_s {
#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6		saddr;
	socklen_t				socklen;
	struct in6_pktinfo		pktinfo;
#elif SMCP_USE_UIP
	uip_ipaddr_t			toaddr;
	uint16_t				toport;	// Always in network order.
#endif

	union {
		struct coap_header_s header;
		uint8_t bytes[80];
	} request;
	size_t request_len;
};

typedef struct smcp_async_response_s* smcp_async_response_t;

extern bool smcp_inbound_is_related_to_async_response(struct smcp_async_response_s* x);

extern smcp_status_t smcp_start_async_response(struct smcp_async_response_s* x,int flags);

extern smcp_status_t smcp_finish_async_response(struct smcp_async_response_s* x);

extern smcp_status_t smcp_outbound_begin_async_response(coap_code_t code, struct smcp_async_response_s* x);

/*!	@} */

#pragma mark -
#pragma mark Helper Functions

extern coap_msg_id_t smcp_get_next_msg_id(smcp_t self);

extern int smcp_convert_status_to_result_code(smcp_status_t status);

extern const char* smcp_status_to_cstr(smcp_status_t x);

__END_DECLS

/*!	@defgroup smcp-extras SMCP Extras
**	@{ @}
*/


/*!	@} */

#endif

#include "smcp-transaction.h"
#include "smcp-observable.h"
#include "smcp-helpers.h"
