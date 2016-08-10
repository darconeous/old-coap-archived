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
**	 * Supports RFC7252 <http://tools.ietf.org/html/rfc7252>.
**	 * Fully asynchronous I/O.
**	 * Supports both BSD sockets and [uIP](http://en.wikipedia.org/wiki/UIP_(micro_IP%29).
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef SMCP_CONFIG_OPTIONS_HEADER
#define SMCP_CONFIG_OPTIONS_HEADER "smcp-config.h"
#endif

#include "coap.h"

#include SMCP_CONFIG_OPTIONS_HEADER

#include "smcp-defaults.h"
#include "smcp-helpers.h"

#ifdef CONTIKI
#include "contiki.h"
#endif

#define SMCP_CSTR_LEN     ((coap_size_t)-1)

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
	SMCP_STATUS_MULTICAST_NOT_SUPPORTED		= -27,
	SMCP_STATUS_WAIT_FOR_SESSION    = -28,
	SMCP_STATUS_SESSION_ERROR       = -29,
	SMCP_STATUS_SESSION_CLOSED      = -30,
	SMCP_STATUS_OUT_OF_SESSIONS     = -31,
	SMCP_STATUS_UNSUPPORTED_MEDIA_TYPE = -32,
	//! When returned from a resend callback (in a transaction), stop sending packets without invalidate the transaction
	SMCP_STATUS_STOP_RESENDING		= -33
};

typedef int smcp_status_t;

struct smcp_s;
typedef struct smcp_s *smcp_t;

/*!	@addtogroup smcp_timer
**	@{
*/

//!	Relative time period, in milliseconds.
typedef int32_t smcp_cms_t;

//!	Absolute timestamp, platform-specific value.
typedef int32_t smcp_timestamp_t;

//!	Special `cms` value representing the distant future.
/*!	Note that this value does not refer to a specific time. */
#define CMS_DISTANT_FUTURE		INT32_MAX

/*!	@} */

typedef smcp_status_t (*smcp_callback_func)(void* context);

typedef smcp_callback_func smcp_request_handler_func;
typedef smcp_callback_func smcp_inbound_resend_func;

#if SMCP_EMBEDDED
// On embedded systems, we know we will always only have
// a single smcp instance, so we can save a considerable
// amount of stack space by simply removing the first argument
// from many functions. In order to make things as maintainable
// as possible, these macros do all of the work for us.
#define SMCP_EMBEDDED_SELF_HOOK		smcp_t const self = smcp_get_current_instance();(void)self
#define smcp_init(self)		smcp_init()
#define smcp_release(self)		smcp_release()
#define smcp_get_next_msg_id(self)		smcp_get_next_msg_id()
#define smcp_handle_request(self,...)		smcp_handle_request(__VA_ARGS__)
#define smcp_handle_response(self,...)		smcp_handle_response(__VA_ARGS__)
#define smcp_get_timeout(self)		smcp_get_timeout()
#define smcp_set_proxy_url(self,...)		smcp_set_proxy_url(__VA_ARGS__)
#define smcp_plat_get_udp_conn(self)		smcp_plat_get_udp_conn()
#define smcp_handle_inbound_packet(self,...)		smcp_handle_inbound_packet(__VA_ARGS__)
#define smcp_outbound_begin(self,...)		smcp_outbound_begin(__VA_ARGS__)
#define smcp_inbound_packet_process(self,...)		smcp_inbound_packet_process(__VA_ARGS__)
#define smcp_vhost_add(self,...)		smcp_vhost_add(__VA_ARGS__)
#define smcp_set_default_request_handler(self,...)		smcp_set_default_request_handler(__VA_ARGS__)

#define smcp_plat_get_port(self)		smcp_plat_get_port()
#define smcp_plat_init(self)		smcp_plat_init()
#define smcp_plat_finalize(self)		smcp_plat_finalize()
#define smcp_plat_get_fd(self)		smcp_plat_get_fd()
#define smcp_plat_wait(self,...)		smcp_plat_wait(__VA_ARGS__)
#define smcp_plat_process(self)		smcp_plat_process()

#define smcp_plat_outbound_start(self,...)		smcp_plat_outbound_start(__VA_ARGS__)
#define smcp_plat_outbound_finish(self,...)		smcp_plat_outbound_finish(__VA_ARGS__)
#define smcp_plat_bind_to_port(self,...)		smcp_plat_bind_to_port(__VA_ARGS__)
#define smcp_plat_bind_to_sockaddr(self,...)		smcp_plat_bind_to_sockaddr(__VA_ARGS__)


#else
#define SMCP_EMBEDDED_SELF_HOOK
#endif

#include "smcp-session.h"

#include "smcp-plat.h"


#if SMCP_EMBEDDED
#define SMCP_LIBRARY_VERSION_CHECK()	do { } while(0)
#else
#ifndef ___SMCP_CONFIG_ID
#define ___SMCP_CONFIG_ID 2
#endif
SMCP_API_EXTERN void ___smcp_check_version(uint32_t x);
#define SMCP_LIBRARY_VERSION_CHECK()	___smcp_check_version(___SMCP_CONFIG_ID)
#endif

// MARK: -
// MARK: SMCP Instance Methods

/*!	@defgroup smcp-instance Instance Methods
**	@{
**	@brief Initializing, Configuring, and Releasing the SMCP instance.
*/

//! Allocates and initializes an SMCP instance.
SMCP_API_EXTERN smcp_t smcp_create(void);

//! Releases an SMCP instance, closing all ports and ending all transactions.
SMCP_API_EXTERN void smcp_release(smcp_t self);

#if SMCP_EMBEDDED && !defined(DOXYGEN_SHOULD_SKIP_THIS)
SMCP_API_EXTERN struct smcp_s smcp_global_instance;
#define smcp_get_current_instance() (&smcp_global_instance)
#else
//! Used from inside of callbacks to obtain a reference to the current instance.
SMCP_API_EXTERN smcp_t smcp_get_current_instance(void);

#endif

//!	Sets the default request handler.
/*!	Whenever the instance receives a request that isn't
**	directed at a recognised vhost or is intended for
**	a proxy, this callback will be called.
**
**	If the inbound message is confirmable and you don't
**	end up sending a response from the callback, a
**	response packet is generated based on the return
**	value of the callback. */
SMCP_API_EXTERN void smcp_set_default_request_handler(
	smcp_t self,
	smcp_request_handler_func request_handler,
	void* context
);

#if SMCP_CONF_ENABLE_VHOSTS
/*!	Adds a virtual host that will use the given request handler
**	instead of the default one.
**
**	This can also be used to implement groups. */
SMCP_API_EXTERN smcp_status_t smcp_vhost_add(
	smcp_t self,
	const char* name, //!^ Hostname of the virtual host
	smcp_request_handler_func request_handler,
	void* context
);
#endif

//!	Sets the URL to use as a CoAP proxy.
/*!	The proxy is used whenever the scheme is
**	unrecognised or the host does not appear
**	to be directly reachable.
**
**	If SMCP_AVOID_MALLOC and SMCP_EMBEDDED are set then
**	the string IS NOT COPIED and used as is. If you
**	are building on an embedded platform, don't pass
**	in strings that are in temporary memory or that
**	live on the stack. */
SMCP_API_EXTERN void smcp_set_proxy_url(smcp_t self, const char* url);

/*!	@} */

// MARK: -
// MARK: Async IO

/*!	@defgroup smcp-asyncio Asynchronous IO
**	@{
**	@brief Functions supporting non-blocking asynchronous IO.
*/

//!	Maximum amount of time that can pass before smcp_plat_process() must be called again.
SMCP_API_EXTERN smcp_cms_t smcp_get_timeout(smcp_t self);

/*!	@} */

// MARK: -
// MARK: Inbound Packet Interface

/*!	@defgroup smcp-net Network Interface
**	@{
**	@brief Functions for manually handling inbound packets.
*/

#define SMCP_INBOUND_PACKET_TRUNCATED		(1 << 0)

//! Handles an inbound packet inbound packet.
/*!	This is useful if you need direct control over the ingress
**	of traffic or want to inject packets into the CoAP stack.
**
**	Before calling this function, you *MUST* at least call the
**	function `smcp_plat_set_remote_sockaddr()`, to set the address
**	of the sender of the packet. You can also call the following
**	functions if the default values are not appropriate:
**
**	* `smcp_plat_set_local_sockaddr()`: If not called, uses a
**    reasonable platform-specific value.
**	* `smcp_plat_set_session_type()`: If not called, uses the
**    value `SMCP_SESSION_TYPE_UDP`.
**
**	If you are using BSD sockets you don't need to use this function.
**
**	Calling this function with the flag SMCP_INBOUND_PACKET_TRUNCATED
**	will instruct the instance to not process this message and to only
**	attempt to send back a 4.13 ENTITY_TOO_LARGE response, if appropriate.
*/
SMCP_API_EXTERN smcp_status_t smcp_inbound_packet_process(
	smcp_t	self,
	char*	packet,
	coap_size_t	packet_length,
	int flags
);

//!	Handles asynchronous errors on outbound packets.
/*!	This is useful for reporting any ICMP errors
**	received back to SMCP so that they can be properly
**	handled.
**
**	Before calling this function, you *MUST* at least call the
**	function `smcp_plat_set_remote_sockaddr()`, to set the address
**	of the intended destination of the packet. You can also call
**	the following function if the default values are not appropriate:
**
**	* `smcp_plat_set_local_sockaddr()`: If not called, uses a
**    reasonable platform-specific value.
**
**	`packet` does not need to contain the entire contents
**	of the packet that generated the error. Whatever bits
**	of the packet that are given in the ICMP message will do.
**
**	If you are using BSD sockets you don't need to use this function.
*/
SMCP_API_EXTERN void smcp_outbound_packet_error(
	smcp_t	self,
	const struct coap_header_s* outbound_packet_header,
	smcp_status_t outbound_packet_error
);

/*!	@} */

// MARK: -
// MARK: Inbound Message Parsing API

/*!	@defgroup smcp-inbound Inbound Message Parsing API
**	@{
**	@brief These functions allow callbacks to examine the
**	       current inbound packet.
**
**	Calling these functions from outside
**	of an SMCP callback is a runtime error.
*/

//!	Returns a pointer to the start of the current inbound CoAP packet.
SMCP_API_EXTERN const struct coap_header_s* smcp_inbound_get_packet(void);

//!	Returns the length of the inbound packet.
SMCP_API_EXTERN coap_size_t smcp_inbound_get_packet_length(void);

//! Convenience macro for getting the code of the inbound packet.
#define smcp_inbound_get_code()		(smcp_inbound_get_packet()->code)

//! Convenience macro for getting the msg_id of the inbound packet.
#define smcp_inbound_get_msg_id()	(smcp_inbound_get_packet()->msg_id)

//! Returns true if SMCP thinks the inbound packet is a dupe.
SMCP_API_EXTERN bool smcp_inbound_is_dupe(void);

//! Returns true if the inbound packet is fake (to trigger updates for observers)
SMCP_API_EXTERN bool smcp_inbound_is_fake(void);

//! Returns true if the inbound packet is a multicast packet
SMCP_API_EXTERN bool smcp_inbound_is_multicast(void);

//! Returns true if SMCP thinks the inbound packet originated from the local machine.
SMCP_API_EXTERN bool smcp_inbound_origin_is_local(void);

//!	Returns a pointer to the start of the inbound packet's content.
/*! Guaranteed to be NUL-terminated */
SMCP_API_EXTERN const char* smcp_inbound_get_content_ptr(void);

//!	Returns the length of the inbound packet's content.
SMCP_API_EXTERN coap_size_t smcp_inbound_get_content_len(void);

//!	Convenience function for getting the content type of the inbound packet.
SMCP_API_EXTERN coap_content_type_t smcp_inbound_get_content_type(void);

//! Retrieve the value and type of the next option in the header and move to the next header.
SMCP_API_EXTERN coap_option_key_t smcp_inbound_next_option(const uint8_t** ptr, coap_size_t* len);

//! Retrieve the value and type of the next option in the header, WITHOUT moving to the next header.
SMCP_API_EXTERN coap_option_key_t smcp_inbound_peek_option(const uint8_t** ptr, coap_size_t* len);

//!	Reset the option pointer to the start of the options.
SMCP_API_EXTERN void smcp_inbound_reset_next_option(void);

//!	Compares the key and value of the current option to specific c-string values.
SMCP_API_EXTERN bool smcp_inbound_option_strequal(coap_option_key_t key, const char* str);

#define smcp_inbound_option_strequal_const(key,const_str)	\
	smcp_inbound_option_strequal(key,const_str)

#define SMCP_GET_PATH_REMAINING			(1<<0)
#define SMCP_GET_PATH_LEADING_SLASH		(1<<1)
#define SMCP_GET_PATH_INCLUDE_QUERY		(1<<2)

//!	Get a string representation of the destination path in the inbound packet.
SMCP_API_EXTERN char* smcp_inbound_get_path(char* where, uint8_t flags);

/*!	@} */

// MARK: -
// MARK: Outbound Message Composing API

/*!	@defgroup smcp-outbound Outbound Message Composing API
**	@{
**	@brief These functions are for constructing outbound CoAP messages from an
**	       SMCP callback.
**
**	Calling these functions from outside of an SMCP callback is an error.
*/

//!	Sets up the outbound packet as a request.
SMCP_API_EXTERN smcp_status_t smcp_outbound_begin(
	smcp_t self,
	coap_code_t code,
	coap_transaction_type_t tt
);

//! Sets up the outbound packet as a response to the current inbound packet.
/*!	This function automatically makes sure that the destination address,
**	msg_id, and token are properly set up. */
SMCP_API_EXTERN smcp_status_t smcp_outbound_begin_response(coap_code_t code);

//!	Changes the code on the current outbound packet.
SMCP_API_EXTERN smcp_status_t smcp_outbound_set_code(coap_code_t code);

SMCP_API_EXTERN smcp_status_t smcp_set_remote_sockaddr_from_host_and_port(const char* addr_str, uint16_t toport);


//!	Adds the given option to the outbound packet.
/*!
**	Tip: If `value` is a c-string, simply pass SMCP_CSTR_LEN
**	     as the value for `len` to avoid needing to explicitly
**	     call `strlen()`.
**
**	@note It is *much* faster to add options in numerical
**	      order than randomly. Whenever possible, add
**	      options in increasing order. */
SMCP_API_EXTERN smcp_status_t smcp_outbound_add_option(
	coap_option_key_t key,
	const char* value,
	coap_size_t len
);

//!	Adds an option with a CoAP-encoded unsigned integer value.
SMCP_API_EXTERN smcp_status_t smcp_outbound_add_option_uint(coap_option_key_t key, uint32_t value);

// These next four flags are for smcp_outbound_set_uri().
#define SMCP_MSG_SKIP_DESTADDR		(1<<0)
#define SMCP_MSG_SKIP_AUTHORITY		(1<<1)
#define SMCP_MSG_SKIP_PATH			(1<<2)
#define SMCP_MSG_SKIP_QUERY			(1<<3)

//!	Sets the destination URI for the outbound packet.
/*!	If the URL is not directly reachable and a proxy URL has been
**	defined, this function will automatically use the proxy. */
SMCP_API_EXTERN smcp_status_t smcp_outbound_set_uri(const char* uri, char flags);

//!	Retrieves the pointer to the content section of the outbound packet.
/*!	If you need to add content to your outbound message, call this function
**	and write your content to the location indicated by the returned pointer.
**	Do not write more than the number of bytes indicated in `max_len`.
**
**	After writing your data (or before, it doesn't really matter), use
**	smcp_outbound_set_content_len() to indicate the length of the content.
**
**	@warning After the following function is called you cannot add any
**	         more options without losing the content. Add all of your options
**	         first! */
SMCP_API_EXTERN char* smcp_outbound_get_content_ptr(
	coap_size_t* max_len //^< [OUT] maximum content length
);

SMCP_API_EXTERN coap_size_t smcp_outbound_get_space_remaining(void);

//!	Sets the actual length of the content. Called after smcp_outbound_get_content_ptr().
SMCP_API_EXTERN smcp_status_t smcp_outbound_set_content_len(coap_size_t len);

//!	Append the given data to the end of the packet.
/*!	This function automatically updates the content length. */
SMCP_API_EXTERN smcp_status_t smcp_outbound_append_content(const char* value, coap_size_t len);

#if !SMCP_AVOID_PRINTF
//!	Write to the content of the outbound message `printf` style.
SMCP_API_EXTERN smcp_status_t smcp_outbound_set_content_formatted(const char* fmt, ...);

#define smcp_outbound_set_content_formatted_const(fmt,...)	\
	smcp_outbound_set_content_formatted(fmt,__VA_ARGS__)
#endif

//!	Sends the outbound packet.
/*!	After calling this function, you are done for this callback. You may not
**	call any other smcp_outbound_* functions. You may only send one outbound
**	packet per callback. */
SMCP_API_EXTERN smcp_status_t smcp_outbound_send(void);

//!	Convenience function to simply drop a packet.
SMCP_API_EXTERN void smcp_outbound_drop(void);

SMCP_API_EXTERN void smcp_outbound_reset(void);

//!	Sets the msg_id on the outbound packet.
/*!	@note In most cases msg_ids are handled automatically. You
**	      do not normally need to call this.
*/
SMCP_API_EXTERN smcp_status_t smcp_outbound_set_msg_id(coap_msg_id_t tid);

//!	Sets the token on the outbound packet.
/*!	@note In most cases tokens are handled automatically. You
**	      do not normally need to call this.
*/
SMCP_API_EXTERN smcp_status_t smcp_outbound_set_token(const uint8_t *token, uint8_t token_length);

//!	Useful for indicating errors.
SMCP_API_EXTERN smcp_status_t smcp_outbound_quick_response(coap_code_t code, const char* body);

/*!	@} */

// MARK: -
// MARK: Helper Functions

SMCP_API_EXTERN coap_msg_id_t smcp_get_next_msg_id(smcp_t self);

SMCP_API_EXTERN coap_code_t smcp_convert_status_to_result_code(smcp_status_t status);

SMCP_API_EXTERN const char* smcp_status_to_cstr(smcp_status_t x);

__END_DECLS

/*!	@defgroup smcp-extras SMCP Extras
**	@{ @}
*/


/*!	@} */

#endif

#if SMCP_DTLS
#include "smcp-plat-ssl.h"
#endif

#include "smcp-async.h"
#include "smcp-transaction.h"
#include "smcp-observable.h"
#include "smcp-helpers.h"
#include "smcp-session.h"
