/*	Simple Monitoring and Control Protocol (SMCP)
**	Stack Implementation
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
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
//#include <sys/errno.h>

#ifdef CONTIKI
#include "contiki.h"
#include "net/uip.h"
#define SMCP_USE_BSD_SOCKETS    0
#endif

#ifdef __APPLE__
#define SMCP_FUNC_RANDOM_UINT32()   arc4random()
#endif

#ifndef SMCP_FUNC_RANDOM_UINT32
#define SMCP_FUNC_RANDOM_UINT32() \
        ((uint32_t)random() ^ \
            ((uint32_t)random() << 16))
#endif

#ifndef SMCP_USE_BSD_SOCKETS
#define SMCP_USE_BSD_SOCKETS    1
#endif

#if SMCP_USE_BSD_SOCKETS
#include <netinet/in.h>
#include <arpa/inet.h>
#define SMCP_SOCKET_ARGS        struct sockaddr* saddr, socklen_t socklen
#endif

#if !SMCP_USE_BSD_SOCKETS && defined(CONTIKI)
#define SMCP_SOCKET_ARGS \
    const uip_ipaddr_t *toaddr, \
    uint16_t toport
#include "net/uip.h"
#endif

#ifndef SMCP_EMBEDDED
#define SMCP_EMBEDDED		defined(CONTIKI)
#endif

#if SMCP_EMBEDDED
#define SMCP_NON_RECURSIVE	static
#else
#define SMCP_NON_RECURSIVE
#endif

#ifndef SMCP_DEPRECATED
#if __GCC_VERSION__
#define SMCP_DEPRECATED
#else
#define SMCP_DEPRECATED __attribute__ ((deprecated))
#endif
#endif

#include "coap.h"

#define SMCP_DEFAULT_PORT           COAP_DEFAULT_PORT
#define SMCP_DEFAULT_PORT_CSTR      #COAP_DEFAULT_PORT
#if CONTIKI
#define SMCP_MAX_PACKET_LENGTH \
        ((UIP_BUFSIZE - UIP_LLH_LEN - \
            UIP_IPUDPH_LEN))
#else
#define SMCP_MAX_PACKET_LENGTH      ((size_t)1200)
#endif
#define SMCP_MAX_CONTENT_LENGTH     (512)
#define SMCP_MAX_HEADERS            (15)
#define SMCP_IPV6_MULTICAST_ADDRESS "FF02::5343:4D50"
#define SMCP_MAX_PATH_LENGTH        (127) // TODO: Should this be 270 instead...?
#define SMCP_MAX_URI_LENGTH \
        (SMCP_MAX_PATH_LENGTH + 7 + 6 + 8 * \
        4 + 7 + 2)

#ifndef IPv4_COMPATIBLE_IPv6_PREFIX
#define IPv4_COMPATIBLE_IPv6_PREFIX "::FFFF:"
#endif

#define SMCP_MAX_CASCADE_COUNT      (128)

__BEGIN_DECLS

#include "btree.h"


typedef int smcp_method_t;

enum {
	SMCP_STATUS_OK                  = 0,
	SMCP_STATUS_FAILURE             = -1,
	SMCP_STATUS_INVALID_ARGUMENT    = -2,
	SMCP_STATUS_BAD_NODE_TYPE       = -3,
	SMCP_STATUS_UNSUPPORTED_URI     = -4,
	SMCP_STATUS_ERRNO               = -5,
	SMCP_STATUS_MALLOC_FAILURE      = -6,
	SMCP_STATUS_HANDLER_INVALIDATED = -7,
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
};

typedef int smcp_status_t;

extern const char* smcp_status_to_cstr(smcp_status_t x);


#define HEADER_CSTR_LEN     ((size_t)-1)

struct smcp_daemon_s;
typedef struct smcp_daemon_s *smcp_daemon_t;

struct smcp_node_s;
typedef struct smcp_node_s *smcp_node_t;


enum {
	SMCP_TRANSACTION_ALWAYS_TIMEOUT = (1 << 0),
	SMCP_TRANSACTION_DELAY_START = (1 << 8),
};

typedef int32_t cms_t;

typedef void (*smcp_response_handler_func)(
	int statuscode,
	void* context
);

typedef smcp_status_t (*smcp_request_handler_func)(
	smcp_node_t node,
    smcp_method_t method
);

extern int smcp_convert_status_to_result_code(smcp_status_t status);


extern smcp_daemon_t smcp_daemon_create(uint16_t port);
extern smcp_daemon_t smcp_daemon_init(
	smcp_daemon_t self, uint16_t port);
extern void smcp_daemon_release(smcp_daemon_t self);

extern uint16_t smcp_daemon_get_port(smcp_daemon_t self);

//! Returns nonzero on error
extern smcp_status_t smcp_daemon_process(smcp_daemon_t self, cms_t cms);

extern cms_t smcp_daemon_get_timeout(smcp_daemon_t self);

extern smcp_node_t smcp_daemon_get_root_node(smcp_daemon_t self);

typedef smcp_status_t (*smcp_request_resend_func)(void* context);

extern smcp_status_t smcp_begin_transaction(
	smcp_daemon_t self,
	coap_transaction_id_t tid,
	cms_t cmsExpiration,
	int	flags,
	smcp_request_resend_func requestResend,
	smcp_response_handler_func responseHandler,
	void* context
);

extern smcp_status_t smcp_invalidate_transaction(
	smcp_daemon_t self,
	coap_transaction_id_t tid
);

#pragma mark -
#pragma mark Constrained sending API
//// New API for sending messages. This API should be more efficient for constrained devices.

extern smcp_status_t smcp_message_begin(
	smcp_daemon_t self,
	coap_code_t code,
	coap_transaction_type_t tt
);

extern smcp_status_t smcp_message_begin_response(coap_code_t code);

extern smcp_status_t smcp_message_set_tid(coap_transaction_id_t tid);

extern smcp_status_t smcp_message_set_code(coap_code_t code);

extern smcp_status_t smcp_message_set_content_type(coap_content_type_t t);

extern smcp_status_t smcp_message_set_content_formatted(const char* fmt, ...);
extern smcp_status_t smcp_message_set_var_content_int(int v);
extern smcp_status_t smcp_message_set_var_content_unsigned_int(unsigned int v);
extern smcp_status_t smcp_message_set_var_content_unsigned_long_int(unsigned long int v);

#if SMCP_USE_BSD_SOCKETS
extern smcp_status_t smcp_message_set_destaddr(
	struct sockaddr *sockaddr, socklen_t socklen);
#elif defined(CONTIKI)
extern smcp_status_t smcp_message_set_destaddr(
	const uip_ipaddr_t *toaddr, uint16_t toport);
#endif

#define SMCP_MSG_SKIP_DESTADDR		(1<<0)
#define SMCP_MSG_SKIP_AUTHORITY		(1<<1)
#define SMCP_MSG_SKIP_PATH			(1<<2)
#define SMCP_MSG_SKIP_QUERY			(1<<3)
extern smcp_status_t smcp_message_set_uri(
	const char* uri,
	char flags
);

extern smcp_status_t smcp_message_add_header(
	coap_option_key_t key,
	const char* value,
	size_t len
);

/*!	After the following function is called you cannot add any more headers
**	without loosing the content. */
extern char* smcp_message_get_content_ptr(size_t* max_len);
extern smcp_status_t smcp_message_set_content_len(size_t len);

extern smcp_status_t smcp_message_set_content(const char* value,size_t len);
extern smcp_status_t smcp_message_send();

#pragma mark -
#pragma mark Network Interface

#if SMCP_USE_BSD_SOCKETS
extern int smcp_daemon_get_fd(smcp_daemon_t self);
#elif defined(CONTIKI)
extern struct uip_udp_conn* smcp_daemon_get_udp_conn(smcp_daemon_t self);
#endif

extern smcp_status_t smcp_daemon_handle_inbound_packet(
	smcp_daemon_t	self,
	char*			packet,
	size_t			packet_length,
	SMCP_SOCKET_ARGS
);


#pragma mark -
#pragma mark Node Functions

extern smcp_node_t smcp_node_alloc();

extern smcp_node_t smcp_node_init(
	smcp_node_t self,
	smcp_node_t parent,
	const char* name		// Unescaped.
);

extern void smcp_node_delete(smcp_node_t node);

extern smcp_node_t smcp_node_get_root(smcp_node_t node);

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

coap_transaction_id_t smcp_daemon_get_current_tid();


/*! Guaranteed to be NUL-terminated */
extern const char* smcp_daemon_get_current_inbound_content_ptr();

extern size_t smcp_daemon_get_current_inbound_content_len();
extern coap_content_type_t smcp_daemon_get_current_inbound_content_type();

#if SMCP_USE_BSD_SOCKETS
extern struct sockaddr* smcp_daemon_get_current_request_saddr();
extern socklen_t smcp_daemon_get_current_request_socklen();
#elif defined(CONTIKI)
extern const uip_ipaddr_t* smcp_daemon_get_current_request_ipaddr();
extern const uint16_t smcp_daemon_get_current_request_ipport();
#endif

extern smcp_daemon_t smcp_get_current_daemon(); // Used from callbacks

extern coap_option_key_t smcp_current_request_next_header(const uint8_t** ptr, size_t* len);
extern coap_option_key_t smcp_current_request_peek_header(const uint8_t** ptr, size_t* len);
//extern void smcp_current_request_rewind_last_header();
extern bool smcp_current_request_header_strequal(coap_option_key_t key,const char* str);
#define smcp_current_request_header_strequal_const(key,str)	smcp_current_request_header_strequal(key,str);
extern const struct coap_header_s* smcp_current_request_get_packet();

#pragma mark -

struct smcp_async_response_s {
	coap_transaction_id_t original_tid;
	coap_transaction_type_t tt;
	uint8_t token_len;
	uint8_t token_value[COAP_MAX_TOKEN_SIZE];
#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6		saddr;
	socklen_t				socklen;
#elif CONTIKI
	uip_ipaddr_t			toaddr;
	uint16_t				toport;	// Always in network order.
#endif
};
typedef struct smcp_async_response_s* smcp_async_response_t;

extern smcp_status_t smcp_start_async_response(struct smcp_async_response_s* x);
extern smcp_status_t smcp_finish_async_response(struct smcp_async_response_s* x);
extern smcp_status_t smcp_message_set_async_response(struct smcp_async_response_s* x);

extern void smcp_daemon_set_proxy_url(smcp_daemon_t self,const char* url);
extern void smcp_current_request_reset_next_header();

__END_DECLS

#endif

#include "smcp_helpers.h"
