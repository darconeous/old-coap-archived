/*	Simple Monitoring and Control Protocol (SMCP)
**	Stack Implementation
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/


#ifndef __SMCP_HEADER__
#define __SMCP_HEADER__ 1

#define SMCP_PAIRINGS_ARE_IN_NODES 1

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

#ifdef __CONTIKI__
#include "contiki.h"
#include "net/uip.h"
#define SMCP_USE_BSD_SOCKETS    0
#endif

#ifdef __APPLE__
#define SMCP_FUNC_RANDOM_UINT32()   arc4random()
#endif

#ifndef SMCP_FUNC_RANDOM_UINT32
#define SMCP_FUNC_RANDOM_UINT32()   random()
#endif

#ifndef SMCP_USE_BSD_SOCKETS
#define SMCP_USE_BSD_SOCKETS    1
#endif

#if SMCP_USE_BSD_SOCKETS
#include <netinet/in.h>
#include <arpa/inet.h>
#define SMCP_SOCKET_ARGS        struct sockaddr* saddr, socklen_t socklen
#endif

#if !SMCP_USE_BSD_SOCKETS && defined(__CONTIKI__)
#define SMCP_SOCKET_ARGS \
    const uip_ipaddr_t *toaddr, \
    uint16_t toport
#endif


#define SMCP_DEFAULT_PORT           (29280)
#define SMCP_MAX_PACKET_LENGTH      (1200)
#define SMCP_MAX_HEADERS            (15)
#define SMCP_IPV6_MULTICAST_ADDRESS "FF02::5343:4D50"
#define SMCP_MAX_PATH_LENGTH        (256)

#ifndef IPv4_COMPATIBLE_IPv6_PREFIX
#define IPv4_COMPATIBLE_IPv6_PREFIX "::FFFF:"
#endif

#define SMCP_DEPRECATED

__BEGIN_DECLS

#include "btree.h"

enum {
	SMCP_RESULT_CODE_OK = 200,
	SMCP_RESULT_CODE_CREATED = 201,
	SMCP_RESULT_CODE_ACK = 204,

	SMCP_RESULT_CODE_BAD_REQUEST = 400,
	SMCP_RESULT_CODE_UNAUTHORIZED = 401,
	SMCP_RESULT_CODE_FORBIDDEN = 403,
	SMCP_RESULT_CODE_NOT_FOUND = 404,
	SMCP_RESULT_CODE_METHOD_NOT_ALLOWED = 405,
	SMCP_RESULT_CODE_CONFLICT = 409,
	SMCP_RESULT_CODE_GONE = 410,

	SMCP_RESULT_CODE_INTERNAL_SERVER_ERROR = 500,
	SMCP_RESULT_CODE_NOT_IMPLEMENTED = 501,
	SMCP_RESULT_CODE_SERVICE_UNAVAILABLE = 503,
	SMCP_RESULT_CODE_GATEWAY_TIMEOUT = 504,
	SMCP_RESULT_CODE_PROTOCOL_VERSION_NOT_SUPPORTED = 505,
};

typedef uint16_t smcp_transaction_id_t;

#define HEADER_CSTR_LEN     ((size_t)-1)

#define USE_COAP_COMPATIBLE_HEADERS 0
#if USE_COAP_COMPATIBLE_HEADERS
typedef enum {
	SMCP_HEADER_CONTENT_TYPE = 1,
	SMCP_HEADER_MAX_AGE = 2,
	SMCP_HEADER_ETAG = 4,           //!< @note UNUSED IN SMCP
	SMCP_HEADER_URI_AUTHORITY = 5,  //!< @note UNUSED IN SMCP
	SMCP_HEADER_LOCATION = 6,       //!< @note UNUSED IN SMCP
	SMCP_HEADER_URI_PATH = 9,       //!< @note UNUSED IN SMCP

	SMCP_HEADER_CSEQ = 10,
	SMCP_HEADER_NEXT = 11,
	SMCP_HEADER_MORE = 12,
	SMCP_HEADER_ORIGIN = 13,
} smcp_header_key_t;

typedef struct {
	smcp_header_key_t	key;
	char*				value;
	size_t				value_len;
} smcp_header_item_t;

#define smcp_header_item_next(item)         ((item) + 1)
#define smcp_header_item_get_value(item)    ((item)->value)
#define smcp_header_item_get_key(item)      ((item)->key)
#define smcp_header_item_get_value_len(item)        ((item)->value_len)
#define smcp_header_item_key_equal(item, k)      ((item)->key == (k))

#else
typedef const char* smcp_header_key_t;
typedef const char* smcp_header_item_t;

#define smcp_header_item_next(item)         ((item) + 2)
#define smcp_header_item_get_key(item)      ((item)[0])
#define smcp_header_item_get_value(item)    ((item)[1])
#define smcp_header_item_get_value_len(item)        HEADER_CSTR_LEN
#define smcp_header_item_key_equal(item, k)  (strcmp((item)[0], (k)) == 0)

//#define SMCP_HEADER_ID			"Id"
#define SMCP_HEADER_CSEQ        "CSeq"
#define SMCP_HEADER_ALLOW       "Allow"
#define SMCP_HEADER_ORIGIN      "Origin"
#define SMCP_HEADER_CONTENT_TYPE        "Content-Type"
#define SMCP_HEADER_MAX_AGE     "Max-Age"
#define SMCP_HEADER_ETAG        "Etag"

// Used with LIST method.
#define SMCP_HEADER_NEXT        "Next"  //! Optionally present in LIST request.
#define SMCP_HEADER_MORE        "More"  //! Optionally present in LIST response.

#endif

typedef enum {
	SMCP_METHOD_GET = 1,
	SMCP_METHOD_POST = 2,
	SMCP_METHOD_PUT = 3,    //!< @note UNUSED IN SMCP
	SMCP_METHOD_DELETE = 4, //!< @note UNUSED IN SMCP
	SMCP_METHOD_LIST = 5,
	SMCP_METHOD_OPTIONS = 6,
	SMCP_METHOD_PAIR = 7,
	SMCP_METHOD_UNPAIR = 8,
} smcp_method_t;

typedef enum {
	SMCP_CONTENT_TYPE_TEXT_PLAIN = 0,
	SMCP_CONTENT_TYPE_TEXT_XML = 1,
	SMCP_CONTENT_TYPE_TEXT_CSV = 2,
	SMCP_CONTENT_TYPE_TEXT_HTML = 3,

	SMCP_CONTENT_TYPE_APPLICATION_LINK_FORMAT = 40,
	SMCP_CONTENT_TYPE_APPLICATION_OCTET_STREAM = 42,

	SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED = 99, //!< SMCP Specific
} smcp_content_type_t;

struct smcp_daemon_s;
typedef struct smcp_daemon_s *smcp_daemon_t;

struct smcp_node_s;
typedef struct smcp_node_s *smcp_node_t;

struct smcp_action_node_s;                              //!< Deprecated
typedef struct smcp_action_node_s *smcp_action_node_t;  //!< Deprecated

struct smcp_event_node_s;                               //!< Deprecated
typedef struct smcp_event_node_s *smcp_event_node_t;    //!< Deprecated

struct smcp_variable_node_s;
typedef struct smcp_variable_node_s *smcp_variable_node_t;

struct smcp_device_node_s;
typedef struct smcp_device_node_s *smcp_device_node_t;

struct smcp_pairing_s;
typedef struct smcp_pairing_s *smcp_pairing_t;

enum {
	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_MASK
	**	@abstract Bitmask for obtaining the reliability from
	**	          pairing flags.
	*/
	SMCP_PARING_FLAG_RELIABILITY_MASK = (3 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_NONE
	**	@abstract Events are transmitted unreliably.
	*/
	SMCP_PARING_FLAG_RELIABILITY_NONE = (0 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_ASAP
	**	@abstract Events are transmitted reliably out-of-order.
	**	          Order-of-events is maintained per-pairing.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_ASAP = (1 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_PART
	**	@abstract Events transmitted and will be retransmitted
	**	          until either the event is ACKed or the event
	**	          is superceded by a more recent event.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_PART = (2 << 0),

	/*!	@enum SMCP_PARING_FLAG_RELIABILITY_FULL
	**	@abstract Events are transmitted reliably and in-order.
	**	          Order-of-events is maintained per-pairing.
	**	          NOTE: Currently unimplemented!
	*/
	SMCP_PARING_FLAG_RELIABILITY_FULL = (3 << 0),

	/*!	@enum SMCP_PARING_FLAG_TEMPORARY
	**	@abstract Pairing is not to be comitted to
	**	          non-volatile storage.
	*/
	SMCP_PARING_FLAG_TEMPORARY = (1 << 2),
};

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
};


enum {
	SMCP_RESPONSE_HANDLER_ALWAYS_TIMEOUT = (1 << 0),
};


typedef int smcp_status_t;

typedef int32_t cms_t;

typedef void (*smcp_response_handler_func)(smcp_daemon_t self,
    int statuscode, smcp_header_item_t headers[], const char* content,
    size_t content_length, SMCP_SOCKET_ARGS, void* context);

typedef enum smcp_node_type_t {
	SMCP_NODE_DEVICE,
	SMCP_NODE_VARIABLE,
	SMCP_NODE_ACTION,   //!< Deprecated
	SMCP_NODE_EVENT,    //!< Deprecated
} smcp_node_type_t;


extern smcp_daemon_t smcp_daemon_create(uint16_t port);
extern smcp_daemon_t smcp_daemon_init(
	smcp_daemon_t self, uint16_t port);
extern void smcp_daemon_release(smcp_daemon_t self);

extern uint16_t smcp_daemon_get_port(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_process(
	smcp_daemon_t self, cms_t cms);                                     // Returns nonzero on error
extern cms_t smcp_daemon_get_timeout(smcp_daemon_t self);

extern smcp_node_t smcp_daemon_get_root_node(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_trigger_event(
	smcp_daemon_t		self,
	const char*			path,
	const char*			content,
	size_t				content_length,
	smcp_content_type_t content_type);
extern smcp_status_t smcp_daemon_trigger_event_for_node(
	smcp_daemon_t		self,
	smcp_event_node_t	node,
	const char*			content,
	size_t				content_length,
	smcp_content_type_t content_type);

extern smcp_status_t smcp_daemon_refresh_variable(
	smcp_daemon_t daemon, smcp_variable_node_t node);

extern smcp_status_t smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	smcp_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_response_handler_func	callback,
	void*						context);
extern smcp_status_t smcp_invalidate_response_handler(
	smcp_daemon_t self, smcp_transaction_id_t tid);

extern smcp_status_t smcp_daemon_send_request(
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
extern smcp_status_t smcp_daemon_send_request_to_url(
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				url,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length);

#pragma mark -
#pragma mark Network Interface

#if SMCP_USE_BSD_SOCKETS
extern int smcp_daemon_get_fd(smcp_daemon_t self);
#elif defined(__CONTIKI__)
extern struct uip_udp_conn* smcp_daemon_get_udp_conn(smcp_daemon_t self);
#endif

extern smcp_status_t smcp_daemon_handle_inbound_packet(
	smcp_daemon_t	self,
	char*			packet,
	size_t			packet_length,
	SMCP_SOCKET_ARGS);


#pragma mark -
#pragma mark Node Functions

extern smcp_device_node_t smcp_node_add_subdevice(
	smcp_node_t node, const char* name);
extern smcp_action_node_t smcp_node_add_action(
	smcp_node_t node, const char* name);                                            //!< Deprecated
extern smcp_variable_node_t smcp_node_add_variable(
	smcp_node_t node, const char* name);
extern smcp_event_node_t smcp_node_add_event(
	smcp_node_t node, const char* name);                                            //!< Deprecated
extern void smcp_node_delete(smcp_node_t node);
extern smcp_status_t smcp_node_get_path(
	smcp_node_t node, char* path, size_t max_path_len);
extern smcp_node_t smcp_node_find_with_path(
	smcp_node_t node, const char* path);


extern smcp_status_t smcp_daemon_pair_with_uri(
	smcp_daemon_t self, const char* path, const char* uri, int flags);


extern int smcp_node_find_closest_with_path(
	smcp_node_t node, const char* path, smcp_node_t* closest);
extern int smcp_node_find_next_with_path(
	smcp_node_t node, const char* path, smcp_node_t* next);

__END_DECLS

#endif
