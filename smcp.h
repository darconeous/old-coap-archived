/*	Simple Monitoring and Control Protocol (SMCP)
**	Stack Implementation
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
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
#define SMCP_MAX_PACKET_LENGTH      (1500)
#define SMCP_MAX_HEADERS            (20)
#define SMCP_IPV6_MULTICAST_ADDRESS "FF02::5343:4D50"
#define SMCP_MAX_PATH_LENGTH        (256)

#ifndef IPv4_COMPATIBLE_IPv6_PREFIX
#define IPv4_COMPATIBLE_IPv6_PREFIX "::FFFF:"
#endif

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

#define SMCP_HEADER_ID          "Id"
#define SMCP_HEADER_CSEQ        "CSeq"
#define SMCP_HEADER_ALLOW       "Allow"
#define SMCP_HEADER_ORIGIN      "Origin"
#define SMCP_HEADER_CONTENT_TYPE        "Content-Type"

// Used with LIST method.
#define SMCP_HEADER_NEXT        "Next"  //! Optionally present in LIST request.
#define SMCP_HEADER_MORE        "More"  //! Optionally present in LIST response.

#define SMCP_METHOD_GET     "GET"
#define SMCP_METHOD_POST    "POST"
#define SMCP_METHOD_OPTIONS "OPTIONS"
#define SMCP_METHOD_PAIR    "PAIR"
#define SMCP_METHOD_UNPAIR  "UNPAIR"
#define SMCP_METHOD_LIST    "LIST"

#define SMCP_CONTENT_TYPE_FORM      "misc/x-smcp+form"

struct smcp_daemon_s;
typedef struct smcp_daemon_s *smcp_daemon_t;

struct smcp_node_s;
typedef struct smcp_node_s *smcp_node_t;

struct smcp_action_node_s;
typedef struct smcp_action_node_s *smcp_action_node_t;

struct smcp_event_node_s;
typedef struct smcp_event_node_s *smcp_event_node_t;

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
};


enum {
	SMCP_RESPONSE_HANDLER_ALWAYS_TIMEOUT = (1 << 0),
};


typedef int smcp_status_t;

typedef int32_t cms_t;

typedef void (*smcp_response_handler_func)(smcp_daemon_t self,
    const char* version, int statuscode, const char* headers[],
    const char* content, size_t content_length, SMCP_SOCKET_ARGS,
    void* context);

typedef enum smcp_node_type_t {
	SMCP_NODE_ACTION,
	SMCP_NODE_EVENT,
	SMCP_NODE_VARIABLE,
	SMCP_NODE_DEVICE,
} smcp_node_type_t;


extern smcp_daemon_t smcp_daemon_create(uint16_t port);
extern smcp_daemon_t smcp_daemon_init(
	smcp_daemon_t self, uint16_t port);
extern void smcp_daemon_release(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_process(
	smcp_daemon_t self, cms_t cms);                                     // Returns nonzero on error
extern cms_t smcp_daemon_get_timeout(smcp_daemon_t self);

extern smcp_node_t smcp_daemon_get_root_node(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_trigger_event(
	smcp_daemon_t	self,
	const char*		path,
	const char*		content,
	size_t			content_length,
	const char*		content_type);
extern smcp_status_t smcp_daemon_trigger_event_for_node(
	smcp_daemon_t		self,
	smcp_event_node_t	node,
	const char*			content,
	size_t				content_length,
	const char*			content_type);

extern smcp_status_t smcp_daemon_refresh_variable(
	smcp_daemon_t daemon, smcp_variable_node_t node);

extern smcp_status_t smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	const char*					idValue,
	cms_t						cmsExpiration,
	int							flags,
	smcp_response_handler_func	callback,
	void*						context);
extern smcp_status_t smcp_invalidate_response_handler(
	smcp_daemon_t self, const char* idValue);

extern smcp_status_t smcp_daemon_send_request(
	smcp_daemon_t	self,
	const char*		method,
	const char*		path,
	const char*		version,
	const char*		headers[],
	const char*		content,
	size_t			content_length,
	SMCP_SOCKET_ARGS);
extern smcp_status_t smcp_daemon_send_request_to_url(
	smcp_daemon_t	self,
	const char*		method,
	const char*		url,
	const char*		version,
	const char*		headers[],
	const char*		content,
	size_t			content_length);

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
	smcp_node_t node, const char* name);
extern smcp_variable_node_t smcp_node_add_variable(
	smcp_node_t node, const char* name);
extern smcp_event_node_t smcp_node_add_event(
	smcp_node_t node, const char* name);
extern void smcp_node_delete(smcp_node_t node);
extern smcp_status_t smcp_node_get_path(
	smcp_node_t node, char* path, size_t max_path_len);
extern smcp_node_t smcp_node_find_with_path(
	smcp_node_t node, const char* path);
extern smcp_status_t smcp_node_pair_with_uri(
	smcp_node_t node, const char* uri, int flags);
extern smcp_status_t smcp_node_pair_with_sockaddr(
	smcp_node_t node, SMCP_SOCKET_ARGS, const char* path, int flags);

extern int smcp_node_find_closest_with_path(
	smcp_node_t node, const char* path, smcp_node_t* closest);
extern int smcp_node_find_next_with_path(
	smcp_node_t node, const char* path, smcp_node_t* next);

__END_DECLS

#endif
