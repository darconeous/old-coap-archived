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
#include <stdio.h>
#include <string.h>
//#include <sys/errno.h>

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


#define SMCP_DEFAULT_PORT           (61616)
#define SMCP_DEFAULT_PORT_CSTR      "61616"
#define SMCP_MAX_PACKET_LENGTH      (1200)
#define SMCP_MAX_HEADERS            (15)
#define SMCP_IPV6_MULTICAST_ADDRESS "FF02::5343:4D50"
#define SMCP_MAX_PATH_LENGTH        (127)
#define SMCP_MAX_URI_LENGTH \
        (SMCP_MAX_PATH_LENGTH + 7 + 6 + 8 * \
        4 + 7 + 2)

#ifndef IPv4_COMPATIBLE_IPv6_PREFIX
#define IPv4_COMPATIBLE_IPv6_PREFIX "::FFFF:"
#endif

#define SMCP_DEPRECATED

#include "coap.h"

__BEGIN_DECLS

#include "btree.h"

enum {
	SMCP_RESULT_CODE_CONTINUE = 100,

	SMCP_RESULT_CODE_OK = 200,
	SMCP_RESULT_CODE_CREATED = 201,
	SMCP_RESULT_CODE_ACK = 204,
	SMCP_RESULT_CODE_PARTIAL_CONTENT = 206,

	SMCP_RESULT_CODE_NOT_MODIFIED = 304,

	SMCP_RESULT_CODE_BAD_REQUEST = 400,
	SMCP_RESULT_CODE_UNAUTHORIZED = 401,
	SMCP_RESULT_CODE_FORBIDDEN = 403,
	SMCP_RESULT_CODE_NOT_FOUND = 404,
	SMCP_RESULT_CODE_METHOD_NOT_ALLOWED = 405,
	SMCP_RESULT_CODE_CONFLICT = 409,
	SMCP_RESULT_CODE_GONE = 410,
	SMCP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE = 415,
	SMCP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE = 416,

	SMCP_RESULT_CODE_INTERNAL_SERVER_ERROR = 500,
	SMCP_RESULT_CODE_NOT_IMPLEMENTED = 501,
	SMCP_RESULT_CODE_BAD_GATEWAY = 502,
	SMCP_RESULT_CODE_SERVICE_UNAVAILABLE = 503,
	SMCP_RESULT_CODE_GATEWAY_TIMEOUT = 504,
	SMCP_RESULT_CODE_PROTOCOL_VERSION_NOT_SUPPORTED = 505,
};

typedef enum {
	SMCP_METHOD_GET = 1,
	SMCP_METHOD_POST = 2,
	SMCP_METHOD_PUT = 3,    //!< @note UNUSED IN SMCP
	SMCP_METHOD_DELETE = 4, //!< @note UNUSED IN SMCP

	// Experimental after this point

	SMCP_METHOD_PAIR = 11,
	SMCP_METHOD_UNPAIR = 12,
} smcp_method_t;

static inline const char* smcp_code_to_cstr(int x) {
	switch(x) {
	case SMCP_METHOD_GET: return "GET"; break;
	case SMCP_METHOD_POST: return "POST"; break;
	case SMCP_METHOD_PUT: return "PUT"; break;
	case SMCP_METHOD_DELETE: return "DELETE"; break;

	case SMCP_METHOD_PAIR: return "PAIR"; break;
	case SMCP_METHOD_UNPAIR: return "UNPAIR"; break;

	case SMCP_RESULT_CODE_CONTINUE: return "CONTINUE"; break;
	case SMCP_RESULT_CODE_OK: return "OK"; break;
	case SMCP_RESULT_CODE_CREATED: return "CREATED"; break;
	case SMCP_RESULT_CODE_ACK: return "ACK"; break;
	case SMCP_RESULT_CODE_PARTIAL_CONTENT: return "PARTIAL_CONTENT"; break;

	case SMCP_RESULT_CODE_NOT_MODIFIED: return "NOT_MODIFIED"; break;

	case SMCP_RESULT_CODE_BAD_REQUEST: return "BAD_REQUEST"; break;
	case SMCP_RESULT_CODE_UNAUTHORIZED: return "UNAUTHORIZED"; break;
	case SMCP_RESULT_CODE_FORBIDDEN: return "FORBIDDEN"; break;
	case SMCP_RESULT_CODE_NOT_FOUND: return "NOT_FOUND"; break;
	case SMCP_RESULT_CODE_METHOD_NOT_ALLOWED: return "METHOD_NOT_ALLOWED";
		break;
	case SMCP_RESULT_CODE_CONFLICT: return "CONFLICT"; break;
	case SMCP_RESULT_CODE_GONE: return "GONE"; break;
	case SMCP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE: return
		    "UNSUPPORTED_MEDIA_TYPE"; break;

	case SMCP_RESULT_CODE_INTERNAL_SERVER_ERROR: return
		    "INTERNAL_SERVER_ERROR"; break;
	case SMCP_RESULT_CODE_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED"; break;
	case SMCP_RESULT_CODE_BAD_GATEWAY: return "BAD_GATEWAY"; break;
	case SMCP_RESULT_CODE_SERVICE_UNAVAILABLE: return "UNAVAILABLE"; break;
	case SMCP_RESULT_CODE_GATEWAY_TIMEOUT: return "TIMEOUT"; break;
	case SMCP_RESULT_CODE_PROTOCOL_VERSION_NOT_SUPPORTED: return
		    "PROTOCOL_VERSION_NOT_SUPPORTED"; break;
	default:  break;
	}
	return "UNKNOWN";
}

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
};

typedef int smcp_status_t;

static inline const char* smcp_status_to_cstr(int x) {
	switch(x) {
	case SMCP_STATUS_OK: return "OK"; break;
	case SMCP_STATUS_FAILURE: return "Unspecified Failure"; break;
	case SMCP_STATUS_INVALID_ARGUMENT: return "Invalid Argument"; break;
	case SMCP_STATUS_BAD_NODE_TYPE: return "Bad Node Type"; break;
	case SMCP_STATUS_UNSUPPORTED_URI: return "Unsupported URI"; break;
	case SMCP_STATUS_ERRNO:
#if 1
		return "ERRNO"; break;
#else
		return strerror(errno); break;
#endif
	case SMCP_STATUS_MALLOC_FAILURE: return "Malloc Failure"; break;
	case SMCP_STATUS_HANDLER_INVALIDATED: return "Handler Invalidated";
		break;
	case SMCP_STATUS_TIMEOUT: return "Timeout"; break;
	case SMCP_STATUS_NOT_IMPLEMENTED: return "Not Implemented"; break;
	case SMCP_STATUS_NOT_FOUND: return "Not Found"; break;
	case SMCP_STATUS_H_ERRNO: return "HERRNO"; break;
	case SMCP_STATUS_RESPONSE_NOT_ALLOWED: return "Response not allowed";
		break;
	}
	return NULL;
}

#define HEADER_CSTR_LEN     ((size_t)-1)

static inline const char* smcp_get_header_key_cstr(coap_header_key_t key)
{
	const char* ret = NULL;

	switch(key) {
	case COAP_HEADER_CONTENT_TYPE: ret = "Content-type"; break;
	case COAP_HEADER_MAX_AGE: ret = "Max-age"; break;
	case COAP_HEADER_ETAG: ret = "Etag"; break;
	case COAP_HEADER_URI_AUTHORITY: ret = "URI-authority"; break;
	case COAP_HEADER_LOCATION: ret = "Location"; break;
	case COAP_HEADER_URI_PATH: ret = "URI-path"; break;

	case COAP_HEADER_URI_SCHEME: ret = "URI-scheme"; break;
	case COAP_HEADER_URI_AUTHORITY_BINARY: ret = "URI-authority-binary";
		break;
	case COAP_HEADER_ACCEPT: ret = "Accept"; break;
	case COAP_HEADER_DATE: ret = "Date"; break;
	case COAP_HEADER_TOKEN: ret = "Token"; break;
	case COAP_HEADER_BLOCK: ret = "Block"; break;
	case COAP_HEADER_PAYLOAD_LENGTH: ret = "Payload-length"; break;

	case COAP_HEADER_CSEQ: ret = "Cseq"; break;
	case COAP_HEADER_NEXT: ret = "Next"; break;
	case COAP_HEADER_MORE: ret = "More"; break;
	case COAP_HEADER_ORIGIN: ret = "Origin"; break;
	case COAP_HEADER_ALLOW: ret = "Allow"; break;

	case COAP_HEADER_RANGE: ret = "Range"; break;

	default:
	{
		static char x[20];
		if(key % 14)
			sprintf(x, "Unknown-%u", key);
		else
			sprintf(x, "Ignore-%u", key);
		ret = x;
	}
	break;
	}
	return ret;
}

static inline coap_header_key_t smcp_get_header_key_from_cstr(
	const char* key) {
	if(strcasecmp(key, "Content-type") == 0)
		return COAP_HEADER_CONTENT_TYPE;
	else if(strcasecmp(key, "Max-age") == 0)
		return COAP_HEADER_MAX_AGE;
	else if(strcasecmp(key, "Etag") == 0)
		return COAP_HEADER_ETAG;
	else if(strcasecmp(key, "URI-authority") == 0)
		return COAP_HEADER_URI_AUTHORITY;
	else if(strcasecmp(key, "Location") == 0)
		return COAP_HEADER_LOCATION;
	else if(strcasecmp(key, "URI-path") == 0)
		return COAP_HEADER_URI_PATH;
	else if(strcasecmp(key, "Cseq") == 0)
		return COAP_HEADER_CSEQ;
	else if(strcasecmp(key, "Next") == 0)
		return COAP_HEADER_NEXT;
	else if(strcasecmp(key, "More") == 0)
		return COAP_HEADER_MORE;
	else if(strcasecmp(key, "Origin") == 0)
		return COAP_HEADER_ORIGIN;
	else if(strcasecmp(key, "Allow") == 0)
		return COAP_HEADER_ALLOW;

	return 0;
}

#define smcp_header_item_next(item)         ((item) + 1)
#define smcp_header_item_get_value(item)    ((item)->value)
#define smcp_header_item_get_key(item)      ((item)->key)

#define smcp_header_item_set_value(item, x)  ((item)->value = (x))
#define smcp_header_item_set_key(item, x)        ((item)->key = (x))

#define smcp_header_item_get_value_len(item)        ((item)->value_len)
#define smcp_header_item_key_equal(item, k)      ((item)->key == (k))
#define smcp_header_item_get_key_cstr(item) \
    smcp_get_header_key_cstr( \
	    smcp_header_item_get_key(item))


typedef enum {
	SMCP_CONTENT_TYPE_TEXT_PLAIN = 0,
	SMCP_CONTENT_TYPE_TEXT_XML = 1,
	SMCP_CONTENT_TYPE_TEXT_CSV = 2,
	SMCP_CONTENT_TYPE_TEXT_HTML = 3,

	SMCP_CONTENT_TYPE_IMAGE_GIF = 21,
	SMCP_CONTENT_TYPE_IMAGE_JPEG = 22,
	SMCP_CONTENT_TYPE_IMAGE_PNG = 23,
	SMCP_CONTENT_TYPE_IMAGE_TIFF = 24,

	SMCP_CONTENT_TYPE_APPLICATION_LINK_FORMAT = 40, //!< draft-shelby-core-link-format
	SMCP_CONTENT_TYPE_APPLICATION_XML = 41,
	SMCP_CONTENT_TYPE_APPLICATION_OCTET_STREAM = 42,
	SMCP_CONTENT_TYPE_APPLICATION_EXI = 47,

	// Experimental after this point

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
	SMCP_RESPONSE_HANDLER_ALWAYS_TIMEOUT = (1 << 0),
};

typedef int32_t cms_t;

typedef void (*smcp_response_handler_func)(smcp_daemon_t self,
    int statuscode, coap_header_item_t headers[], const char* content,
    size_t content_length, void* context);

typedef enum smcp_node_type_t {
	SMCP_NODE_DEVICE,
	SMCP_NODE_VARIABLE,
	SMCP_NODE_ACTION,   //!< Deprecated
	SMCP_NODE_EVENT,    //!< Deprecated
} smcp_node_type_t;

extern int smcp_convert_status_to_result_code(smcp_status_t status);


extern smcp_daemon_t smcp_daemon_create(uint16_t port);
extern smcp_daemon_t smcp_daemon_init(
	smcp_daemon_t self, uint16_t port);
extern void smcp_daemon_release(smcp_daemon_t self);

extern uint16_t smcp_daemon_get_port(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_process(
	smcp_daemon_t self, cms_t cms);                                     // Returns nonzero on error
extern cms_t smcp_daemon_get_timeout(smcp_daemon_t self);

extern smcp_node_t smcp_daemon_get_root_node(smcp_daemon_t self);

extern smcp_status_t smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	coap_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_response_handler_func	callback,
	void*						context);
extern smcp_status_t smcp_invalidate_response_handler(
	smcp_daemon_t self, coap_transaction_id_t tid);

extern smcp_status_t smcp_daemon_send_request(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	coap_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
extern smcp_status_t smcp_daemon_send_request_to_url(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				url,
	coap_header_item_t		headers[],
	const char*				content,
	size_t					content_length);

extern smcp_status_t smcp_daemon_send_response(
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);

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

extern smcp_node_t smcp_node_alloc();

extern smcp_device_node_t smcp_node_init_subdevice(
	smcp_node_t self, smcp_node_t parent, const char* name);
extern smcp_variable_node_t smcp_node_init_variable(
	smcp_node_t self, smcp_node_t parent, const char* name);
extern smcp_action_node_t smcp_node_init_action(
	smcp_node_t self, smcp_node_t parent, const char* name);
extern smcp_event_node_t smcp_node_init_event(
	smcp_node_t self, smcp_node_t parent, const char* name);


/*
   extern smcp_device_node_t smcp_node_init_subdevice(NULL,smcp_node_t node,const char* name);
   extern smcp_variable_node_t smcp_node_init_variable(NULL,smcp_node_t node,const char* name);
   extern smcp_action_node_t smcp_node_init_action(NULL,smcp_node_t node,const char* name);	//!< Deprecated
   extern smcp_event_node_t smcp_node_init_event(NULL,smcp_node_t node,const char* name);	//!< Deprecated
 */

extern void smcp_node_delete(smcp_node_t node);
extern smcp_status_t smcp_node_get_path(
	smcp_node_t node, char* path, size_t max_path_len);
extern smcp_node_t smcp_node_find_with_path(
	smcp_node_t node, const char* path);
extern int smcp_node_find_closest_with_path(
	smcp_node_t node, const char* path, smcp_node_t* closest);
extern int smcp_node_find_next_with_path(
	smcp_node_t node, const char* path, smcp_node_t* next);

extern smcp_status_t smcp_default_request_handler(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			relative_path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);

#pragma mark -
#pragma mark Pairing Functions

extern smcp_status_t smcp_daemon_pair_with_uri(
	smcp_daemon_t self, const char* path, const char* uri, int flags);
extern smcp_status_t smcp_daemon_trigger_event(
	smcp_daemon_t		self,
	const char*			path,
	const char*			content,
	size_t				content_length,
	smcp_content_type_t content_type);
extern smcp_status_t smcp_daemon_trigger_event_with_node(
	smcp_daemon_t		self,
	smcp_node_t			node,
	const char*			subpath,
	const char*			content,
	size_t				content_length,
	smcp_content_type_t content_type);
extern smcp_status_t smcp_daemon_refresh_variable(
	smcp_daemon_t daemon, smcp_variable_node_t node);


coap_transaction_id_t smcp_daemon_get_current_tid(smcp_daemon_t self);

#if SMCP_USE_BSD_SOCKETS
extern struct sockaddr* smcp_daemon_get_current_request_saddr(
	smcp_daemon_t self);
extern socklen_t smcp_daemon_get_current_request_socklen(
	smcp_daemon_t self);
#elif defined(__CONTIKI__)
extern const uip_ipaddr_t* smcp_daemon_get_current_request_ipaddr(
	smcp_daemon_t self);
extern const uint16_t smcp_daemon_get_current_request_ipport(
	smcp_daemon_t self);
#endif


__END_DECLS

#endif

#include "smcp_helpers.h"
