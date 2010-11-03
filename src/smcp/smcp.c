/*	Simple Home Automation Protocol (SMCP)
**	Stack Implementation
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#define SMCP_VERSION_STRING "SMCP/0.1"

#ifdef __CONTIKI__
#include "contiki.h"
#include "net/uip-udp-packet.h"
#include "net/uiplib.h"
#include "net/tcpip.h"
#include "net/resolv.h"
#endif

#include "assert_macros.h"

#include "smcp.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ll.h"

#include "url-helpers.h"
#include "smcp_node.h"
#include "smcp_pairing.h"
#include "smcp_logging.h"

#if SMCP_USE_BSD_SOCKETS
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "smcp_helpers.h"

#include "smcp_timer.h"
#include "smcp_internal.h"

// Remove this when we get the node system cleaned up.
//#include "smcp_variable_node.h"

#pragma mark -
#pragma mark Macros

#pragma mark -
#pragma mark Private Functions

#if VERBOSE_DEBUG
static const char*
get_method_string(smcp_method_t method) {
	const char* method_string = NULL;

	switch(method) {
	case COAP_METHOD_GET: method_string = "GET"; break;
	case COAP_METHOD_POST: method_string = "POST"; break;
	case COAP_METHOD_PUT: method_string = "PUT"; break;
	case COAP_METHOD_DELETE: method_string = "DELETE"; break;
	case COAP_METHOD_PAIR: method_string = "PAIR"; break;
	case COAP_METHOD_UNPAIR: method_string = "UNPAIR"; break;
	}
	return method_string;
}
#endif

/*
   static smcp_method_t
   get_method_index(const char* method_string) {
    if(strcmp(method_string,"GET")==0)
        return COAP_METHOD_GET;
    else if(strcmp(method_string,"POST")==0)
        return COAP_METHOD_POST;
    else if(strcmp(method_string,"PUT")==0)
        return COAP_METHOD_PUT;
    else if(strcmp(method_string,"DELETE")==0)
        return COAP_METHOD_DELETE;
    else if(strcmp(method_string,"PAIR")==0)
        return COAP_METHOD_PAIR;
    else if(strcmp(method_string,"UNPAIR")==0)
        return COAP_METHOD_UNPAIR;

    return 0;
   }
 */

/*
   static coap_content_type_t
   get_content_type_index(const char* content_type_string) {
    if(strcmp(content_type_string,"text/plain")==0)
        return COAP_CONTENT_TYPE_TEXT_PLAIN;
    else if(strcmp(content_type_string,"application/x-www-form-urlencoded")==0)
        return COAP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;
    else if(strcmp(content_type_string,"text/csv")==0)
        return COAP_CONTENT_TYPE_TEXT_CSV;
    else if(strcmp(content_type_string,"text/xml")==0)
        return COAP_CONTENT_TYPE_TEXT_XML;
    return COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM;
   }
 */

#pragma mark -
#pragma mark Other

const char* smcp_status_to_cstr(int x) {
	switch(x) {
	case SMCP_STATUS_HOST_LOOKUP_FAILURE: return "Hostname Lookup Failure";
		break;
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

#pragma mark -
#pragma mark Private SMCP Types


static bt_compare_result_t
smcp_response_handler_compare(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_response_handler_t lhs = (smcp_response_handler_t)lhs_;
	const smcp_response_handler_t rhs = (smcp_response_handler_t)rhs_;

	if(lhs->tid > rhs->tid)
		return 1;
	if(lhs->tid < rhs->tid)
		return -1;
	return 0;
}

static bt_compare_result_t
smcp_response_handler_compare_str(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_response_handler_t lhs = (smcp_response_handler_t)lhs_;
	coap_transaction_id_t rhs = strtol((const char*)rhs_, NULL, 10);

	if(lhs->tid > rhs)
		return 1;
	if(lhs->tid < rhs)
		return -1;
	return 0;
}

static bt_compare_result_t
smcp_response_handler_compare_tid(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_response_handler_t lhs = (smcp_response_handler_t)lhs_;
	coap_transaction_id_t rhs = *(coap_transaction_id_t*)rhs_;

	if(lhs->tid > rhs)
		return 1;
	if(lhs->tid < rhs)
		return -1;
	return 0;
}


#if defined(__CONTIKI__)
struct smcp_daemon_s smcp_daemon_global_instance;
#endif

#pragma mark -
#pragma mark Declarations


smcp_status_t smcp_daemon_handle_list(
	smcp_daemon_t	self,
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length);

smcp_status_t smcp_invalidate_response_handler(
	smcp_daemon_t self, coap_transaction_id_t tid);
smcp_status_t smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	coap_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_response_handler_func	callback,
	void*						context);

smcp_status_t smcp_daemon_handle_request(
	smcp_daemon_t	self,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length);
smcp_status_t smcp_daemon_handle_response(
	smcp_daemon_t	self,
	int				statuscode,
	const char*		content,
	size_t			content_length);

#pragma mark -
#pragma mark SMCP Implementation

smcp_daemon_t
smcp_daemon_create(uint16_t port) {
	smcp_daemon_t ret = NULL;

	ret = (smcp_daemon_t)calloc(1, sizeof(struct smcp_daemon_s));

	require(ret != NULL, bail);

	ret = smcp_daemon_init(ret, port);

bail:
	return ret;
}

smcp_daemon_t
smcp_daemon_init(
	smcp_daemon_t ret, uint16_t port
) {
	if(port == 0)
		port = SMCP_DEFAULT_PORT;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
		.sin6_family	= AF_INET6,
		.sin6_port		= htons(port),
	};
#endif

	require(ret != NULL, bail);

#if SMCP_USE_BSD_SOCKETS
	ret->fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	require_action_string(ret->fd > 0, bail, { smcp_daemon_release(
				ret); ret = NULL; }, "Failed to create socket");

	if(bind(ret->fd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
		require_action_string(errno == EADDRINUSE, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_daemon_release(
				    ret); ret = NULL; }, "Failed to bind socket");

		saddr.sin6_port = 0;
		require_action_string(bind(ret->fd, (struct sockaddr*)&saddr,
				sizeof(saddr)) == 0, bail, { DEBUG_PRINTF(CSTR(
						"errno=%d"), errno); smcp_daemon_release(
					ret); ret = NULL;
			}, "Failed to bind socket to port zero");
	}
#elif __CONTIKI__

	ret->udp_conn = udp_new(NULL, 0, NULL);
	uip_udp_bind(ret->udp_conn, htons(port));
	ret->udp_conn->rport = 0;
#endif

#if SMCP_USE_BSD_SOCKETS
	{   // Join the multicast group for SMCP_IPV6_MULTICAST_ADDRESS
		struct ipv6_mreq imreq;
		int btrue = 1;
		struct hostent *tmp = gethostbyname2(SMCP_IPV6_MULTICAST_ADDRESS,
			AF_INET6);
		memset(&imreq, 0, sizeof(imreq));
		ret->mcfd = socket(AF_INET6, SOCK_DGRAM, 0);

		require(!h_errno && tmp, bail);
		require(tmp->h_length > 1, bail);

		memcpy(&imreq.ipv6mr_multiaddr.s6_addr, tmp->h_addr_list[0], 16);

		require(0 ==
			setsockopt(ret->mcfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				&btrue,
				sizeof(btrue)), bail);

		// Do a precautionary leave group, to clear any stake kernel data.
		setsockopt(ret->mcfd,
			IPPROTO_IPV6,
			IPV6_LEAVE_GROUP,
			&imreq,
			sizeof(imreq));

		require(0 ==
			setsockopt(ret->mcfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &imreq,
				sizeof(imreq)), bail);
	}
#endif

	ret->port = port;
	ret->is_processing_message = false;
	require_string(smcp_node_init(&ret->root_node,
			NULL,
			NULL) != NULL, bail, "Unable to initialize root node");

bail:
	return ret;
}

void
smcp_daemon_release(smcp_daemon_t self) {
	require(self, bail);

	// Delete all response handlers
	while(self->handlers) {
		smcp_invalidate_response_handler(self, self->handlers->tid);
	}

	// Delete all timers
	while(self->timers) {
		smcp_timer_t timer = self->timers;
		if(timer->cancel)
			timer->cancel(self, timer->context);
		smcp_daemon_invalidate_timer(self, timer);
	}

	// Delete all nodes
	smcp_node_delete(smcp_daemon_get_root_node(self));

#if SMCP_USE_BSD_SOCKETS
	close(self->fd);
	close(self->mcfd);
#elif __CONTIKI__
	if(self->udp_conn)
		uip_udp_remove(self->udp_conn);
#endif

	// TODO: Make sure we were actually alloc'd!
	free(self);
bail:
	return;
}

uint16_t
smcp_daemon_get_port(smcp_daemon_t self) {
	return self->port;
}

#if SMCP_USE_BSD_SOCKETS
int
smcp_daemon_get_fd(smcp_daemon_t self) {
	return self->fd;
}
#elif defined(__CONTIKI__)
struct uip_udp_conn*
smcp_daemon_get_udp_conn(smcp_daemon_t self) {
	return self->udp_conn;
}
#endif

const char* smcp_get_status_description(smcp_status_t statuscode) {
	switch(statuscode) {
	case SMCP_STATUS_OK:
		return "OK";
		break;
	case SMCP_STATUS_FAILURE:
		return "FAILURE";
		break;
	case SMCP_STATUS_INVALID_ARGUMENT:
		return "INVALID_ARGUMENT";
		break;
	case SMCP_STATUS_BAD_NODE_TYPE:
		return "BAD_NODE_TYPE";
		break;
	case SMCP_STATUS_UNSUPPORTED_URI:
		return "UNSUPPORTED_URI";
		break;
	default:
		return "UNKNOWN";
		break;
	}
}

smcp_status_t
smcp_daemon_send_response(
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = 0;

#if __CONTIKI__
	char* const packet = (char*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
#else
	char packet[SMCP_MAX_PACKET_LENGTH + 1] = {};
#endif
	coap_transaction_id_t tid = self->current_inbound_request_tid;
	size_t packet_length = 0;
	int header_count = 0;
	int extra_headers = 0;

	if(headers) {
		coap_header_item_t* next_header;
		for(next_header = headers;
		    next_header && smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header))
			header_count++;
	}

	if(self->current_inbound_request_token)
		extra_headers++;

	coap_header_item_t headers_[extra_headers ? header_count +
	    extra_headers : 0];

	require_action_string(!self->did_respond,
		bail,
		ret = SMCP_STATUS_RESPONSE_NOT_ALLOWED,
		"Attempted to send more than one response!");

	if(extra_headers) {
		memset(headers_, 0, sizeof(coap_header_item_t) *
			    (header_count + extra_headers));

		if(headers)
			memcpy(headers_,
				headers,
				sizeof(coap_header_item_t) * header_count);
		headers = headers_;
		header_count += extra_headers;

		if(self->current_inbound_request_token) {
			util_add_header(headers,
				header_count,
				COAP_HEADER_TOKEN,
				self->current_inbound_request_token,
				self->current_inbound_request_token_len);
		}
	}

	packet_length = coap_encode_header(
		    (unsigned char*)packet,
		SMCP_MAX_PACKET_LENGTH,
		COAP_TRANS_TYPE_ACK,
		http_to_coap_code(statuscode),
		tid,
		headers,
		header_count
	    );

	require_action(content_length <=
		    (SMCP_MAX_PACKET_LENGTH - packet_length),
		bail,
		ret = SMCP_STATUS_MESSAGE_TOO_BIG);

	memcpy(packet + packet_length, content, content_length);

	packet_length += content_length;

	DEBUG_PRINTF(CSTR(
			"%p: sending response tid=%d, size=%d, statuscode=%d (coap_code = %d)"),
		self, tid, (int)packet_length, statuscode,
		http_to_coap_code(statuscode));

#if SMCP_USE_BSD_SOCKETS
	require_action(0 <
		sendto(self->fd, packet, packet_length, 0,
			self->current_inbound_saddr,
			self->current_inbound_socklen), bail, {
		    ret = SMCP_STATUS_ERRNO;
		    DEBUG_PRINTF(CSTR("Unable to send: errno = %d (%s)"), errno,
				strerror(errno));
		});
#elif __CONTIKI__
	uip_udp_packet_sendto(
		self->udp_conn,
		packet,
		packet_length,
		&self->current_inbound_toaddr,
		self->current_inbound_toport
	);
#endif

	self->did_respond = true;

bail:
	return ret;
}

smcp_status_t
smcp_daemon_send_request(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	const char*				query,
	coap_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;

#if __CONTIKI__
	char* const packet = &uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
#else
	char packet[SMCP_MAX_PACKET_LENGTH + 1] = {};
#endif
	size_t packet_length = 0;
	int header_count = 0;
	int extra_headers = 0;


	// Remove any leading slashes.
	while(path && path[0] == '/') path++;

	if(headers) {
		coap_header_item_t* iter;
		for(iter = headers; iter->key; iter++)
			header_count++;
	}

	if(path && (path[0] != 0))
		extra_headers++;

	if(query && (query[0] != 0))
		extra_headers++;

	if(self->is_processing_message) {
		require_action(self->cascade_count != 0xFF,
			bail,
			ret = SMCP_STATUS_LOOP_DETECTED);
		extra_headers++;
	}

	{
		coap_header_item_t headers_[extra_headers ? header_count +
		    extra_headers : 0];

		if(extra_headers) {
			coap_header_item_t *iter;
			memset(headers_, 0, sizeof(coap_header_item_t) *
				    (header_count + extra_headers));

			if(headers)
				memcpy(headers_,
					headers,
					sizeof(coap_header_item_t) * header_count);
			iter = headers = headers_;
			iter += header_count;
			header_count += extra_headers;

			if(path && (path[0] != 0)) {
				iter->key = COAP_HEADER_URI_PATH;
				iter->value = (char*)path;
				iter->value_len = strlen(path);
				iter++;
			}

			if(query && (query[0] != 0)) {
				iter->key = COAP_HEADER_URI_QUERY;
				iter->value = (char*)query;
				iter->value_len = strlen(query);
				iter++;
			}

			if(self->is_processing_message) {
				iter->key = COAP_HEADER_CASCADE_COUNT;
				iter->value = (char*)&self->cascade_count;
				iter->value_len = 1;
				iter++;
			}
		}

		packet_length = coap_encode_header(
			    (unsigned char*)packet,
			SMCP_MAX_PACKET_LENGTH,
			tid ? COAP_TRANS_TYPE_CONFIRMABLE :
			COAP_TRANS_TYPE_NONCONFIRMABLE,
			http_to_coap_code(method),
			tid,
			headers,
			header_count
		    );
	}

	require_action(content_length <=
		    (SMCP_MAX_PACKET_LENGTH - packet_length),
		bail,
		ret = SMCP_STATUS_MESSAGE_TOO_BIG);

	memcpy(packet + packet_length, content, content_length);

	packet_length += content_length;

	DEBUG_PRINTF(CSTR(
			"smcp_daemon(%p): sending request tid=%d, size=%d, method=%d"),
		self,
		tid, (int)packet_length, method);

#if SMCP_USE_BSD_SOCKETS
	DEBUG_PRINTF(CSTR("smcp_daemon(%p): port=%d"), self,
		    (int)ntohs(((struct sockaddr_in6*)saddr)->sin6_port));
	require_action_string(0 <
		sendto(self->fd,
			packet,
			packet_length,
			0,
			saddr,
			socklen), bail, ret = SMCP_STATUS_ERRNO, strerror(errno));
#elif __CONTIKI__
	uip_udp_packet_sendto(
		self->udp_conn,
		packet,
		packet_length,
		toaddr,
		toport
	);
#endif

bail:
	return ret;
}

smcp_status_t
smcp_daemon_send_request_to_url(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				uri_,
	coap_header_item_t		headers[],
	const char*				content,
	size_t					content_length
) {
	smcp_status_t ret = 0;
	char* proto_str = NULL;
	char* path_str = NULL;
	char* addr_str = NULL;
	char* port_str = NULL;
	char* query_str = NULL;

	uint16_t toport = htons(SMCP_DEFAULT_PORT);

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
		.sin6_family	= AF_INET6,
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
	};
#elif __CONTIKI__
	uip_ipaddr_t toaddr;
#endif

	require_action(uri_, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	if(!url_is_absolute(uri_)) {
		// Pairing with ourselves
		path_str = (char*)uri_;
		proto_str = "coap";
		addr_str = "::1";
		toport = htons(self->port);
	} else {
		char* uri_copy = alloca(strlen(uri_) + 1);

		strcpy(uri_copy, uri_);

		// Parse the URI.
		require_action_string(
			url_parse(uri_copy, &proto_str, NULL, NULL, &addr_str,
				&port_str, &path_str, &query_str),
			bail,
			ret = SMCP_STATUS_UNSUPPORTED_URI,
			"Unable to parse URL"
		);
		require_action(strequal_const(proto_str,
				"smcp") || strequal_const(proto_str,
				"coap"), bail, ret = SMCP_STATUS_UNSUPPORTED_URI);

		if(port_str)
			toport = htons(strtol(port_str, NULL, 10));
	}

	DEBUG_PRINTF(
		CSTR("URI Parse: \"%s\" -> host=\"%s\" port=\"%u\" path=\"%s\""),
		uri_,
		addr_str,
		    (int)ntohs(toport),
		path_str
	);

	// Below is the code which looks up the hostnames.
	// TODO: Invesitage if it would make sense to have a default
	// forwarding rule when this fails.

#if SMCP_USE_BSD_SOCKETS
	{
		struct addrinfo hint = {
			.ai_flags		= AI_ALL | AI_V4MAPPED,
			.ai_family		= AF_INET6,
			.ai_socktype	= SOCK_DGRAM,
			.ai_protocol	= IPPROTO_UDP,
		};
		struct addrinfo *results = NULL;
		int error = getaddrinfo(addr_str, port_str, &hint, &results);

		if(error && (inet_addr(addr_str) != INADDR_NONE)) {
			char addr_v4mapped_str[8 + strlen(addr_str)];
			sprintf(addr_v4mapped_str, "::ffff:%s", addr_str);
			error = getaddrinfo(addr_v4mapped_str,
				port_str,
				&hint,
				&results);
		}
		require_action_string(!error,
			bail,
			ret = SMCP_STATUS_HOST_LOOKUP_FAILURE,
			gai_strerror(error));
		require_action(results,
			bail,
			ret = SMCP_STATUS_HOST_LOOKUP_FAILURE);

		memcpy(&saddr, results->ai_addr, results->ai_addrlen);
	}
	saddr.sin6_port = toport;
#elif __CONTIKI__
	memset(&toaddr, 0, sizeof(toaddr));
	ret =
	    uiplib_ipaddrconv(addr_str,
		&toaddr) ? 0 : SMCP_STATUS_HOST_LOOKUP_FAILURE;
	if(ret) {
		uip_ipaddr_t *temp = resolv_lookup(addr_str);
		if(temp) {
			memcpy(&toaddr, temp, sizeof(uip_ipaddr_t));
			ret = 0;
		} else {
			resolv_query(addr_str);
			// TODO: We should be doing domain name resolution here too!
		}
	}
//#define PRINT6ADDR(addr) DEBUG_PRINTF("smcp_daemon_send_request_to_url: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15])
//	PRINT6ADDR(&toaddr);
	require_action_string(ret == SMCP_STATUS_OK,
		bail,
		ret = SMCP_STATUS_HOST_LOOKUP_FAILURE,
		"Unable to resolve hostname");
#else
#error TODO: Implement me!
#endif

	// Send the request
	ret = smcp_daemon_send_request(
		self,
		tid,
		method,
		path_str,
		query_str,
		headers,
		content,
		content_length,
#if SMCP_USE_BSD_SOCKETS
		    (struct sockaddr*)&saddr,
		sizeof(saddr)
#elif __CONTIKI__
		&toaddr,
		toport
#else
#error TODO: Implement me!
#endif
	    );

bail:
	return ret;
}

const coap_header_item_t*
smcp_daemon_get_current_request_headers(smcp_daemon_t self) {
	if(self->is_processing_message)
		return self->current_inbound_headers;
	return NULL;
}

uint8_t
smcp_daemon_get_current_request_header_count(smcp_daemon_t self) {
	if(self->is_processing_message)
		return self->current_inbound_header_count;
	return 0;
}

coap_transaction_id_t
smcp_daemon_get_current_tid(smcp_daemon_t self) {
	return self->current_inbound_request_tid;
}

#if SMCP_USE_BSD_SOCKETS
struct sockaddr* smcp_daemon_get_current_request_saddr(smcp_daemon_t self)
{
	return self->current_inbound_saddr;
}

socklen_t smcp_daemon_get_current_request_socklen(smcp_daemon_t self) {
	return self->current_inbound_socklen;
}
#elif defined(__CONTIKI__)
const uip_ipaddr_t* smcp_daemon_get_current_request_ipaddr(
	smcp_daemon_t self) {
	return &self->current_inbound_toaddr;
}

const uint16_t smcp_daemon_get_current_request_ipport(smcp_daemon_t self)
{
	return self->current_inbound_toport;
}
#endif

smcp_status_t
smcp_daemon_handle_inbound_packet(
	smcp_daemon_t	self,
	char*			packet,
	size_t			packet_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	coap_transaction_id_t tid;
	coap_transaction_type_t tt;
	coap_code_t code;
	size_t header_length;
	smcp_status_t status = 0;

	self->current_inbound_header_count = SMCP_MAX_HEADERS + 1;

	DEBUG_PRINTF(CSTR("%p: Inbound packet!"), self);
	header_length = coap_decode_header(
		    (unsigned char*)packet,
		packet_length,
		&tt,
		&code,
		&tid,
		self->current_inbound_headers,
		&self->current_inbound_header_count
	    );

	//headers[self->current_inbound_header_count].key = 0;

	require(header_length > 0, bail);

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	// Kind of a hack.
	packet[packet_length] = 0;

	self->current_inbound_request_tid = tid;

#if SMCP_USE_BSD_SOCKETS
	self->current_inbound_saddr = saddr;
	self->current_inbound_socklen = socklen;
#elif __CONTIKI__
	self->current_inbound_toaddr = *toaddr;
	self->current_inbound_toport = toport;
#endif

	self->is_processing_message = true;

	self->did_respond = (tt != COAP_TRANS_TYPE_CONFIRMABLE);

	if(COAP_CODE_IS_REQUEST(code)) {
		// Need to extract the path.
		char *path = "";

		self->current_inbound_request_token = 0;
		self->current_inbound_request_token_len = 0;
		self->cascade_count = SMCP_MAX_CASCADE_COUNT;

		coap_header_item_t *iter = self->current_inbound_headers;
		coap_header_item_t *end = iter +
		    self->current_inbound_header_count;
		for(; iter != end; ++iter) {
			if(iter->key == COAP_HEADER_URI_PATH) {
				path = alloca(iter->value_len + 1);
				memcpy(path, iter->value, iter->value_len);
				path[iter->value_len] = 0;
			} else if(iter->key == COAP_HEADER_TOKEN) {
				self->current_inbound_request_token = iter->value;
				self->current_inbound_request_token_len = iter->value_len;
			} else if(iter->key == COAP_HEADER_CASCADE_COUNT) {
				if(iter->value_len)
					self->cascade_count = ((unsigned char)*iter->value) -
					    1;
				else
					self->cascade_count = 128 - 1;
				if(self->cascade_count > SMCP_MAX_CASCADE_COUNT)
					self->cascade_count = SMCP_MAX_CASCADE_COUNT;
			}
		}

		status = smcp_daemon_handle_request(
			self,
			code,
			path,
			packet + header_length,
			packet_length - header_length
		    );
	} else if(COAP_CODE_IS_RESULT(code)) {
		status = smcp_daemon_handle_response(
			self,
			coap_to_http_code(code),
			packet + header_length,
			packet_length - header_length
		    );
	}

	check_string(status == SMCP_STATUS_OK, smcp_status_to_cstr(status));

	// Check to make sure we have responded by now. If not, we need to.
	if(!self->did_respond) {
		if(COAP_CODE_IS_REQUEST(code)) {
			smcp_daemon_send_response(
				self,
				smcp_convert_status_to_result_code(status),
				NULL,
				NULL,
				0
			);
		} else {
			// TODO: Need a way to specify a reset response.
			smcp_daemon_send_response(
				self,
				0,
				NULL,
				NULL,
				0
			);
		}
	}

bail:
	self->is_processing_message = false;
	return ret;
}

smcp_status_t
smcp_daemon_process(
	smcp_daemon_t self, cms_t cms
) {
	smcp_status_t ret = 0;

#if SMCP_USE_BSD_SOCKETS
	int tmp;
	struct pollfd pollee = { self->fd, POLLIN | POLLHUP, 0 };

	if(cms >= 0)
		cms = MIN(cms, smcp_daemon_get_timeout(self));
	else
		cms = smcp_daemon_get_timeout(self);

	errno = 0;

	tmp = poll(&pollee, 1, cms);

	// Ensure that poll did not fail with an error.
	require_action_string(errno == 0,
		bail,
		ret = SMCP_STATUS_ERRNO,
		strerror(errno));

	if(tmp > 0) {
		char packet[SMCP_MAX_PACKET_LENGTH];
		size_t packet_length = sizeof(packet);
		struct sockaddr_in6 packet_saddr;
		socklen_t packet_saddr_len = sizeof(packet_saddr);

		packet_length = recvfrom(
			self->fd,
			    (void*)packet,
			packet_length,
			0,
			    (struct sockaddr*)&packet_saddr,
			&packet_saddr_len
		    );

		require_action(packet_length > 0, bail, ret = SMCP_STATUS_ERRNO);

		packet[packet_length] = 0;

		ret = smcp_daemon_handle_inbound_packet(
			self,
			packet,
			packet_length,
			    (struct sockaddr*)&packet_saddr,
			packet_saddr_len
		    );
	}
#endif

	smcp_daemon_handle_timers(self);

bail:
	return ret;
}

#pragma mark -
#pragma mark SMCP Response Handler

void
smcp_internal_delete_handler_(
	smcp_response_handler_t handler,
	smcp_daemon_t			self
) {
	DEBUG_PRINTF(CSTR(
			"%p: Deleting response handler w/tid=%d"), self, handler->tid);

	// Remove the timer associated with this handler.
	smcp_daemon_invalidate_timer(self, &handler->timer);

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		    (*handler->callback)(
			self,
			SMCP_STATUS_HANDLER_INVALIDATED,
			NULL,
			0,
			handler->context
		);
	}

	free(handler);
}

void
smcp_internal_handler_timeout_(
	smcp_daemon_t			self,
	smcp_response_handler_t handler
) {
	smcp_response_handler_func callback = handler->callback;
	void* context = handler->context;

	if(callback) {
		handler->callback = NULL;
		smcp_invalidate_response_handler(self, handler->tid);
		    (*callback)(
		    self,
		    SMCP_STATUS_TIMEOUT,
		    NULL,
		    0,
		    context
		);
	} else {
		smcp_invalidate_response_handler(self, handler->tid);
	}
}

smcp_status_t
smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	coap_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_response_handler_func	callback,
	void*						context
) {
	smcp_status_t ret = 0;
	smcp_response_handler_t handler;

	require_action(callback != NULL,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT);

	handler = (smcp_response_handler_t)calloc(sizeof(*handler), 1);

	require_action(handler, bail, ret = SMCP_STATUS_MALLOC_FAILURE);

	DEBUG_PRINTF(CSTR("%p: Adding response handler w/tid=%d"), self, tid);

	handler->tid = tid;
	handler->callback = callback;
	handler->context = context;
	handler->flags = flags;
	convert_cms_to_timeval(&handler->expiration, cmsExpiration);

	smcp_daemon_schedule_timer(
		self,
		smcp_timer_init(
			&handler->timer,
			    (smcp_timer_callback_t)&smcp_internal_handler_timeout_,
			NULL,
			handler
		),
		cmsExpiration
	);

	bt_insert(
		    (void**)&self->handlers,
		handler,
		    (bt_compare_func_t)smcp_response_handler_compare,
		    (bt_delete_func_t)smcp_internal_delete_handler_,
		self
	);

	DEBUG_PRINTF(CSTR("%p: Total Handlers: %d"), self,
		bt_count((void**)&self->handlers));

bail:
	return ret;
}

smcp_status_t
smcp_invalidate_response_handler(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid
) {
	bt_remove(
		    (void**)&self->handlers,
		    (void*)&tid,
		    (bt_compare_func_t)smcp_response_handler_compare_tid,
		    (bt_delete_func_t)smcp_internal_delete_handler_,
		self
	);
	return 0;
}

smcp_status_t
smcp_daemon_handle_response(
	smcp_daemon_t	self,
	int				statuscode,
	const char*		content,
	size_t			content_length
) {
	smcp_status_t ret = 0;
	smcp_response_handler_t handler = NULL;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(CSTR(
				"smcp_daemon(%p): Incoming response! tid=%d"), self,
			smcp_daemon_get_current_tid(self));
		coap_dump_headers(
			SMCP_DEBUG_OUT_FILE,
			"    ",
			    (int)statuscode,
			smcp_daemon_get_current_request_headers(self),
			smcp_daemon_get_current_request_header_count(self)
		);

/*
        bool content_is_text;
        if(content_is_text)
            DEBUG_PRINTF(CSTR("CONTENT: \"%s\""),content);
 */
	}
#endif

	DEBUG_PRINTF(CSTR("%p: Total Handlers: %d"), self,
		bt_count((void**)&self->handlers));

	coap_transaction_id_t tid = smcp_daemon_get_current_tid(self);

	handler = (smcp_response_handler_t)bt_find(
		    (void**)&self->handlers,
		    (void*)&tid,
		    (bt_compare_func_t)smcp_response_handler_compare_tid,
		self
	    );

#if VERBOSE_DEBUG
	require_string(handler, bail, "Unable to find response handler");
#else
	require_quiet(handler, bail);
#endif

	if(handler->callback) {
		if(handler->flags & SMCP_RESPONSE_HANDLER_ALWAYS_TIMEOUT) {
			    (*handler->callback)(
				self,
				statuscode,
				content,
				content_length,
				handler->context
			);
		} else {
			smcp_response_handler_func callback = handler->callback;
			handler->callback = NULL;
			    (*callback)(
			    self,
			    statuscode,
			    content,
			    content_length,
			    handler->context
			);
			smcp_invalidate_response_handler(self, tid);
		}
	}

bail:
	return ret;
}


int smcp_convert_status_to_result_code(smcp_status_t status) {
	int ret = COAP_RESULT_CODE_INTERNAL_SERVER_ERROR;

	switch(status) {
	case SMCP_STATUS_OK:
		ret = COAP_RESULT_CODE_OK;
		break;
	case SMCP_STATUS_NOT_FOUND:
		ret = COAP_RESULT_CODE_NOT_FOUND;
		break;
	case SMCP_STATUS_NOT_IMPLEMENTED:
		ret = COAP_RESULT_CODE_NOT_IMPLEMENTED;
		break;
	case SMCP_STATUS_BAD_NODE_TYPE:
	case SMCP_STATUS_UNSUPPORTED_URI:
		ret = COAP_RESULT_CODE_BAD_REQUEST;
		break;
	}

	return ret;
}

#pragma mark -
#pragma mark SMCP Request Handlers


smcp_status_t
smcp_daemon_handle_request(
	smcp_daemon_t	self,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_status_t ret = 0;


#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(CSTR(
				"smcp_daemon(%p): Incoming request! tid=%d"), self,
			smcp_daemon_get_current_tid(self));
		coap_dump_headers(
			SMCP_DEBUG_OUT_FILE,
			"    ",
			    (int)method,
			smcp_daemon_get_current_request_headers(self),
			smcp_daemon_get_current_request_header_count(self)
		);

/*
        bool content_is_text;
        if(content_is_text)
            DEBUG_PRINTF(CSTR("CONTENT: \"%s\""),content);
 */
	}
#endif

	// TODO: Add authentication!

	smcp_node_t node;
	smcp_status_t (*request_handler)(
		smcp_daemon_t self, smcp_node_t node, smcp_method_t method,
		const char* relative_path, const char* content,
		size_t content_length);

	request_handler = &smcp_default_request_handler;

	// Try to find the closest node and call the request_handler handler.
	path +=
	    smcp_node_find_closest_with_path(smcp_daemon_get_root_node(
			self), path,
		    (smcp_node_t*)&node);

	require(node, bail);

	if(node->request_handler)
		request_handler = node->request_handler;

	ret = (*request_handler)(
	    self,
	    node,
	    method,
	    path,
	    content,
	    content_length
	    );


	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

bail:
	return ret;
}

smcp_status_t
smcp_default_request_handler(
	smcp_daemon_t	self,
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_status_t ret = SMCP_STATUS_NOT_FOUND;

	require(node, bail);

	switch(method) {
	case COAP_METHOD_GET:
		ret = smcp_daemon_handle_list(self,
			node,
			method,
			path,
			content,
			content_length);
		break;
	case COAP_METHOD_PAIR:
		ret = smcp_daemon_handle_pair(self,
			node,
			method,
			path,
			content,
			content_length);
		break;
	default:
		DEBUG_PRINTF(CSTR(
				"Unknown method in request: %s"), get_method_string(method));
		ret = smcp_daemon_send_response(self,
			COAP_RESULT_CODE_NOT_IMPLEMENTED,
			NULL,
			NULL,
			0);
		break;
	}

bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_list(
	smcp_daemon_t	self,
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_status_t ret = 0;
	char* next_node = NULL;
	coap_header_item_t replyHeaders[5] = {};
	char replyContent[128];
	coap_code_t response_code = COAP_RESULT_CODE_OK;

	memset(replyContent, 0, sizeof(replyContent));
	size_t content_break_threshold = 60;
	size_t content_offset = 0;

	const coap_header_item_t *iter =
	    smcp_daemon_get_current_request_headers(self);
	const coap_header_item_t *end = iter +
	    smcp_daemon_get_current_request_header_count(self);
	for(; iter != end; ++iter) {
		if(iter->key == COAP_HEADER_NEXT) {
			next_node = alloca(iter->value_len + 1);
			memcpy(next_node, iter->value, iter->value_len);
			next_node[iter->value_len] = 0;
		}
	}

	if(content_break_threshold >= sizeof(replyContent) - 1)
		// Trim the content break threshold to something we support.
		content_break_threshold = sizeof(replyContent) - 2;

	// We only support this method on direct queries.
	require_action(path[0] == 0, bail, ret = SMCP_STATUS_NOT_FOUND);

	if((content_break_threshold == 0) || (content_offset && !next_node)) {
		// We don't support content offsets right now.
		// TODO: Think about the implications of content offsets.
		smcp_daemon_send_response(self,
			COAP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE,
			replyHeaders,
			NULL,
			0);
		goto bail;
	}

	// Node should always be set by the time we get here.
	require_action(node, bail, ret = SMCP_STATUS_BAD_ARGUMENT);

	if(next_node && next_node[0]) {
		smcp_node_t next;
		node = smcp_node_find_with_path(node, next_node);
		response_code = COAP_RESULT_CODE_PARTIAL_CONTENT;
		check_string(node, "Unable to find next node!");
		next = bt_next(node);
		if(node && !next && node->parent)
			next = bt_first(((smcp_node_t)node->parent)->children);
		node = next;
	} else {
		if(((smcp_node_t)node)->children)
			node = bt_first(((smcp_node_t)node)->children);
		else
			node = NULL;
	}

	while(node) {
		smcp_node_t next;
		const char* node_name = node->name;

		if(!node_name)
			break;

		if((strlen(node_name) + 4) >
		        (content_break_threshold - strlen(replyContent) - 2))
			break;

		strlcat(replyContent, "<", sizeof(replyContent));

		if(node->name)
			strlcat(replyContent, node_name, sizeof(replyContent));

		strlcat(replyContent, ">", sizeof(replyContent));

		if(node->children)
			strlcat(replyContent, ";ct=40", sizeof(replyContent));
		next = bt_next(node);

		next_node = (char*)node->name;
		node = next;
#if SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
		strlcat(replyContent, ",\n" + (!node), sizeof(replyContent));
#else
		strlcat(replyContent, "," + (!node), sizeof(replyContent));
#endif
	}

	// If there are more nodes, indicate as such in the headers.
	if(node) {
		response_code = COAP_RESULT_CODE_PARTIAL_CONTENT;
#if SUPPORT_USING_LAST_LINE_FOR_EMPTY_NEXT_HEADER
		util_add_header(replyHeaders,
			SMCP_MAX_HEADERS,
			COAP_HEADER_NEXT,
			"",
			HEADER_CSTR_LEN);
#else
		util_add_header(replyHeaders,
			SMCP_MAX_HEADERS,
			COAP_HEADER_NEXT,
			next_node,
			HEADER_CSTR_LEN);
#endif
	}

	coap_content_type_t content_type =
	    COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;

	util_add_header(
		replyHeaders,
		SMCP_MAX_HEADERS,
		COAP_HEADER_CONTENT_TYPE,
		    (const void*)&content_type,
		1
	);

	smcp_daemon_send_response(self,
		response_code,
		replyHeaders,
		replyContent,
		strlen(replyContent));
bail:
	return ret;
}


#pragma mark -
#pragma mark Nodes

smcp_node_t
smcp_daemon_get_root_node(smcp_daemon_t self) {
	return &self->root_node;
}
