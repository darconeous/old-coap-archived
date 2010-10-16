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
#endif

#include "assert_macros.h"

#include "smcp.h"
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/time.h>
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
#endif

#include "smcp_helpers.h"

#include "smcp_timer.h"
#include "smcp_internal.h"

#pragma mark -
#pragma mark Macros


#pragma mark -
#pragma mark Time Calculation Utils


#pragma mark -
#pragma mark Private Functions

static const char*
get_method_string(smcp_method_t method) {
	const char* method_string = NULL;

	switch(method) {
	case SMCP_METHOD_GET: method_string = "GET"; break;
	case SMCP_METHOD_POST: method_string = "POST"; break;
	case SMCP_METHOD_PUT: method_string = "PUT"; break;
	case SMCP_METHOD_DELETE: method_string = "DELETE"; break;
	case SMCP_METHOD_PAIR: method_string = "PAIR"; break;
	case SMCP_METHOD_UNPAIR: method_string = "UNPAIR"; break;
	}
	return method_string;
}

static smcp_method_t
get_method_index(const char* method_string) {
	if(strcmp(method_string, "GET") == 0)
		return SMCP_METHOD_GET;
	else if(strcmp(method_string, "POST") == 0)
		return SMCP_METHOD_POST;
	else if(strcmp(method_string, "PUT") == 0)
		return SMCP_METHOD_PUT;
	else if(strcmp(method_string, "DELETE") == 0)
		return SMCP_METHOD_DELETE;
//	else if(strcmp(method_string,"OPTIONS")==0)
//		return SMCP_METHOD_OPTIONS;
	else if(strcmp(method_string, "PAIR") == 0)
		return SMCP_METHOD_PAIR;
	else if(strcmp(method_string, "UNPAIR") == 0)
		return SMCP_METHOD_UNPAIR;

	return 0;
}


static const char*
get_content_type_string(smcp_content_type_t content_type) {
	const char* content_type_string = NULL;

	switch(content_type) {
	case SMCP_CONTENT_TYPE_TEXT_PLAIN: content_type_string = "text/plain";
		break;
	case SMCP_CONTENT_TYPE_TEXT_CSV: content_type_string = "text/csv";
		break;
	case SMCP_CONTENT_TYPE_TEXT_XML: content_type_string = "text/xml";
		break;
	case SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED:
		content_type_string = "application/x-www-form-urlencoded"; break;
	default:
	case SMCP_CONTENT_TYPE_APPLICATION_OCTET_STREAM: content_type_string =
		    "application/octet-stream"; break;
	}
	return content_type_string;
}

static smcp_content_type_t
get_content_type_index(const char* content_type_string) {
	if(strcmp(content_type_string, "text/plain") == 0)
		return SMCP_CONTENT_TYPE_TEXT_PLAIN;
	else if(strcmp(content_type_string,
			"application/x-www-form-urlencoded") == 0)
		return SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;
	else if(strcmp(content_type_string, "text/csv") == 0)
		return SMCP_CONTENT_TYPE_TEXT_CSV;
	else if(strcmp(content_type_string, "text/xml") == 0)
		return SMCP_CONTENT_TYPE_TEXT_XML;
	return SMCP_CONTENT_TYPE_APPLICATION_OCTET_STREAM;
}

#pragma mark -
#pragma mark Other


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


smcp_status_t smcp_daemon_handle_post(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);
smcp_status_t smcp_daemon_handle_options(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);
smcp_status_t smcp_daemon_handle_get(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);
smcp_status_t smcp_daemon_handle_list(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);
smcp_status_t smcp_daemon_handle_pair(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);


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
	smcp_daemon_t		self,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);
smcp_status_t smcp_daemon_handle_response(
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length);


#pragma mark -
#pragma mark SMCP Timer Implementation


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
	uip_udp_bind(ret->udp_conn, HTONS(port));
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

	require_string(smcp_node_init_subdevice(&ret->root_node,
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
	char packet[SMCP_MAX_PACKET_LENGTH];
	size_t packet_length = 0;
	int header_count = 0;

	coap_transaction_id_t tid = self->current_inbound_request_tid;

	require_action_string(!self->did_respond,
		bail,
		ret = SMCP_STATUS_RESPONSE_NOT_ALLOWED,
		"Attempted to send more than one response!");

	if(headers) {
		coap_header_item_t* next_header;
		for(next_header = headers;
		    next_header && smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header))
			header_count++;
	}

	packet_length = coap_encode_header(
		    (unsigned char*)packet,
		sizeof(packet),
		COAP_TRANS_TYPE_ACK,
		http_to_coap_code(statuscode),
		tid,
		headers,
		header_count
	    );

/*
    packet_length += snprintf(packet,SMCP_MAX_PACKET_LENGTH,"%s %d\r\n",SMCP_VERSION_STRING,statuscode);

    packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH-packet_length,"Id: %d\r\n",tid);

    if(headers) {
        coap_header_item_t *next_header;
        for(next_header=headers;smcp_header_item_get_key(next_header);next_header=smcp_header_item_next(next_header)) {
            packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH-packet_length,"%s: %s\r\n",smcp_header_item_get_key_cstr(next_header),smcp_header_item_get_value(next_header));
        }
    }

    packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH-packet_length,"\r\n");

    packet_length = strlen(packet);
 */

	memcpy(packet + packet_length, content,
		MIN(SMCP_MAX_PACKET_LENGTH - packet_length, content_length));

	packet_length = MIN(SMCP_MAX_PACKET_LENGTH,
		packet_length + content_length);

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
		self->current_inbound_toaddr,
		self->current_inbound_toport
	);
#endif

	//DEBUG_PRINTF(CSTR("smcp_daemon(%p):SENT RESPONSE PACKET: \"%s\" %d bytes"),self,packet,(int)packet_length);
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
	coap_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	char packet[SMCP_MAX_PACKET_LENGTH + 1] = "";
	size_t packet_length = 0;
	int header_count = 0;

	coap_header_item_t just_in_case[2] = {};

	if(headers) {
		coap_header_item_t* next_header;
		util_add_header(headers, 16, COAP_HEADER_URI_PATH, path,
			strlen(path));
		for(next_header = headers;
		    next_header && smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header))
			header_count++;
	} else {
		headers = just_in_case;
		header_count++;
		util_add_header(headers, 16, COAP_HEADER_URI_PATH, path,
			strlen(path));
	}


	packet_length = coap_encode_header(
		    (unsigned char*)packet,
		sizeof(packet),
		tid ? COAP_TRANS_TYPE_CONFIRMABLE : COAP_TRANS_TYPE_NONCONFIRMABLE,
		http_to_coap_code(method),
		tid,
		headers,
		header_count
	    );

/*
    packet_length += snprintf(packet,SMCP_MAX_PACKET_LENGTH,"%s ",get_method_string(method));

    if(path && path[0]!='/') {
        packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH,"/");
    }

    packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH,"%s %s\r\n",path?path:"/",SMCP_VERSION_STRING);

    packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH-packet_length,"Id: %d\r\n",tid);

    if(headers) {
        coap_header_item_t *next_header;
        for(next_header=headers;smcp_header_item_get_key(next_header);next_header=smcp_header_item_next(next_header)) {
            packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH-packet_length,"%s: %s\r\n",smcp_header_item_get_key_cstr(next_header),smcp_header_item_get_value(next_header));
        }
    }

    packet_length += snprintf(packet+packet_length,SMCP_MAX_PACKET_LENGTH-packet_length,"\r\n");

    packet_length = strlen(packet);
 */

	if(content && content_length)
		memcpy(packet + packet_length, content,
			MIN(SMCP_MAX_PACKET_LENGTH, packet_length + content_length));

	packet_length = MIN(SMCP_MAX_PACKET_LENGTH,
		packet_length + content_length);

	DEBUG_PRINTF(CSTR(
			"smcp_daemon(%p): sending request tid=%d, size=%d, method=%d"),
		self,
		tid, (int)packet_length, method);

#if SMCP_USE_BSD_SOCKETS
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
		htons(toport)
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
	char uri[uri_ ? strlen(uri_) : 0 + 1];        // Requires compiler support for variable sized arrays
	char* proto_str = NULL;
	char* path_str = NULL;
	char* addr_str = NULL;
	char* port_str = NULL;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
		.sin6_family	= AF_INET6,
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
		.sin6_port		= htons(SMCP_DEFAULT_PORT),
	};
#elif __CONTIKI__
	uip_ipaddr_t toaddr;
	uint16_t toport = SMCP_DEFAULT_PORT;
#endif

	require_action(uri_, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action((strncmp(uri_, "smcp:",
				5) == 0) || (strncmp(uri_,
				"coap:",
				5) == 0), bail, ret = SMCP_STATUS_UNSUPPORTED_URI);

	strcpy(uri, uri_);

	// Parse the URI.
	require_action_string(
		url_parse(uri, &proto_str, &addr_str, &port_str, &path_str),
		bail,
		ret = SMCP_STATUS_UNSUPPORTED_URI,
		"Unable to parse URL"
	);

	if(port_str) {
#if SMCP_USE_BSD_SOCKETS
		saddr.sin6_port = htons(strtol(port_str, NULL, 10));
#elif __CONTIKI__
		toport = strtol(port_str, NULL, 10);
#else
#error TODO: Implement me!
#endif

#if SMCP_USE_BSD_SOCKETS
	} else {
		port_str = SMCP_DEFAULT_PORT_CSTR;
#endif
	}

	DEBUG_PRINTF(
		CSTR("URI Parse: \"%s\" -> host=\"%s\" port=\"%s\" path=\"%s\""),
		uri_,
		addr_str,
		port_str,
		path_str
	);

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
			ret = SMCP_STATUS_FAILURE,
			gai_strerror(error));
		require_action(results, bail, ret = SMCP_STATUS_FAILURE);

		memcpy(&saddr, results->ai_addr, results->ai_addrlen);
	}
#elif __CONTIKI__
	ret = uiplib_ipaddrconv(addr_str, &toaddr);
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
	require_action_string(ret == SMCP_STATUS_OK,
		bail,
		ret = SMCP_STATUS_FAILURE,
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
	return self->current_inbound_toaddr;
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
	coap_header_item_t headers[SMCP_MAX_HEADERS + 1] = { };
	size_t header_count = (sizeof(headers)) / (sizeof(headers[0]));
	size_t header_length;

	DEBUG_PRINTF(CSTR("%p: Inbound packet!"), self);
	header_length = coap_decode_header(
		    (unsigned char*)packet,
		packet_length,
		&tt,
		&code,
		&tid,
		headers,
		&header_count
	    );

	require(header_length > 0, bail);

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	packet[packet_length] = 0;

	self->current_inbound_request_tid = tid;

#if SMCP_USE_BSD_SOCKETS
	self->current_inbound_saddr = saddr;
	self->current_inbound_socklen = socklen;
#elif __CONTIKI__
	self->current_inbound_toaddr = toaddr;
	self->current_inbound_toport = toport;
#endif

	switch(tt) {
	case COAP_TRANS_TYPE_CONFIRMABLE:
		self->did_respond = false;
	case COAP_TRANS_TYPE_NONCONFIRMABLE:
		// Need to extract the path.
	{
		char path[128] = "/";

		coap_header_item_t *next_header;
		for(next_header = headers;
		        smcp_header_item_get_key(next_header);
		        next_header = smcp_header_item_next(next_header)) {
			if(smcp_header_item_key_equal(next_header,
						COAP_HEADER_URI_PATH))
				memcpy(path, smcp_header_item_get_value(
							next_header),
					    smcp_header_item_get_value_len(next_header));
		}
		if(code >= 40) {
			DEBUG_PRINTF(CSTR(
						"%p: (tid=%d) Bad method value, %d"), self, tid,
				    code);
			goto bail;
		}

		smcp_daemon_handle_request(
			    self,
			    code,
			    path,
			    headers,
			    packet + header_length,
			    packet_length - header_length
		);

		check((tt != COAP_TRANS_TYPE_CONFIRMABLE) || self->did_respond);

		// Check to make sure we have responded by now. If not, we need to.
		if((tt == COAP_TRANS_TYPE_CONFIRMABLE) && !self->did_respond) {
			// Send generic not found response here.
			smcp_daemon_send_response(
				    self,
				    SMCP_RESULT_CODE_NOT_FOUND,
				    headers,
				    NULL,
				    0
			);
		}
	}
	break;
	case COAP_TRANS_TYPE_ACK:
		if(code < 40) {
			DEBUG_PRINTF(CSTR(
					"%p: (tid=%d) Bad response code, %d"), self, tid, code);
			goto bail;
		}
	case COAP_TRANS_TYPE_RESET:
		smcp_daemon_handle_response(
			self,
			coap_to_http_code(code),
			headers,
			packet + header_length,
			packet_length - header_length
		);
		break;
	default:
		DEBUG_PRINTF(CSTR("%p: Bad transaction type: %d"), self, tt);
		goto bail;
		break;
	}

bail:
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
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = 0;
	smcp_response_handler_t handler = NULL;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(CSTR(
				"smcp_daemon(%p): Incoming response! tid=%d"), self, tid);
		DEBUG_PRINTF(CSTR("RESULT: %d"), statuscode);
		coap_header_item_t *next_header;
		unsigned char holder;
		for(next_header = headers;
		    smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header)) {
			switch(smcp_header_item_get_key(next_header)) {
			case COAP_HEADER_CONTENT_TYPE:
				DEBUG_PRINTF(CSTR(
						"\tHEADER: %s: %s"),
					smcp_header_item_get_key_cstr(
						next_header),
					get_content_type_string(*(const char*)
						smcp_header_item_get_value(
							next_header)));
				break;
			case COAP_HEADER_BLOCK:
				if(next_header->value_len == 0)
					DEBUG_PRINTF(CSTR(
							"\tHEADER: %s: empty!"),
						smcp_header_item_get_key_cstr(next_header));
				else if(next_header->value_len == 1)
					DEBUG_PRINTF(CSTR(
							"\tHEADER: %s: %02x"),
						smcp_header_item_get_key_cstr(
							next_header), next_header->value[0]);
				else if(next_header->value_len == 2)
					DEBUG_PRINTF(CSTR(
							"\tHEADER: %s: %02x %02x"),
						smcp_header_item_get_key_cstr(
							next_header), next_header->value[0],
						next_header->value[1]);
				else
					DEBUG_PRINTF(CSTR(
							"\tHEADER: %s: %02x %02x %02x"),
						smcp_header_item_get_key_cstr(
							next_header), next_header->value[0],
						next_header->value[1], next_header->value[2]);
				break;
			default:
				holder = next_header->value[next_header->value_len];
				next_header->value[next_header->value_len] = 0;
				DEBUG_PRINTF(CSTR(
						"\tHEADER: %s: \"%s\""),
					smcp_header_item_get_key_cstr(
						next_header),
					smcp_header_item_get_value(next_header));
				next_header->value[next_header->value_len] = holder;
				break;
			}
		}
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
				headers,
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
			    headers,
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
	int ret = SMCP_RESULT_CODE_INTERNAL_SERVER_ERROR;

	switch(status) {
	case SMCP_STATUS_OK:
		ret = SMCP_RESULT_CODE_OK;
		break;
	case SMCP_STATUS_NOT_FOUND:
		ret = SMCP_RESULT_CODE_NOT_FOUND;
		break;
	case SMCP_STATUS_NOT_IMPLEMENTED:
		ret = SMCP_RESULT_CODE_NOT_IMPLEMENTED;
		break;
	}

	return ret;
}

#pragma mark -
#pragma mark SMCP Request Handlers


smcp_status_t
smcp_daemon_handle_request(
	smcp_daemon_t		self,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = 0;


#if VERBOSE_DEBUG
	{   // Print out debugging information.
		bool content_is_text;
		DEBUG_PRINTF(CSTR(
				"smcp_daemon(%p): Incoming request! tid=%d"), self, tid);
		DEBUG_PRINTF(CSTR("REQUEST: \"%s\" \"%s\""),
			get_method_string(method), path);
		smcp_content_type_t content_type;
		coap_header_item_t *next_header;
		for(next_header = headers;
		    smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header)) {
			switch(smcp_header_item_get_key(next_header)) {
			case COAP_HEADER_CONTENT_TYPE:
				content_type = *(const char*)smcp_header_item_get_value(
					next_header);
				DEBUG_PRINTF(CSTR(
						"\tHEADER: %s: \"%s\""),
					smcp_header_item_get_key_cstr(
						next_header), get_content_type_string(content_type));
				if((content_type == SMCP_CONTENT_TYPE_TEXT_PLAIN)
				    || (content_type ==
				        SMCP_CONTENT_TYPE_APPLICATION_LINK_FORMAT)
				    || (content_type == SMCP_CONTENT_TYPE_TEXT_CSV)
				    || (content_type == SMCP_CONTENT_TYPE_TEXT_XML)
				)
					content_is_text = true;
				break;
			default:
			{
				unsigned char holder =
				        next_header->value[next_header->value_len];
				next_header->value[next_header->value_len] = 0;
				DEBUG_PRINTF(CSTR(
							"\tHEADER: %s: \"%s\""),
					    smcp_header_item_get_key_cstr(
							next_header),
					    smcp_header_item_get_value(next_header));
				next_header->value[next_header->value_len] = holder;
			}
			break;
			}
		}
		if(content_is_text)
			DEBUG_PRINTF(CSTR("CONTENT: \"%s\""), content);
	}
#endif

	// TODO: Add authentication!

	smcp_node_t node;
	smcp_status_t (*request_handler)(
		smcp_daemon_t self, smcp_node_t node, smcp_method_t method,
		const char* relative_path, coap_header_item_t headers[],
		const char* content, size_t content_length);

	request_handler = &smcp_default_request_handler;

	// Try to find the closest node and call the unhandled_request handler.
	path +=
	    smcp_node_find_closest_with_path(smcp_daemon_get_root_node(
			self), path,
		    (smcp_node_t*)&node);

	require(node, bail);

	if(((node->type == SMCP_NODE_DEVICE) ||
	            (node->type == SMCP_NODE_VARIABLE))) {
		if(((smcp_device_node_t)node)->unhandled_request)
			request_handler =
			    ((smcp_device_node_t)node)->unhandled_request;
	}

	ret = (*request_handler)(
	    self,
	    node,
	    method,
	    path,
	    headers,
	    content,
	    content_length
	    );


	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

bail:
	return ret;
}

smcp_status_t
smcp_default_request_handler(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = SMCP_STATUS_OK;

	require(node, bail);

	switch(method) {
	case SMCP_METHOD_POST:
	case SMCP_METHOD_PUT:
		ret = smcp_daemon_handle_post(self,
			node,
			method,
			path,
			headers,
			content,
			content_length);
		break;
	case SMCP_METHOD_GET:
		ret = smcp_daemon_handle_get(self,
			node,
			method,
			path,
			headers,
			content,
			content_length);
		break;
	case SMCP_METHOD_PAIR:
		ret = smcp_daemon_handle_pair(self,
			node,
			method,
			path,
			headers,
			content,
			content_length);
		break;
	default:
		DEBUG_PRINTF(CSTR(
				"Unknown method in request: %s"), get_method_string(method));
		ret = smcp_daemon_send_response(self,
			SMCP_RESULT_CODE_NOT_IMPLEMENTED,
			NULL,
			NULL,
			0);
		break;
	}

bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_post(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = 0;
	coap_header_item_t replyHeaders[SMCP_MAX_HEADERS + 1] = {};
	smcp_content_type_t content_type = SMCP_CONTENT_TYPE_TEXT_PLAIN;

	coap_header_item_t *next_header;

	for(next_header = headers;
	    smcp_header_item_get_key(next_header);
	    next_header = smcp_header_item_next(next_header)) {
		if(smcp_header_item_key_equal(next_header, COAP_HEADER_TOKEN))
			replyHeaders[0] = *next_header;
		else if(smcp_header_item_key_equal(next_header,
				COAP_HEADER_CONTENT_TYPE))
			content_type = *(unsigned char*)smcp_header_item_get_value(
				next_header);
	}

	// Node should always be set by the time we get here.
	require(node, bail);

	// We only support this method on direct queries.
	require(path[0] == 0, bail);

	if(node->type != SMCP_NODE_ACTION) {
		// Method not allowed.
		smcp_daemon_send_response(self,
			SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
			replyHeaders,
			NULL,
			0);
		goto bail;
	}

	if(((smcp_action_node_t)node)->post_func) {
		    (*((smcp_action_node_t)node)->post_func)(
			    ((smcp_action_node_t)node),
			headers,
			content,
			content_length,
			content_type,
			node->context
		);
	}

	smcp_daemon_send_response(self,
		SMCP_RESULT_CODE_ACK,
		replyHeaders,
		NULL,
		0);

bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_get(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = 0;
	char replyContent[128];
	size_t replyContentLength = 0;
	smcp_content_type_t replyContentType = SMCP_CONTENT_TYPE_TEXT_PLAIN;
	coap_header_item_t replyHeaders[SMCP_MAX_HEADERS + 1] = {};

	coap_header_item_t *next_header;

	for(next_header = headers;
	    smcp_header_item_get_key(next_header);
	    next_header = smcp_header_item_next(next_header)) {
		if(smcp_header_item_key_equal(next_header, COAP_HEADER_TOKEN))
			replyHeaders[0] = *next_header;
	}

	// Node should always be set by the time we get here.
	require(node, bail);

	// We only support this method on direct queries.
	require(path[0] == 0, bail);

	if(node->type == SMCP_NODE_DEVICE) {
		ret = smcp_daemon_handle_list(self,
			node,
			method,
			path,
			headers,
			content,
			content_length);
		goto bail;
	}


	if(node->type == SMCP_NODE_VARIABLE) {
		replyContentLength = sizeof(replyContent);
		ret = (*((smcp_variable_node_t)node)->get_func)(
			    (smcp_variable_node_t)node,
			headers,
			replyContent,
			&replyContentLength,
			&replyContentType,
			    ((smcp_variable_node_t)node)->context
		    );
	} else {
		smcp_daemon_send_response(self,
			SMCP_RESULT_CODE_BAD_REQUEST,
			replyHeaders,
			NULL,
			0);
		goto bail;
	}

	if(ret != SMCP_STATUS_OK) {
		smcp_daemon_send_response(self,
			SMCP_RESULT_CODE_INTERNAL_SERVER_ERROR,
			replyHeaders,
			NULL,
			0);
		goto bail;
	}

	util_add_header(replyHeaders,
		SMCP_MAX_HEADERS,
		COAP_HEADER_CONTENT_TYPE,
		    (const void*)&replyContentType,
		1);

	smcp_daemon_send_response(self,
		SMCP_RESULT_CODE_OK,
		replyHeaders,
		replyContent,
		replyContentLength);
bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_list(
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = 0;
	char* next_node = NULL;
	coap_header_item_t replyHeaders[SMCP_MAX_HEADERS + 1] = {};
	char replyContent[128];
	coap_code_t response_code = SMCP_RESULT_CODE_OK;

	memset(replyContent, 0, sizeof(replyContent));
	size_t content_break_threshold = 60;
	size_t content_offset = 0;

	coap_header_item_t *next_header;
	for(next_header = headers;
	    smcp_header_item_get_key(next_header);
	    next_header = smcp_header_item_next(next_header)) {
		if(smcp_header_item_key_equal(next_header, COAP_HEADER_NEXT)) {
			next_node = smcp_header_item_get_value(next_header);
		} else if(smcp_header_item_key_equal(next_header,
				COAP_HEADER_TOKEN)) {
			replyHeaders[0] = *next_header;
		} else if(smcp_header_item_key_equal(next_header,
				COAP_HEADER_RANGE)) {
			unsigned char *iter = (unsigned char*)next_header->value;
			unsigned char remaining_bytes =
			    (unsigned char)next_header->value_len;
			char shift;

			if(!remaining_bytes)
				continue;

			// Extract the content_break_threshold
			content_break_threshold = 0;
			shift = 0;
			do {
				content_break_threshold |= ((*iter & 0x7F) << shift);
				if(*iter & (1 << 7)) {
					remaining_bytes--;
					shift += 6;
					continue;
				}
				remaining_bytes--;
			} while(remaining_bytes);

			if(!remaining_bytes)
				continue;

			// Extract the content_offset
			content_offset = 0;
			shift = 0;
			do {
				content_offset |= ((*iter & 0x7F) << shift);
				if(*iter & (1 << 7)) {
					remaining_bytes--;
					shift += 6;
					continue;
				}
				remaining_bytes--;
			} while(remaining_bytes);
		}
	}

	if(content_break_threshold >= sizeof(replyContent) - 1)
		// Trim the content break threshold to something we support.
		content_break_threshold = sizeof(replyContent) - 2;

	// We only support this method on direct queries.
	require(path[0] == 0, bail);

	if((content_break_threshold == 0) || (content_offset && !next_node)) {
		// We don't support content offsets right now.
		// TODO: Think about the implications of content offsets.
		smcp_daemon_send_response(self,
			SMCP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE,
			replyHeaders,
			NULL,
			0);
		goto bail;
	}

	// Node should always be set by the time we get here.
	require(node, bail);

	if((node->type == SMCP_NODE_EVENT) ||
	        (node->type == SMCP_NODE_ACTION)) {
		// You can't call LIST on events or actions
		// TODO: PROTOCOL: Consider using this method for listing pairings...?
		smcp_daemon_send_response(self,
			SMCP_RESULT_CODE_BAD_REQUEST,
			replyHeaders,
			NULL,
			0);
		goto bail;
	}

	if(next_node) {
		while(*next_node && (*next_node == ' ')) next_node++;
		if(*next_node == '<') {
			int i;
			next_node++;
			for(i = 0; next_node[i]; i++) {
				if(next_node[i] == '>') {
					next_node[i] = 0;
					break;
				}
			}
		}
	}

	if(next_node && next_node[0]) {
		smcp_node_t next;
		node = smcp_node_find_with_path(node, next_node);
		response_code = SMCP_RESULT_CODE_PARTIAL_CONTENT;
		check_string(node, "Unable to find next node!");
		next = bt_next(node);
		if(node && !next && node->parent) {
			if(node->parent->type == SMCP_NODE_DEVICE) {
				switch(node->type) {
				case SMCP_NODE_ACTION:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->events);
					if(next)
						break;
				case SMCP_NODE_EVENT:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->variables);
					if(next)
						break;
				case SMCP_NODE_VARIABLE:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->subdevices);
					if(next)
						break;
				case SMCP_NODE_DEVICE:
					// At the end!
					break;
				}
			} else if(node->parent->type == SMCP_NODE_VARIABLE) {
				switch(node->type) {
				case SMCP_NODE_ACTION:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->events);
					if(next)
						break;
				case SMCP_NODE_EVENT:
					// At the end!
					break;
				}
			}
		}
		node = next;
	} else {
		switch(node->type) {
		case SMCP_NODE_DEVICE:
			if(((smcp_device_node_t)node)->actions)
				node = bt_first(((smcp_device_node_t)node)->actions);
			else if(((smcp_device_node_t)node)->events)
				node = bt_first(((smcp_device_node_t)node)->events);
			else if(((smcp_device_node_t)node)->variables)
				node = bt_first(((smcp_device_node_t)node)->variables);
			else if(((smcp_device_node_t)node)->subdevices)
				node = bt_first(((smcp_device_node_t)node)->subdevices);
			else
				node = NULL;
			break;
		case SMCP_NODE_VARIABLE:
			if(((smcp_device_node_t)node)->actions)
				node = bt_first(((smcp_device_node_t)node)->actions);
			else if(((smcp_device_node_t)node)->events)
				node = bt_first(((smcp_device_node_t)node)->events);
			else
				node = NULL;
			break;
		default:
			node = NULL;
			break;
		}
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

		if(node->type == SMCP_NODE_ACTION)
			strlcat(replyContent, "?", sizeof(replyContent));
		else if(node->type == SMCP_NODE_EVENT)
			strlcat(replyContent, "!", sizeof(replyContent));

		if(node->name)
			strlcat(replyContent, node_name, sizeof(replyContent));

		if(node->type == SMCP_NODE_DEVICE)
			strlcat(replyContent, "/", sizeof(replyContent));

		strlcat(replyContent, ">", sizeof(replyContent));

		next = bt_next(node);
		if(!next && node->parent) {
			if(node->parent->type == SMCP_NODE_DEVICE) {
				switch(node->type) {
				case SMCP_NODE_ACTION:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->events);
					if(next)
						break;
				case SMCP_NODE_EVENT:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->variables);
					if(next)
						break;
				case SMCP_NODE_VARIABLE:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->subdevices);
					if(next)
						break;
				case SMCP_NODE_DEVICE:
					// At the end!
					break;
				}
			} else if(node->parent->type == SMCP_NODE_VARIABLE) {
				switch(node->type) {
				case SMCP_NODE_ACTION:
					next = bt_first(
						    ((smcp_device_node_t)node->parent)->events);
					if(next)
						break;
				case SMCP_NODE_EVENT:
					// At the end!
					break;
				}
			}
		}
		next_node = (char*)node->name;
		node = next;
		strlcat(replyContent, ",\n" + (!node), sizeof(replyContent));
	}

	// If there are more nodes, indicate as such in the headers.
	if(node) {
		response_code = SMCP_RESULT_CODE_PARTIAL_CONTENT;
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

	smcp_content_type_t content_type =
	    SMCP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;

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
