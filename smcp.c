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

#pragma mark -
#pragma mark Macros


#pragma mark -
#pragma mark Time Calculation Utils

#define USEC_PER_SEC    (1000000)
#define USEC_PER_MSEC   (1000)
#define MSEC_PER_SEC    (1000)

#if defined(__CONTIKI__)
#define gettimeofday gettimeofday_
static int
gettimeofday(
	struct timeval *tv, void *tzp
) {
	if(tv) {
		tv->tv_sec = clock_seconds();
		tv->tv_usec =
		    (clock_time() % CLOCK_SECOND) * USEC_PER_SEC / CLOCK_SECOND;
		return 0;
	}
	return -1;
}
#endif

static void
convert_cms_to_timeval(
	struct timeval* tv, int cms
) {
	gettimeofday(tv, NULL);

	// Add all whole seconds to tv_sec
	tv->tv_sec += cms / MSEC_PER_SEC;

	// Remove all whole seconds from cms
	cms -= ((cms / MSEC_PER_SEC) * MSEC_PER_SEC);

	tv->tv_usec += ((cms % MSEC_PER_SEC) * MSEC_PER_SEC);

	tv->tv_sec += tv->tv_usec / USEC_PER_SEC;

	tv->tv_usec %= USEC_PER_SEC;
}

static int
convert_timeval_to_cms(const struct timeval* tv) {
	int ret = 0;
	struct timeval current_time;

	gettimeofday(&current_time, NULL);

	if(current_time.tv_sec <= tv->tv_sec) {
		ret = (tv->tv_sec - current_time.tv_sec) * MSEC_PER_SEC;
		ret += (tv->tv_usec - current_time.tv_usec) / USEC_PER_MSEC;

		if(ret < 0)
			ret = 0;
	}

	return ret;
}

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
	case SMCP_METHOD_LIST: method_string = "LIST"; break;
	case SMCP_METHOD_OPTIONS: method_string = "OPTIONS"; break;
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
	else if(strcmp(method_string, "LIST") == 0)
		return SMCP_METHOD_LIST;
	else if(strcmp(method_string, "OPTIONS") == 0)
		return SMCP_METHOD_OPTIONS;
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


static bool
util_add_header(
	smcp_header_item_t	headerList[],
	int					maxHeaders,
	smcp_header_key_t	key,
	const char*			value,
	size_t				len
) {
#if USE_COAP_COMPATIBLE_HEADERS
	for(; maxHeaders && headerList[0].key; maxHeaders--, headerList++) ;
	if(maxHeaders) {
		headerList[0].key = name;
		headerList[0].value = value;
		headerList[0].value_len = (len == HEADER_CSTR_LEN) ? len : strlen(
			value);
		headerList[1].key = 0;
		return true;
	}
#else
	for(; maxHeaders && headerList[0]; maxHeaders--, headerList += 2) ;
	if(maxHeaders) {
		headerList[0] = key;
		headerList[1] = value;
		headerList[2] = NULL;
		return true;
	}
#endif
	return false;
}


#pragma mark -
#pragma mark Private SMCP Types

typedef void (*smcp_timer_callback_t)(smcp_daemon_t smcp, void* context);

struct smcp_timer_s {
	struct ll_item_s		ll;
	struct timeval			fire_date;
	void*					context;
	smcp_timer_callback_t	callback;
	smcp_timer_callback_t	cancel;
};

typedef struct smcp_timer_s *smcp_timer_t;

struct smcp_response_handler_s {
	struct bt_item_s			bt_item;
	smcp_transaction_id_t		tid;
	struct timeval				expiration;
	int							flags;
	smcp_timer_t				timer;
	smcp_response_handler_func	callback;
	void*						context;
};

typedef struct smcp_response_handler_s *smcp_response_handler_t;

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
	smcp_transaction_id_t rhs = strtol((const char*)rhs_, NULL, 10);

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
	smcp_transaction_id_t rhs = *(smcp_transaction_id_t*)rhs_;

	if(lhs->tid > rhs)
		return 1;
	if(lhs->tid < rhs)
		return -1;
	return 0;
}

#pragma mark -
#pragma mark Class Definition

// Consider members of this struct to be private!
struct smcp_daemon_s {
#if SMCP_USE_BSD_SOCKETS
	int						fd;
	int						mcfd;
#elif __CONTIKI__
	struct uip_udp_conn*	udp_conn;
#endif

	smcp_pairing_t			admin_pairings;
	smcp_node_t				root_node;
	smcp_timer_t			timers;
	smcp_response_handler_t handlers;

	smcp_pairing_t			pairings;

	uint16_t				port;
};

#if defined(__CONTIKI__)
struct smcp_daemon_s smcp_daemon_global_instance;
#endif

#pragma mark -
#pragma mark Declarations


smcp_status_t smcp_daemon_handle_post(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
smcp_status_t smcp_daemon_handle_options(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
smcp_status_t smcp_daemon_handle_get(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
smcp_status_t smcp_daemon_handle_list(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
smcp_status_t smcp_daemon_handle_pair(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);


smcp_status_t smcp_invalidate_response_handler(
	smcp_daemon_t self, smcp_transaction_id_t tid);
smcp_status_t smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	smcp_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_response_handler_func	callback,
	void*						context);

smcp_status_t smcp_daemon_handle_request(
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);
smcp_status_t smcp_daemon_handle_response(
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	int						statuscode,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS);


#pragma mark -
#pragma mark SMCP Timer Implementation

static ll_compare_result_t
smcp_timer_compare_func(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_timer_t lhs = (smcp_timer_t)lhs_;
	const smcp_timer_t rhs = (smcp_timer_t)rhs_;

	if(lhs->fire_date.tv_sec > rhs->fire_date.tv_sec)
		return 1;
	if(lhs->fire_date.tv_sec < rhs->fire_date.tv_sec)
		return -1;

	if(lhs->fire_date.tv_usec > rhs->fire_date.tv_usec)
		return 1;

	if(lhs->fire_date.tv_usec < rhs->fire_date.tv_usec)
		return -1;

	return 0;
}

smcp_timer_t
smcp_daemon_schedule_timer(
	smcp_daemon_t			self,
	int						cms,
	smcp_timer_callback_t	callback,
	smcp_timer_callback_t	cancel,
	void*					context
) {
	smcp_timer_t ret;

	ret = calloc(sizeof(*ret), 1);

	require(ret, bail);

	convert_cms_to_timeval(&ret->fire_date, cms);

	ret->callback = callback;
	ret->cancel = cancel;
	ret->context = context;

	ll_sorted_insert(
		    (void**)&self->timers,
		ret,
		&smcp_timer_compare_func,
		NULL
	);

bail:
	return ret;
}

void
smcp_daemon_invalidate_timer(
	smcp_daemon_t	self,
	smcp_timer_t	timer
) {
	ll_remove((void**)&self->timers, (void*)timer);
	free(timer);
}

cms_t
smcp_daemon_get_timeout(smcp_daemon_t self) {
	cms_t ret = 60000;

	if(self->timers)
		ret = MIN(ret, convert_timeval_to_cms(&self->timers->fire_date));

	ret = MAX(ret, 0);

	return ret;
}

void
smcp_daemon_handle_timers(smcp_daemon_t self) {
	while(self->timers &&
	        (convert_timeval_to_cms(&self->timers->fire_date) <= 0)) {
		smcp_timer_t timer = self->timers;
		timer->callback(self, timer->context);
		smcp_daemon_invalidate_timer(self, timer);
	}
}

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

	ret->port = port;

	ret->root_node = (smcp_node_t)smcp_node_add_subdevice(NULL, NULL);

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
	if(self->root_node)
		smcp_node_delete(self->root_node);

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
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	int						statuscode,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	char packet[SMCP_MAX_PACKET_LENGTH];
	const char** header_iter;
	size_t packet_length = 0;

	packet_length += snprintf(packet,
		SMCP_MAX_PACKET_LENGTH,
		"%s %d\r\n",
		SMCP_VERSION_STRING,
		statuscode);

	packet_length += snprintf(packet + packet_length,
		SMCP_MAX_PACKET_LENGTH - packet_length,
		"Id: %d\r\n",
		tid);

	if(headers) {
		for(header_iter = headers; header_iter[0]; header_iter += 2) {
			packet_length += snprintf(packet + packet_length,
				SMCP_MAX_PACKET_LENGTH - packet_length,
				"%s: %s\r\n",
				header_iter[0],
				header_iter[1]);
		}
	}

	packet_length += snprintf(packet + packet_length,
		SMCP_MAX_PACKET_LENGTH - packet_length,
		"\r\n");

	packet_length = strlen(packet);

	memcpy(packet + packet_length, content,
		MIN(SMCP_MAX_PACKET_LENGTH - packet_length, content_length));

	packet_length = MIN(SMCP_MAX_PACKET_LENGTH,
		packet_length + content_length);

#if SMCP_USE_BSD_SOCKETS
	require_action(0 <
		sendto(self->fd,
			packet,
			packet_length,
			0,
			saddr,
			socklen), bail, {
		    ret = -1;
		    DEBUG_PRINTF(CSTR("Unable to send: errno = %d (%s)"), errno,
				strerror(errno));
		});
#elif __CONTIKI__
	uip_udp_packet_sendto(
		self->udp_conn,
		packet,
		packet_length,
		toaddr,
		toport
	);
#endif

	DEBUG_PRINTF(CSTR(
			"smcp_daemon(%p):SENT RESPONSE PACKET: \"%s\" %d bytes"), self,
		packet,
		    (int)packet_length);

bail:
	return ret;
}

smcp_status_t
smcp_daemon_send_request(
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	char packet[SMCP_MAX_PACKET_LENGTH + 1] = "";
	const char** header_iter;
	size_t packet_length = 0;

	packet_length += snprintf(packet,
		SMCP_MAX_PACKET_LENGTH,
		"%s %s %s\r\n",
		get_method_string(method),
		path ? path : "",
		SMCP_VERSION_STRING);

	packet_length += snprintf(packet + packet_length,
		SMCP_MAX_PACKET_LENGTH - packet_length,
		"Id: %d\r\n",
		tid);

	if(headers) {
		for(header_iter = headers; header_iter[0]; header_iter += 2) {
			packet_length += snprintf(packet + packet_length,
				SMCP_MAX_PACKET_LENGTH - packet_length,
				"%s: %s\r\n",
				header_iter[0],
				header_iter[1]);
		}
	}

	packet_length += snprintf(packet + packet_length,
		SMCP_MAX_PACKET_LENGTH - packet_length,
		"\r\n");

	packet_length = strlen(packet);

	if(content && content_length)
		memcpy(packet + packet_length, content,
			MIN(SMCP_MAX_PACKET_LENGTH, packet_length + content_length));

	packet_length = MIN(SMCP_MAX_PACKET_LENGTH,
		packet_length + content_length);

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

	DEBUG_PRINTF(CSTR(
			"smcp_daemon(%p):SENT REQUEST PACKET: \"%s\" %d bytes"), self,
		packet,
		    (int)packet_length);
bail:
	return ret;
}

smcp_status_t
smcp_daemon_send_request_to_url(
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				uri_,
	smcp_header_item_t		headers[],
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
	require_action(strncmp(uri_,
			"smcp:",
			5) == 0, bail, ret = SMCP_STATUS_UNSUPPORTED_URI);

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
	// TODO: We should be doing domain name resolution here too!
	require_action(uiplib_ipaddrconv(addr_str,
			&toaddr) != 0, bail, ret = SMCP_STATUS_FAILURE);
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


smcp_status_t
smcp_daemon_handle_inbound_packet(
	smcp_daemon_t	self,
	char*			packet,
	size_t			packet_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	char* packet_cursor = packet;
	ssize_t packet_length_remaining = packet_length;
	smcp_transaction_id_t tid;

	require_string(packet_length > 10, bail, "Inbound packet too short");

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	packet[packet_length] = 0;

	if(memcmp(packet_cursor, "SMCP/", 5) == 0) {
		// This is a reply.
		int statuscode;
		const char* version;
		const char* headers[SMCP_MAX_HEADERS * 2 + 1];
		int hindex = 0;

		// Grab the start of the version string.
		version = packet_cursor;

		// Move to the end of the version string
		do {
			require(packet_length_remaining >= 2, bail);
			packet_cursor++;
			packet_length_remaining--;
		} while(!isspace(packet_cursor[0]));

		// Zero terminate the version string.
		packet_cursor[0] = 0;

		packet_cursor++;
		packet_length_remaining--;

		// Extract the status code
		statuscode = strtol(packet_cursor, NULL, 10);

		// Move to the next line.
		do {
			require(packet_length_remaining >= 1, bail);
			packet_cursor++;
			packet_length_remaining--;
		} while(packet_cursor[-1] != '\n');

		// Extract the headers
		while(packet_cursor[0] != '\r' && packet_cursor[0] != '\n') {
			// Grab the start of the next header;
			if(SMCP_MAX_HEADERS * 2 > hindex)
				headers[hindex++] = packet_cursor;

			// Move to the end of the header name.
			do {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			} while(packet_cursor[0] != ':');

			// Mark the end of the header name.
			packet_cursor[0] = 0;

			// Move to the start of the value
			do {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			} while((!packet_cursor[0] ||
			        isspace(packet_cursor[0])) &&
			        (packet_cursor[0] != '\r') &&
			        (packet_cursor[0] != '\n'));

			// Grab the start of the header value
			if(SMCP_MAX_HEADERS * 2 > hindex)
				headers[hindex++] = packet_cursor;

			// Move to the end of the line
			while((packet_cursor[0] != '\n') &&
			        (packet_cursor[0] != '\r')) {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			}

			// Mark the end of the header value.
			packet_cursor[0] = 0;

			DEBUG_PRINTF(CSTR("Parsed header \"%s\" = \"%s\""),
				headers[hindex - 2], headers[hindex - 1]);

			// The transaction id is special, remove it from the headers.
			if(strcmp(headers[hindex - 2], "Id") == 0) {
				tid = strtol(headers[hindex - 1], NULL, 10);
				hindex -= 2;
			}

			while(packet_cursor[-1] != '\n') {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			}
		}

		// Zero-terminate the header list
		headers[hindex] = 0;

		// Move to the content (if it is present)
		if(packet_length_remaining) do {
				packet_cursor++;
				packet_length_remaining--;
			} while(packet_cursor[-1] != '\n' && packet_length_remaining);


		smcp_daemon_handle_response(
			self,
			tid,
			statuscode,
			headers,
			packet_cursor,
			packet_length_remaining,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
	} else {
		// This is a request.
		smcp_method_t method;
		const char* method_string;
		const char* path;
		const char* version;
		const char* headers[SMCP_MAX_HEADERS * 2 + 1];
		int hindex = 0;

		method_string = packet_cursor;

		// Move to the end of the method name
		do {
			require_string(packet_length_remaining >= 2,
				bail,
				"Ran out of space attempting to parse method name");
			packet_cursor++;
			packet_length_remaining--;
		} while(!isspace(packet_cursor[0]));

		// Zero terminate the method name.
		packet_cursor[0] = 0;

		method = get_method_index(method_string);

		// Move to the start of the path.
		packet_cursor++;
		packet_length_remaining--;
		path = packet_cursor;

		// Move to the end of the path
		do {
			require(packet_length_remaining >= 2, bail);
			packet_cursor++;
			packet_length_remaining--;
		} while(!isspace(packet_cursor[0]));

		// Zero terminate the path.
		packet_cursor[0] = 0;

		// Move to the start of version string
		packet_cursor++;
		packet_length_remaining--;
		version = packet_cursor;

		// Move to the end of the version string
		do {
			require(packet_length_remaining >= 2, bail);
			packet_cursor++;
			packet_length_remaining--;
		} while(!isspace(packet_cursor[0]));

		// Zero terminate the version string.
		packet_cursor[0] = 0;

		// Move to the next line.
		do {
			require(packet_length_remaining >= 2, bail);
			packet_cursor++;
			packet_length_remaining--;
		} while(packet_cursor[-1] != '\n');

		// Extract the headers
		while(packet_cursor[0] != '\r' && packet_cursor[0] != '\n') {
			// Grab the start of the next header;
			if(SMCP_MAX_HEADERS * 2 > hindex)
				headers[hindex++] = packet_cursor;

			// Move to the end of the header name.
			do {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			} while(packet_cursor[0] != ':');

			// Mark the end of the header name.
			packet_cursor[0] = 0;

			// Move to the start of the value
			do {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			} while(!packet_cursor[0] || isspace(packet_cursor[0]));

			// Grab the start of the header value
			if(SMCP_MAX_HEADERS * 2 > hindex)
				headers[hindex++] = packet_cursor;

			// Move to the end of the line
			do {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			} while(packet_cursor[0] != '\n' && packet_cursor[0] != '\r');

			// Mark the end of the header value.
			packet_cursor[0] = 0;

			do {
				require(packet_length_remaining >= 2, bail);
				packet_cursor++;
				packet_length_remaining--;
			} while(packet_cursor[-1] != '\n');

			// The transaction id is special, remove it from the headers.
			if(strcmp(headers[hindex - 2], "Id") == 0) {
				tid = strtol(headers[hindex - 1], NULL, 10);
				hindex -= 2;
			}
		}

		// Zero-terminate the header list
		headers[hindex] = 0;

		// Move to the content (if it is present)
		if(packet_length_remaining) do {
				packet_cursor++;
				packet_length_remaining--;
			} while(packet_cursor[-1] != '\n' && packet_length_remaining);

		// Handle the request.
		smcp_daemon_handle_request(
			self,
			tid,
			method,
			path,
			headers,
			packet_cursor,
			packet_length_remaining,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
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

	cms = MIN(cms, smcp_daemon_get_timeout(self));

	tmp = poll(&pollee, 1, cms);

	// Ensure that poll did not fail with an error.
	require_action(tmp >= 0, bail, ret = SMCP_STATUS_ERRNO);

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
	if(handler->timer)
		smcp_daemon_invalidate_timer(self, handler->timer);

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		    (*handler->callback)(
			self,
			SMCP_STATUS_HANDLER_INVALIDATED,
			NULL,
			NULL,
			0,
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

	handler->timer = NULL;
	if(callback) {
		handler->callback = NULL;
		    (*callback)(
		    self,
		    SMCP_STATUS_TIMEOUT,
		    NULL,
		    NULL,
		    0,
		    NULL,
		    0,
		    handler->context
		);
		smcp_invalidate_response_handler(self, handler->tid);
	}
}

smcp_status_t
smcp_daemon_add_response_handler(
	smcp_daemon_t				self,
	smcp_transaction_id_t		tid,
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

	handler->timer =
	    smcp_daemon_schedule_timer(self,
		cmsExpiration,
		    (smcp_timer_callback_t)&smcp_internal_handler_timeout_,
		NULL,
		handler);

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
	smcp_transaction_id_t	tid
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
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	int						statuscode,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	smcp_response_handler_t handler = NULL;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		const char** header_iter;
		DEBUG_PRINTF(CSTR(
				"smcp_daemon(%p): Incoming response! tid=%d"), self, tid);
		DEBUG_PRINTF(CSTR("RESULT: %d"), statuscode);
		for(header_iter = headers; header_iter[0]; header_iter += 2) {
			DEBUG_PRINTF(CSTR(
					"\tHEADER: %s: %s"), header_iter[0], header_iter[1]);
		}
	}
#endif

	// Lookup response, fire handler.

//	for(i=0;headers[i];i+=2) {
//		if(0==strcmp(headers[i],SMCP_HEADER_ID))
//			tid = strtol(headers[i+1],NULL,10);
//	}

	DEBUG_PRINTF(CSTR("%p: Total Handlers: %d"), self,
		bt_count((void**)&self->handlers));

	handler = (smcp_response_handler_t)bt_find(
		    (void**)&self->handlers,
		    (void*)&tid,
		    (bt_compare_func_t)smcp_response_handler_compare_tid,
		self
	    );

	require_string(handler, bail, "Unable to find response handler");

	if(handler->callback) {
		if(handler->flags & SMCP_RESPONSE_HANDLER_ALWAYS_TIMEOUT) {
			    (*handler->callback)(
				self,
				statuscode,
				headers,
				content,
				content_length,
#if SMCP_USE_BSD_SOCKETS
				saddr,
				socklen,
#elif __CONTIKI__
				toaddr,
				toport,
#else
#error TODO: Implement me!
#endif
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
#if SMCP_USE_BSD_SOCKETS
			    saddr,
			    socklen,
#elif __CONTIKI__
			    toaddr,
			    toport,
#else
#error TODO: Implement me!
#endif
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
	smcp_daemon_t			self,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		const char** header_iter;
		DEBUG_PRINTF(CSTR(
				"smcp_daemon(%p): Incoming request! tid=%d"), self, tid);
		DEBUG_PRINTF(CSTR("REQUEST: %s %s"), get_method_string(
				method), path);
		for(header_iter = headers; header_iter[0]; header_iter += 2) {
			DEBUG_PRINTF(CSTR(
					"\tHEADER: %s: %s"), header_iter[0], header_iter[1]);
		}
	}
#endif

	// TODO: Add authentication!

	smcp_node_t node =
	    smcp_node_find_with_path(smcp_daemon_get_root_node(self), path);
	if(!node &&
	        ((strcmp(path,
					"*") != 0) && (method != SMCP_METHOD_OPTIONS))) {
		// Try to find the closest node and call the unhandled_request handler.
		path +=
		    smcp_node_find_closest_with_path(smcp_daemon_get_root_node(
				self), path, (smcp_node_t*)&node);
		if(node &&
		        ((node->type == SMCP_NODE_DEVICE) ||
		            (node->type == SMCP_NODE_VARIABLE))) {
			if(((smcp_device_node_t)node)->unhandled_request) {
				ret = (*((smcp_device_node_t)node)->unhandled_request)(
					self,
					method,
					path,
					headers,
					content,
					content_length,
#if SMCP_USE_BSD_SOCKETS
					saddr,
					socklen,
#elif __CONTIKI__
					toaddr,
					toport,
#else
#error TODO: Implement me!
#endif
					node->context
				    );
				if((ret == SMCP_STATUS_OK) && (method != SMCP_METHOD_PAIR))
					goto bail;
			}
		}

		// The PAIR method we can handle without a node, as long as
		// the unhandled_request function doesn't indicate that the path doesn't exist.
		if((method != SMCP_METHOD_PAIR) ||
		        (ret == SMCP_STATUS_NOT_FOUND)) {
			smcp_header_item_t replyHeaders[SMCP_MAX_HEADERS * 2 + 1];
			replyHeaders[0] = NULL;

/*
            for(i=0;headers[i];i+=2) {
                if(0==strcmp(headers[i],SMCP_HEADER_CSEQ))
                    util_add_header(replyHeaders,SMCP_MAX_HEADERS,SMCP_HEADER_CSEQ,headers[i+1],HEADER_CSTR_LEN);
                if(0==strcmp(headers[i],SMCP_HEADER_ID))
                    util_add_header(replyHeaders,SMCP_MAX_HEADERS,SMCP_HEADER_ID,headers[i+1],HEADER_CSTR_LEN);
            }
 */
			if(!ret)
				ret = SMCP_STATUS_NOT_FOUND;
			smcp_daemon_send_response(self,
				tid,
				smcp_convert_status_to_result_code(ret),
				replyHeaders,
				NULL,
				0,
#if SMCP_USE_BSD_SOCKETS
				saddr,
				socklen
#elif __CONTIKI__
				toaddr,
				toport
#else
#error TODO: Implement me!
#endif
			);
			goto bail;
		}
	}

	if(method == SMCP_METHOD_POST) {
		ret = smcp_daemon_handle_post(self,
			node,
			tid,
			method,
			path,
			headers,
			content,
			content_length,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		    );
	} else if(method == SMCP_METHOD_OPTIONS) {
		ret = smcp_daemon_handle_options(self,
			node,
			tid,
			method,
			path,
			headers,
			content,
			content_length,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		    );
	} else if(method == SMCP_METHOD_GET) {
		ret = smcp_daemon_handle_get(self,
			node,
			tid,
			method,
			path,
			headers,
			content,
			content_length,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		    );
	} else if(method == SMCP_METHOD_LIST) {
		ret = smcp_daemon_handle_list(self,
			node,
			tid,
			method,
			path,
			headers,
			content,
			content_length,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		    );
	} else if(method == SMCP_METHOD_PAIR) {
		ret = smcp_daemon_handle_pair(self,
			node,
			tid,
			method,
			path,
			headers,
			content,
			content_length,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		    );
	} else {
		// Unknown or unsupported method.
		smcp_header_item_t replyHeaders[SMCP_MAX_HEADERS * 2 + 1];
		replyHeaders[0] = NULL;
/*
        smcp_header_item_t *next_header;
        for(next_header=headers;smcp_header_item_get_key(next_header);next_header=smcp_header_item_next(next_header)) {
            if(smcp_header_item_key_equal(next_header,SMCP_HEADER_CSEQ))
                util_add_header(
                    replyHeaders,
                    SMCP_MAX_HEADERS,
                    SMCP_HEADER_CSEQ,
                    smcp_header_item_get_value(next_header),
                    smcp_header_item_get_value_len(next_header)
                );
            if(smcp_header_item_key_equal(next_header,SMCP_HEADER_ID))
                util_add_header(
                    replyHeaders,
                    SMCP_MAX_HEADERS,
                    SMCP_HEADER_ID,
                    smcp_header_item_get_value(next_header),
                    smcp_header_item_get_value_len(next_header)
                );
        }
 */
		DEBUG_PRINTF(CSTR(
				"Unknown method in request: %s"), get_method_string(method));
		smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_NOT_IMPLEMENTED,
			replyHeaders,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
	}

bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_post(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	smcp_header_item_t replyHeaders[SMCP_MAX_HEADERS * 2 + 1] = {};
	smcp_content_type_t content_type = SMCP_CONTENT_TYPE_TEXT_PLAIN;

	smcp_header_item_t *next_header;

	for(next_header = headers;
	    smcp_header_item_get_key(next_header);
	    next_header = smcp_header_item_next(next_header)) {
/*
        if(smcp_header_item_key_equal(next_header,SMCP_HEADER_CSEQ))
            util_add_header(
                replyHeaders,
                SMCP_MAX_HEADERS,
                SMCP_HEADER_CSEQ,
                smcp_header_item_get_value(next_header),
                smcp_header_item_get_value_len(next_header)
            );
        else if(smcp_header_item_key_equal(next_header,SMCP_HEADER_ID))
            util_add_header(
                replyHeaders,
                SMCP_MAX_HEADERS,
                SMCP_HEADER_ID,
                smcp_header_item_get_value(next_header),
                smcp_header_item_get_value_len(next_header)
            );
        else
 */
		if(smcp_header_item_key_equal(next_header,
				SMCP_HEADER_CONTENT_TYPE))
			content_type = get_content_type_index(
				smcp_header_item_get_value(next_header));
	}

	// Node should always be set by the time we get here.
	require(node, bail);

	if(node->type != SMCP_NODE_ACTION) {
		// Method not allowed.
		smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
			replyHeaders,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
		goto bail;
	}

	if(((smcp_action_node_t)node)->post_func) {
		    (*((smcp_action_node_t)node)->post_func)(
			    ((smcp_action_node_t)node),
			headers,
			content,
			content_length,
			content_type,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen,
#elif __CONTIKI__
			toaddr,
			toport,
#else
#error TODO: Implement me!
#endif
			node->context
		);
	}

	smcp_daemon_send_response(self,
		tid,
		SMCP_RESULT_CODE_ACK,
		replyHeaders,
		NULL,
		0,
#if SMCP_USE_BSD_SOCKETS
		saddr,
		socklen
#elif __CONTIKI__
		toaddr,
		toport
#else
#error TODO: Implement me!
#endif
	);

bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_options(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	smcp_header_item_t replyHeaders[SMCP_MAX_HEADERS * 2 + 1] = {};

/*
    smcp_header_item_t *next_header;
    for(next_header=headers;smcp_header_item_get_key(next_header);next_header=smcp_header_item_next(next_header)) {
        if(smcp_header_item_key_equal(next_header,SMCP_HEADER_CSEQ))
            util_add_header(
                replyHeaders,
                SMCP_MAX_HEADERS,
                SMCP_HEADER_CSEQ,
                smcp_header_item_get_value(next_header),
                smcp_header_item_get_value_len(next_header)
            );
        else if(smcp_header_item_key_equal(next_header,SMCP_HEADER_ID))
            util_add_header(
                replyHeaders,
                SMCP_MAX_HEADERS,
                SMCP_HEADER_ID,
                smcp_header_item_get_value(next_header),
                smcp_header_item_get_value_len(next_header)
            );
    }
 */

	if(0 == strcmp("*", path)) {
		util_add_header(replyHeaders,
			SMCP_MAX_HEADERS,
			SMCP_HEADER_ALLOW,
			"GET, POST, OPTIONS, PAIR, LIST",
			HEADER_CSTR_LEN);
		smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_OK,
			replyHeaders,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
	} else {
		// Node should always be set by the time we get here.
		require(node, bail);

		switch(node->type) {
		case SMCP_NODE_ACTION:
			util_add_header(replyHeaders,
				SMCP_MAX_HEADERS,
				SMCP_HEADER_ALLOW,
				"POST, OPTIONS, PAIR",
				HEADER_CSTR_LEN);
			break;
		case SMCP_NODE_EVENT:
			util_add_header(replyHeaders,
				SMCP_MAX_HEADERS,
				SMCP_HEADER_ALLOW,
				"OPTIONS, PAIR",
				HEADER_CSTR_LEN);
			break;
		case SMCP_NODE_DEVICE:
			util_add_header(replyHeaders,
				SMCP_MAX_HEADERS,
				SMCP_HEADER_ALLOW,
				"GET, OPTIONS, LIST",
				HEADER_CSTR_LEN);
			break;
		case SMCP_NODE_VARIABLE:
			util_add_header(replyHeaders,
				SMCP_MAX_HEADERS,
				SMCP_HEADER_ALLOW,
				"GET, OPTIONS, LIST",
				HEADER_CSTR_LEN);
			break;
		}
		smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_OK,
			replyHeaders,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
	}
bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_get(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	char replyContent[128];
	size_t replyContentLength = 0;
	smcp_content_type_t replyContentType = SMCP_CONTENT_TYPE_TEXT_PLAIN;
	smcp_header_item_t replyHeaders[SMCP_MAX_HEADERS * 2 + 1];

	replyHeaders[0] = NULL;

/*
    int i;
    for(i=0;headers[i];i+=2) {
        if(0==strcmp(headers[i],SMCP_HEADER_CSEQ))
            util_add_header(replyHeaders,SMCP_MAX_HEADERS,SMCP_HEADER_CSEQ,headers[i+1],HEADER_CSTR_LEN);
        if(0==strcmp(headers[i],SMCP_HEADER_ID))
            util_add_header(replyHeaders,SMCP_MAX_HEADERS,SMCP_HEADER_ID,headers[i+1],HEADER_CSTR_LEN);
    }
 */

	// Node should always be set by the time we get here.
	require(node, bail);

	if(node->type == SMCP_NODE_VARIABLE) {
		replyContentLength = sizeof(replyContent);
		ret = (*((smcp_variable_node_t)node)->get_func)(
			    (smcp_variable_node_t)node,
			headers,
			replyContent,
			&replyContentLength,
			&replyContentType,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen,
#elif __CONTIKI__
			toaddr,
			toport,
#else
#error TODO: Implement me!
#endif
			    ((smcp_variable_node_t)node)->context
		    );
	} else {
		smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_BAD_REQUEST,
			replyHeaders,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
		goto bail;
	}

	if(ret != SMCP_STATUS_OK) {
		smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_INTERNAL_SERVER_ERROR,
			replyHeaders,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
		goto bail;
	}

	util_add_header(replyHeaders,
		SMCP_MAX_HEADERS,
		SMCP_HEADER_CONTENT_TYPE,
		get_content_type_string(replyContentType),
		HEADER_CSTR_LEN);

	smcp_daemon_send_response(self,
		tid,
		SMCP_RESULT_CODE_OK,
		replyHeaders,
		replyContent,
		replyContentLength,
#if SMCP_USE_BSD_SOCKETS
		saddr,
		socklen
#elif __CONTIKI__
		toaddr,
		toport
#else
#error TODO: Implement me!
#endif
	);
bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_list(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	const char* next_node = NULL;
	smcp_header_item_t replyHeaders[SMCP_MAX_HEADERS * 2 + 1];
	char replyContent[128];

	replyHeaders[0] = NULL;

	memset(replyContent, 0, sizeof(replyContent));
	int i;
	for(i = 0; headers[i]; i += 2) {
/*
        if(0==strcmp(headers[i],SMCP_HEADER_CSEQ))
            util_add_header(replyHeaders,SMCP_MAX_HEADERS,SMCP_HEADER_CSEQ,headers[i+1],HEADER_CSTR_LEN);
        if(0==strcmp(headers[i],SMCP_HEADER_ID))
            util_add_header(replyHeaders,SMCP_MAX_HEADERS,SMCP_HEADER_ID,headers[i+1],HEADER_CSTR_LEN);
 */
		if(0 == strcmp(headers[i], SMCP_HEADER_NEXT))
			next_node = headers[i + 1];
	}

	// Node should always be set by the time we get here.
	require(node, bail);

	if((node->type == SMCP_NODE_EVENT) ||
	        (node->type == SMCP_NODE_ACTION)) {
		// You can't call LIST on events or actions
		// TODO: PROTOCOL: Consider using this method for listing pairings...?
		smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_BAD_REQUEST,
			replyHeaders,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		);
		goto bail;
	}

	if(next_node) {
		smcp_node_t next;
		node = smcp_node_find_with_path(node, next_node);
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

		if(strlen(node_name) >
		        (sizeof(replyContent) - strlen(replyContent) - 2))
			break;

		if(node->type == SMCP_NODE_ACTION)
			strlcat(replyContent, "?", sizeof(replyContent));
		else if(node->type == SMCP_NODE_EVENT)
			strlcat(replyContent, "!", sizeof(replyContent));

		if(node->name)
			strlcat(replyContent, node_name, sizeof(replyContent));

		if(node->type == SMCP_NODE_DEVICE)
			strlcat(replyContent, "/", sizeof(replyContent));

		strlcat(replyContent, "\n", sizeof(replyContent));

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
		node = next;
	}

	// If there are more nodes, indicate as such in the headers.
	if(node) {
		util_add_header(replyHeaders,
			SMCP_MAX_HEADERS,
			SMCP_HEADER_MORE,
			"",
			HEADER_CSTR_LEN);
	}

	smcp_daemon_send_response(self,
		tid,
		SMCP_RESULT_CODE_OK,
		replyHeaders,
		replyContent,
		strlen(replyContent),
#if SMCP_USE_BSD_SOCKETS
		saddr,
		socklen
#elif __CONTIKI__
		toaddr,
		toport
#else
#error TODO: Implement me!
#endif
	);
bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_pair(
	smcp_daemon_t			self,
	smcp_node_t				node,
	smcp_transaction_id_t	tid,
	smcp_method_t			method,
	const char*				path,
	smcp_header_item_t		headers[],
	const char*				content,
	size_t					content_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;

	if(node && (node->type != SMCP_NODE_EVENT) &&
	        (node->type != SMCP_NODE_ACTION)) {
		ret = smcp_daemon_send_response(self,
			tid,
			SMCP_RESULT_CODE_BAD_REQUEST,
			NULL,
			NULL,
			0,
#if SMCP_USE_BSD_SOCKETS
			saddr,
			socklen
#elif __CONTIKI__
			toaddr,
			toport
#else
#error TODO: Implement me!
#endif
		    );
		goto bail;
	}

	ret = smcp_daemon_send_response(
		self,
		tid,
		smcp_convert_status_to_result_code(
			smcp_daemon_pair_with_uri(
				self,
				path,
				content,
				0
			)
		),
		NULL,
		NULL,
		0,
#if SMCP_USE_BSD_SOCKETS
		saddr,
		socklen
#elif __CONTIKI__
		toaddr,
		toport
#else
#error TODO: Implement me!
#endif
	    );
bail:
	return ret;
}

#pragma mark -
#pragma mark Nodes

smcp_node_t
smcp_daemon_get_root_node(smcp_daemon_t self) {
	return self->root_node;
}


smcp_status_t
smcp_daemon_trigger_event(
	smcp_daemon_t		self,
	const char*			path,
	const char*			content,
	size_t				content_length,
	smcp_content_type_t content_type
) {
	smcp_status_t ret = 0;
	smcp_pairing_t iter;
	char cseq[24];
	char url[SMCP_MAX_PATH_LENGTH + 128 + 1];
	smcp_transaction_id_t tid = SMCP_FUNC_RANDOM_UINT32();

	memset(cseq, 0, sizeof(cseq));

	const char* headers[] = {
		SMCP_HEADER_CSEQ,		  cseq,
		SMCP_HEADER_ORIGIN,		  url,
		SMCP_HEADER_CONTENT_TYPE, get_content_type_string(content_type),
		NULL
	};

	require_action(path, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	// Move past any preceding slashes.
	while(path && *path == '/') path++;

	// TODO: Get IP address, and add it to the URL!
	snprintf(url, sizeof(url) - 1, "smcp:%s", path);

	for(iter = smcp_daemon_get_first_pairing_for_path(self, path);
	    iter;
	    iter = smcp_daemon_next_pairing(self, iter)) {
		smcp_pairing_seq_t seq = smcp_pairing_get_next_seq(iter);

		DEBUG_PRINTF(CSTR("sending stuff for pairing \"%p\"..."), iter);

		snprintf(cseq,
			sizeof(cseq) - 1,
			"%lX POST",
			    (long unsigned int)seq);

		smcp_daemon_send_request(
			self,
			tid,
			SMCP_METHOD_POST,
			iter->path,
			headers,
			content,
			content_length,
#if SMCP_USE_BSD_SOCKETS
			    (struct sockaddr*)&iter->saddr,
			sizeof(iter->saddr)
#elif __CONTIKI__
			&iter->addr,
			iter->port
#else
#error TODO: Implement me!
#endif
		);

		// TODO: Handle retransmits for reliable pairings!
	}

bail:
	return ret;
}

smcp_status_t
smcp_daemon_refresh_variable(
	smcp_daemon_t daemon, smcp_variable_node_t node
) {
	smcp_status_t ret = 0;
	char content[512];
	size_t content_length = sizeof(content);
	smcp_content_type_t content_type = SMCP_CONTENT_TYPE_TEXT_PLAIN;
	char path[100];

	require_action(daemon != NULL,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(node != NULL, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	smcp_node_get_path((smcp_node_t)node, path, sizeof(path));

	strncat(path, "!changed", sizeof(path));

	if(node->get_func) {
		ret =
		    (*node->get_func)(node, NULL, content, &content_length,
			&content_type,
			NULL, 0, node->context);
		require(ret == 0, bail);
	}

	ret = smcp_daemon_trigger_event(
		daemon,
		path,
		content,
		content_length,
		content_type
	    );

bail:
	return ret;
}

//! Deprecated.
smcp_status_t
smcp_daemon_trigger_event_for_node(
	smcp_daemon_t		self,
	smcp_event_node_t	node,
	const char*			content,
	size_t				content_length,
	smcp_content_type_t content_type
) {
	smcp_status_t ret = 0;
	char path[SMCP_MAX_PATH_LENGTH + 1];

	require_action(SMCP_NODE_EVENT == node->type,
		bail,
		ret = SMCP_STATUS_BAD_NODE_TYPE);

	smcp_node_get_path((smcp_node_t)node, path, sizeof(path) - 1);

	ret = smcp_daemon_trigger_event(self,
		path,
		content,
		content_length,
		content_type);

bail:
	return ret;
}
