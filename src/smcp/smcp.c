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

#if CONTIKI
#include "contiki.h"
#include "net/uip-udp-packet.h"
#include "net/uiplib.h"
#include "net/tcpip.h"
#include "net/resolv.h"
extern u16_t uip_slen;
#endif

#include "assert_macros.h"
#include <stdarg.h>

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

#if CONTIKI
struct smcp_daemon_s smcp_daemon_global_instance;
smcp_daemon_t
smcp_get_current_daemon() {
	return &smcp_daemon_global_instance;
}
#define smcp_set_current_daemon(x)

#else
// TODO: Make thread safe!
static smcp_daemon_t smcp_daemon_current_instance;

smcp_daemon_t
smcp_get_current_daemon() {
	return smcp_daemon_current_instance;
}

#define smcp_set_current_daemon(x) \
    do { smcp_daemon_current_instance = (x); } while(0)
#endif

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
	case SMCP_STATUS_MALLOC_FAILURE: return "Malloc Failure"; break;
	case SMCP_STATUS_HANDLER_INVALIDATED: return "Handler Invalidated";
		break;
	case SMCP_STATUS_TIMEOUT: return "Timeout"; break;
	case SMCP_STATUS_NOT_IMPLEMENTED: return "Not Implemented"; break;
	case SMCP_STATUS_NOT_FOUND: return "Not Found"; break;
	case SMCP_STATUS_H_ERRNO: return "HERRNO"; break;
	case SMCP_STATUS_RESPONSE_NOT_ALLOWED: return "Response not allowed";
		break;

	case SMCP_STATUS_LOOP_DETECTED: return "Loop detected"; break;
	case SMCP_STATUS_BAD_ARGUMENT: return "Bad Argument"; break;
	case SMCP_STATUS_MESSAGE_TOO_BIG: return "Message Too Big"; break;

	case SMCP_STATUS_ERRNO:
#if 1
		return "ERRNO"; break;
#else
		return strerror(errno); break;
#endif
	default: return "Unknown error"; break;
	}
	return NULL;
}

#pragma mark -
#pragma mark Private SMCP Types


static bt_compare_result_t
smcp_transaction_compare(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_transaction_t lhs = (smcp_transaction_t)lhs_;
	const smcp_transaction_t rhs = (smcp_transaction_t)rhs_;

	if(lhs->tid > rhs->tid)
		return 1;
	if(lhs->tid < rhs->tid)
		return -1;
	return 0;
}

static bt_compare_result_t
smcp_transaction_compare_tid(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_transaction_t lhs = (smcp_transaction_t)lhs_;
	coap_transaction_id_t rhs = *(coap_transaction_id_t*)rhs_;

	if(lhs->tid > rhs)
		return 1;
	if(lhs->tid < rhs)
		return -1;
	return 0;
}

#pragma mark -
#pragma mark Declarations


smcp_status_t smcp_daemon_handle_list(
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length);

smcp_status_t smcp_invalidate_transaction(
	smcp_daemon_t self, coap_transaction_id_t tid);

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

	ret->port = port;

#if SMCP_USE_BSD_SOCKETS
	ret->fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	require_action_string(ret->fd > 0, bail, { smcp_daemon_release(
				ret); ret = NULL; }, "Failed to create socket");

	// Keep attempting to bind until we find a port that works.
	while(bind(ret->fd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
		// We should only continue trying if errno == EADDRINUSE.
		require_action_string(errno == EADDRINUSE, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_daemon_release(
				    ret); ret = NULL; }, "Failed to bind socket");
		ret->port++;

		// Make sure we aren't in an infinite loop.
		require_action_string(port!=ret->port, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_daemon_release(
				    ret); ret = NULL; }, "Failed to bind socket (ran out of ports)");

		saddr.sin6_port = htons(ret->port);
	}

	// Now we need to figure out what port we actually bound to.
	socklen_t socklen = sizeof(saddr);
	getsockname(ret->fd, (struct sockaddr*)&saddr, &socklen);
	ret->port = ntohs(saddr.sin6_port);

#elif CONTIKI
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
		smcp_invalidate_transaction(self, self->handlers->tid);
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
#elif CONTIKI
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
#elif defined(CONTIKI)
struct uip_udp_conn*
smcp_daemon_get_udp_conn(smcp_daemon_t self) {
	return self->udp_conn;
}
#endif

const coap_header_item_t*
smcp_daemon_get_current_request_headers() {
	if(smcp_get_current_daemon()->is_processing_message)
		return smcp_get_current_daemon()->current_inbound_headers;
	return NULL;
}

uint8_t
smcp_daemon_get_current_request_header_count() {
	if(smcp_get_current_daemon()->is_processing_message)
		return smcp_get_current_daemon()->current_inbound_header_count;
	return 0;
}

coap_transaction_id_t
smcp_daemon_get_current_tid() {
	return smcp_get_current_daemon()->current_inbound_request_tid;
}

#if SMCP_USE_BSD_SOCKETS
struct sockaddr* smcp_daemon_get_current_request_saddr() {
	return smcp_get_current_daemon()->current_inbound_saddr;
}

socklen_t smcp_daemon_get_current_request_socklen() {
	return smcp_get_current_daemon()->current_inbound_socklen;
}
#elif defined(CONTIKI)
const uip_ipaddr_t* smcp_daemon_get_current_request_ipaddr() {
	return &smcp_get_current_daemon()->current_inbound_toaddr;
}

const uint16_t smcp_daemon_get_current_request_ipport() {
	return smcp_get_current_daemon()->current_inbound_toport;
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

	require(header_length > 0, bail);

	DEBUG_PRINTF(CSTR("%p: tt=%d"), self,tt);
	DEBUG_PRINTF(CSTR("%p: http.code=%d"), self,COAP_TO_HTTP_CODE(code));

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	// Kind of a hack.
	packet[packet_length] = 0;

	self->current_inbound_request_tid = tid;

#if SMCP_USE_BSD_SOCKETS
	self->current_inbound_saddr = saddr;
	self->current_inbound_socklen = socklen;
#elif CONTIKI
	self->current_inbound_toaddr = *toaddr;
	self->current_inbound_toport = toport;
#endif

	smcp_set_current_daemon(self);
	self->is_processing_message = true;
	self->did_respond = (tt != COAP_TRANS_TYPE_CONFIRMABLE);
	self->cascade_count = SMCP_MAX_CASCADE_COUNT;
	self->has_cascade_count = false;

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
				self->has_cascade_count = true;
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
		coap_header_item_t *iter = self->current_inbound_headers;
		coap_header_item_t *end = iter +
		    self->current_inbound_header_count;

		for(; iter != end; ++iter) {
			if(iter->key == COAP_HEADER_CASCADE_COUNT) {
				if(iter->value_len)
					self->cascade_count = ((unsigned char)*iter->value) -
					    1;
				else
					self->cascade_count = 128 - 1;
				if(self->cascade_count > SMCP_MAX_CASCADE_COUNT)
					self->cascade_count = SMCP_MAX_CASCADE_COUNT;
				self->has_cascade_count = true;
			}
		}


		status = smcp_daemon_handle_response(
			self,
			coap_to_http_code(code),
			packet + header_length,
			packet_length - header_length
		    );
	}

	check_string(status == SMCP_STATUS_OK, smcp_status_to_cstr(status));

	// Check to make sure we have responded by now. If not, we need to.
	if((tt==COAP_TRANS_TYPE_CONFIRMABLE) && !self->did_respond) {
		if(COAP_CODE_IS_REQUEST(code)) {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(smcp_convert_status_to_result_code(status)));
		} else {
			// TODO: Need a way to specify a reset response.
			smcp_message_begin_response(0);
		}
		smcp_message_send();
	}

bail:
	smcp_set_current_daemon(NULL);
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

	smcp_set_current_daemon(self);
	smcp_daemon_handle_timers(self);
	smcp_set_current_daemon(NULL);

bail:
	return ret;
}

#pragma mark -
#pragma mark Constrained sending API

smcp_status_t
smcp_message_begin(
	smcp_daemon_t self, coap_code_t code, coap_transaction_type_t tt
) {
	if(!self)
		self = smcp_get_current_daemon();
	check(!smcp_get_current_daemon() || smcp_get_current_daemon()==self);
	smcp_set_current_daemon(self);

	self->is_responding = false;

	self->current_outbound_header_count = 0;
	self->current_outbound_tt = tt;
	self->current_outbound_code = code;

	self->current_outbound_header_len = 0;
	self->current_outbound_content_len = 0;

#if SMCP_USE_BSD_SOCKETS
	self->current_outbound_socklen = 0;
#elif defined(CONTIKI)
	// TODO: Writeme
#endif
	return SMCP_STATUS_OK;
}

smcp_status_t smcp_message_begin_response(coap_code_t code) {
	smcp_status_t ret = SMCP_STATUS_OK;

	const smcp_daemon_t self = smcp_get_current_daemon();

	require_action_string(!self->did_respond,
		bail,
		ret = SMCP_STATUS_RESPONSE_NOT_ALLOWED,
		"Attempted to send more than one response!"
	);
	self->is_responding = true;

	smcp_message_begin(self,code,COAP_TRANS_TYPE_ACK);
	smcp_message_set_tid(self->current_inbound_request_tid);

	if(self->current_inbound_request_token) {
		ret = smcp_message_add_header(
			COAP_HEADER_TOKEN,
			self->current_inbound_request_token,
			self->current_inbound_request_token_len
		);
	}
	if(self->has_cascade_count) {
		ret = smcp_message_add_header(
			COAP_HEADER_CASCADE_COUNT,
			(char*)&self->cascade_count,
			1
		);
	}

#if SMCP_USE_BSD_SOCKETS
	ret = smcp_message_set_destaddr(
		self->current_inbound_saddr,
		self->current_inbound_socklen
	);
#elif CONTIKI
	ret = smcp_message_set_destaddr(
		&self->current_inbound_toaddr,
		self->current_inbound_toport
	);
#endif

bail:
	return ret;
}

smcp_status_t
smcp_message_set_tid(coap_transaction_id_t tid) {
	smcp_get_current_daemon()->current_outbound_tid = tid;
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_message_set_code(coap_code_t code) {
	smcp_get_current_daemon()->current_outbound_code = code;
	// TODO: More work required here?
	return SMCP_STATUS_NOT_IMPLEMENTED;
}

#if SMCP_USE_BSD_SOCKETS
smcp_status_t
smcp_message_set_destaddr(
	struct sockaddr *sockaddr, socklen_t socklen
) {
	memcpy(
		&smcp_get_current_daemon()->current_outbound_saddr,
		sockaddr,
		socklen
	);
	smcp_get_current_daemon()->current_outbound_socklen = socklen;

	return SMCP_STATUS_OK;
}
#elif defined(CONTIKI)
smcp_status_t
smcp_message_set_destaddr(
	const uip_ipaddr_t *toaddr, uint16_t toport
) {
	uip_ipaddr_copy(&smcp_get_current_daemon()->udp_conn->ripaddr, toaddr);
	smcp_get_current_daemon()->udp_conn->rport = toport;

	return SMCP_STATUS_OK;
}
#endif

smcp_status_t
smcp_message_add_header(
	coap_header_key_t key, const char* value, size_t len
) {
	// TODO: Make sure we don't overflow!
	coap_header_item_t* item = &smcp_get_current_daemon()
		->current_outbound_headers[smcp_get_current_daemon()->current_outbound_header_count++];

	item->key = key;
	item->value = (char*)value;
	item->value_len = len;

	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_message_set_uri(
	const char* uri, char flags
) {
	smcp_status_t ret = SMCP_STATUS_OK;

	const char* start;

	if(!(flags&SMCP_MSG_SKIP_DESTADDR))
	do {
	char* addr_str = NULL;
	char* port_str = NULL;

	uint16_t toport = htons(SMCP_DEFAULT_PORT);

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
		.sin6_family	= AF_INET6,
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
	};
#elif CONTIKI
	uip_ipaddr_t toaddr;
#endif

	require_action(uri, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	if(!url_is_absolute(uri)) {
		// Pairing with ourselves
		addr_str = "::1";
		toport = htons(smcp_get_current_daemon()->port);
	} else {
		char* uri_copy = alloca(strlen(uri) + 1);

		strcpy(uri_copy, uri);

		// Parse the URI.
		require_action_string(
			url_parse(
				uri_copy,
				NULL,
				NULL,
				NULL,
				&addr_str,
				&port_str,
				NULL,
				NULL
			),
			bail,
			ret = SMCP_STATUS_UNSUPPORTED_URI,
			"Unable to parse URL"
		);

		if(port_str)
			toport = htons(strtol(port_str, NULL, 10));
	}

	// If we don't have an address, skip this part.
	if(!addr_str || addr_str[0]==0)
		break;

	DEBUG_PRINTF(
		CSTR("URI Parse: \"%s\" -> host=\"%s\" port=\"%u\""),
		uri,
		addr_str,
		(int)ntohs(toport)
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

	smcp_message_set_destaddr((struct sockaddr *)&saddr,sizeof(struct sockaddr_in6));

#elif CONTIKI
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

	smcp_message_set_destaddr(&toaddr,toport);
#else
#error TODO: Implement me!
#endif
	} while(0);

	if(url_is_absolute(uri)) {
		// Skip past scheme.
		while((*uri != ':'))
			if(!*uri++)
				goto bail;

		uri++;

		if((uri[0] != '/') || (uri[1] != '/'))
			goto bail;

		uri += 2;

		start = uri;

		// Skip past authority.
		while((*uri != '/') && *uri)
			uri++;

		if(!(flags&SMCP_MSG_SKIP_AUTHORITY))
			smcp_message_add_header(COAP_HEADER_URI_AUTHORITY,
				start,
				uri - start);
	}

	if(!*uri)
		goto bail;

	// Skip past first slashes.
	while((*uri == '/') && *uri)
		uri++;

	start = uri;

	// Skip past path.
	while((*uri != '?') && *uri)
		uri++;

	if(uri - start)
		smcp_message_add_header(COAP_HEADER_URI_PATH, start, uri - start);

	if(!*uri++)
		goto bail;

	start = uri;

	if(!*uri)
		goto bail;

	// Skip to the end
	while(*uri++) ;

	smcp_message_add_header(COAP_HEADER_URI_QUERY, start, uri - start);




bail:
	return ret;
}

smcp_status_t
smcp_message_set_content(const char* value,size_t len) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;

	size_t max_len;
	char* dest;

	if(len==COAP_HEADER_CSTR_LEN)
		len = strlen(value);

	max_len = len;

	dest = smcp_message_get_content_ptr(&max_len);

	require(dest,bail);

	require(max_len>=len,bail);

	memcpy(dest, value, len);

	smcp_message_set_content_len(len);

	ret = SMCP_STATUS_OK;

bail:
	return ret;
}

char*
smcp_message_get_content_ptr(size_t* max_len) {
#if VERBOSE_DEBUG
	coap_dump_headers(SMCP_DEBUG_OUT_FILE,
		"Outbound: ",
		smcp_get_current_daemon()->current_outbound_code,
		smcp_get_current_daemon()->current_outbound_headers,
		smcp_get_current_daemon()->current_outbound_header_count
	);
	DEBUG_PRINTF(CSTR("Outbound: tt=%d"),smcp_get_current_daemon()->current_outbound_tt);
#endif

	char* buffer;

#if SMCP_USE_BSD_SOCKETS
	buffer = smcp_get_current_daemon()->current_outbound_packet;
#elif CONTIKI
	uip_udp_conn = smcp_get_current_daemon()->udp_conn;
	buffer = (unsigned char*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
#else
#error WRITEME!
#endif

	smcp_get_current_daemon()->current_outbound_header_len = coap_encode_header(
		(unsigned char*)buffer,
		SMCP_MAX_PACKET_LENGTH,
		smcp_get_current_daemon()->current_outbound_tt,
		smcp_get_current_daemon()->current_outbound_code,
		smcp_get_current_daemon()->current_outbound_tid,
		smcp_get_current_daemon()->current_outbound_headers,
		smcp_get_current_daemon()->current_outbound_header_count
	);

	if(max_len)
		*max_len = SMCP_MAX_PACKET_LENGTH-smcp_get_current_daemon()->current_outbound_header_len;

	return buffer + smcp_get_current_daemon()->current_outbound_header_len;
}

smcp_status_t
smcp_message_set_content_len(size_t len) {
	smcp_get_current_daemon()->current_outbound_content_len = len;
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_message_send() {
	smcp_status_t ret = SMCP_STATUS_FAILURE;

	if(!smcp_get_current_daemon()->current_outbound_header_len) {
		require(smcp_message_get_content_ptr(NULL)!=NULL,bail);
	}

#if SMCP_USE_BSD_SOCKETS

	require_string(smcp_get_current_daemon()->current_outbound_socklen,bail,"Destaddr not set");

	ssize_t sent_bytes = sendto(
		smcp_get_current_daemon()->fd,
		smcp_get_current_daemon()->current_outbound_packet,
		smcp_get_current_daemon()->current_outbound_header_len +
		smcp_get_current_daemon()->current_outbound_content_len,
		0,
		(struct sockaddr *)&smcp_get_current_daemon()->current_outbound_saddr,
		smcp_get_current_daemon()->current_outbound_socklen
	);

	require_action_string(
		(sent_bytes>=0),
		bail, ret = SMCP_STATUS_ERRNO, strerror(errno)
	);

	require_action_string(
		sent_bytes,
		bail, ret = SMCP_STATUS_FAILURE, "sendto() returned zero."
	);

#elif CONTIKI
	uip_udp_conn = smcp_get_current_daemon()->udp_conn;
	uip_slen = smcp_get_current_daemon()->current_outbound_header_len +
		smcp_get_current_daemon()->current_outbound_content_len;

	uip_process(UIP_UDP_SEND_CONN);

#if UIP_CONF_IPV6
	tcpip_ipv6_output();
#else
	if(uip_len > 0)
		tcpip_output();
#endif
	uip_slen = 0;

	memset(&smcp_get_current_daemon()->udp_conn->ripaddr, 0,
		sizeof(uip_ipaddr_t));
	smcp_get_current_daemon()->udp_conn->rport = 0;
#endif
	if(smcp_get_current_daemon()->is_responding)
		smcp_get_current_daemon()->did_respond = true;
	smcp_get_current_daemon()->is_responding = false;

	ret = SMCP_STATUS_OK;
bail:
	return ret;
}

#pragma mark -

smcp_status_t
smcp_message_set_content_type(coap_content_type_t t) {
	static coap_content_type_t type;
	type = t;
	return smcp_message_add_header(COAP_HEADER_CONTENT_TYPE, (char*)&type, 1);
}

smcp_status_t
smcp_message_set_content_formatted(const char* fmt, ...) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	size_t len = 0;
	va_list args;
	va_start(args,fmt);

	char* content = smcp_message_get_content_ptr(&len);

	require(content!=NULL,bail);

	len = vsnprintf(content,len,fmt,args);

	require(len!=0,bail);

	ret = smcp_message_set_content_len(len);

bail:
	va_end(args);
	return ret;
}

smcp_status_t
smcp_message_set_var_content_int(int v) {
	smcp_message_set_content_type(SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	return smcp_message_set_content_formatted("v=%d",v);
}

smcp_status_t
smcp_message_set_var_content_unsigned_int(unsigned int v) {
	smcp_message_set_content_type(SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	return smcp_message_set_content_formatted("v=%u",v);
}

smcp_status_t
smcp_message_set_var_content_unsigned_long_int(unsigned long int v) {
	smcp_message_set_content_type(SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	return smcp_message_set_content_formatted("v=%ul",v);
}









#pragma mark -
#pragma mark SMCP Response Handler

void
smcp_internal_delete_handler_(
	smcp_transaction_t handler,
	smcp_daemon_t			self
) {
	DEBUG_PRINTF(CSTR(
			"%p: Deleting response handler w/tid=%d"), self, handler->tid);

	// Remove the timer associated with this handler.
	smcp_daemon_invalidate_timer(self, &handler->timer);

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		    (*handler->callback)(
			SMCP_STATUS_HANDLER_INVALIDATED,
			NULL,
			0,
			handler->context
		);
	}

	free(handler);
}

//static int smcp_rtt = COAP_RESPONSE_TIMEOUT;
static int smcp_rtt = 100;

static int calc_retransmit_timeout(int retries_) {
	int ret = smcp_rtt;

	ret = (ret<<retries_);

	ret *= (1000 - 150) + (SMCP_FUNC_RANDOM_UINT32() % 300);

	ret /= 1000;

	if(ret > 2500)
		ret = 2500;

	return ret;
}

void
smcp_internal_handler_timeout_(
	smcp_daemon_t			self,
	smcp_transaction_t handler
) {
	smcp_response_handler_func callback = handler->callback;
	void* context = handler->context;

	if(handler->resendCallback && (convert_timeval_to_cms(&handler->expiration) > 0)) {
		// Resend and try another day.
		self->current_outbound_tid = handler->tid;
		handler->resendCallback(context);
		int retryAfter = calc_retransmit_timeout(handler->attemptCount++);

		smcp_daemon_schedule_timer(
			self,
			&handler->timer,
			retryAfter
		);

	} else if(callback) {
		handler->callback = NULL;
		smcp_invalidate_transaction(self, handler->tid);
		(*callback)(
		    SMCP_STATUS_TIMEOUT,
		    NULL,
		    0,
		    context
		);
	} else {
		smcp_invalidate_transaction(self, handler->tid);
	}
}

smcp_status_t
smcp_begin_transaction(
	smcp_daemon_t				self,
	coap_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_request_resend_func resendCallback,
	smcp_response_handler_func	callback,
	void*						context
) {
	smcp_status_t ret = 0;
	smcp_transaction_t handler;

	require_action(callback != NULL,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT);

	handler = (smcp_transaction_t)calloc(sizeof(*handler), 1);

	require_action(handler, bail, ret = SMCP_STATUS_MALLOC_FAILURE);

	DEBUG_PRINTF(CSTR("%p: Adding response handler w/tid=%d"), self, tid);

	handler->tid = tid;
	handler->resendCallback = resendCallback;
	handler->callback = callback;
	handler->context = context;
	handler->flags = flags;
	convert_cms_to_timeval(&handler->expiration, cmsExpiration);
	handler->attemptCount = 0;

	if(resendCallback) {
		// In this case we will be reattempting for a given duration.
		// The first attempt should happen pretty much immediately.
		cmsExpiration = 0;
	}

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
		    (bt_compare_func_t)smcp_transaction_compare,
		    (bt_delete_func_t)smcp_internal_delete_handler_,
		self
	);

	DEBUG_PRINTF(CSTR("%p: Total Handlers: %d"), self,
		(int)bt_count((void**)&self->handlers));

bail:
	return ret;
}

smcp_status_t
smcp_invalidate_transaction(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid
) {
	bt_remove(
		    (void**)&self->handlers,
		    (void*)&tid,
		    (bt_compare_func_t)smcp_transaction_compare_tid,
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
	smcp_transaction_t handler = NULL;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(CSTR(
				"smcp_daemon(%p): Incoming response! tid=%d"), self,
			smcp_daemon_get_current_tid());
		coap_dump_headers(
			SMCP_DEBUG_OUT_FILE,
			"    ",
			(int)HTTP_TO_COAP_CODE(statuscode),
			smcp_daemon_get_current_request_headers(),
			smcp_daemon_get_current_request_header_count()
		);

/*
        bool content_is_text;
        if(content_is_text)
            DEBUG_PRINTF(CSTR("CONTENT: \"%s\""),content);
 */
	}
#endif

	DEBUG_PRINTF(CSTR("%p: Total Handlers: %d"), self,
		(int)bt_count((void**)&self->handlers));

	coap_transaction_id_t tid = smcp_daemon_get_current_tid();

	handler = (smcp_transaction_t)bt_find(
		    (void**)&self->handlers,
		    (void*)&tid,
		    (bt_compare_func_t)smcp_transaction_compare_tid,
		self
	    );

#if VERBOSE_DEBUG
	require_string(handler, bail, "Unable to find response handler");
#else
	require_quiet(handler, bail);
#endif

	if(handler->callback) {
		if(handler->flags & SMCP_RESPONSE_HANDLER_ALWAYS_TIMEOUT) {
			handler->resendCallback = NULL;
			(*handler->callback)(
				statuscode,
				content,
				content_length,
				handler->context
			);
		} else {
			smcp_response_handler_func callback = handler->callback;
			handler->resendCallback = NULL;
			handler->callback = NULL;
			(*callback)(
			    statuscode,
			    content,
			    content_length,
			    handler->context
			);
		}
		smcp_invalidate_transaction(self, tid);
	}

bail:
	return ret;
}


int smcp_convert_status_to_result_code(smcp_status_t status) {
	int ret = HTTP_RESULT_CODE_INTERNAL_SERVER_ERROR;

	switch(status) {
	case SMCP_STATUS_OK:
		ret = HTTP_RESULT_CODE_OK;
		break;
	case SMCP_STATUS_NOT_FOUND:
		ret = HTTP_RESULT_CODE_NOT_FOUND;
		break;
	case SMCP_STATUS_NOT_IMPLEMENTED:
		ret = HTTP_RESULT_CODE_NOT_IMPLEMENTED;
		break;
	case SMCP_STATUS_NOT_ALLOWED:
		ret = HTTP_RESULT_CODE_METHOD_NOT_ALLOWED;
		break;
	case SMCP_STATUS_BAD_NODE_TYPE:
	case SMCP_STATUS_UNSUPPORTED_URI:
		ret = HTTP_RESULT_CODE_BAD_REQUEST;
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
			smcp_daemon_get_current_tid());
		coap_dump_headers(
			SMCP_DEBUG_OUT_FILE,
			"    ",
			    (int)method,
			smcp_daemon_get_current_request_headers(),
			smcp_daemon_get_current_request_header_count()
		);
	}
#endif

	// TODO: Add authentication!

	smcp_node_t node;
	smcp_request_handler_func request_handler;

	request_handler = &smcp_default_request_handler;

	// Try to find the closest node and call the request_handler handler.
	path +=
	    smcp_node_find_closest_with_path(smcp_daemon_get_root_node(
			self), path,
		    (smcp_node_t*)&node);

	require(node, bail);

	if(node->request_handler)
		request_handler = node->request_handler;

	if(method == COAP_METHOD_PAIR) {
		request_handler = &smcp_daemon_handle_pair;
	}

	ret = (*request_handler)(
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
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	if(method == COAP_METHOD_GET) {
		if(!node->parent && strequal_const(path, ".well-known/core")) {
			// Redirect requests for .well-known/core to the root for now.
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_TEMPORARY_REDIRECT));
			smcp_message_add_header(COAP_HEADER_LOCATION, "/", 1);
			smcp_message_set_content("Redirected to </>.\n",COAP_HEADER_CSTR_LEN);
			smcp_message_send();
		}
		return smcp_daemon_handle_list(node,
			method,
			path,
			content,
			content_length);
	}
	if(method == COAP_METHOD_PAIR) {
		return smcp_daemon_handle_pair(node,
			method,
			path,
			content,
			content_length);
	}
	if(!path || (path[0] == 0)) {
		DEBUG_PRINTF(CSTR(
				"Unknown method in request: %s"), http_code_to_cstr(method));
		return SMCP_STATUS_NOT_IMPLEMENTED;
	}
	return SMCP_STATUS_NOT_FOUND;
}

smcp_status_t
smcp_daemon_handle_list(
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_status_t ret = 0;
	char* next_node = NULL;
	char replyContent[SMCP_MAX_PATH_LENGTH + 32 + 1];
	size_t content_break_threshold = 120;
	size_t content_offset = 0;

	smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));

	memset(replyContent, 0, sizeof(replyContent));

	const coap_header_item_t *iter =
	    smcp_daemon_get_current_request_headers();
	const coap_header_item_t *end = iter +
	    smcp_daemon_get_current_request_header_count();
	for(; iter != end; ++iter) {
		if(iter->key == COAP_HEADER_CONTINUATION_RESPONSE) {
			next_node = alloca(iter->value_len + 1);
			memcpy(next_node, iter->value, iter->value_len);
			next_node[iter->value_len] = 0;
		} else if(iter->key == COAP_HEADER_SIZE_REQUEST) {
			uint8_t i;
			content_break_threshold = 0;
			for(i = 0; i < iter->value_len; i++)
				content_break_threshold =
				    (content_break_threshold << 8) + iter->value[i];
			if(content_break_threshold >= sizeof(replyContent)) {
				DEBUG_PRINTF(CSTR(
						"Requested size (%d) is too large, trimming to %d."),
					(int)content_break_threshold, (int)sizeof(replyContent) - 1);
				content_break_threshold = sizeof(replyContent) - 1;
			}
		}
	}

	// We only support this method on direct queries.
	require_action(path[0] == 0, bail, ret = SMCP_STATUS_NOT_FOUND);

	if((content_break_threshold == 0) || (content_offset && !next_node)) {
		// We don't support content offsets right now.
		// TODO: Think about the implications of content offsets.
		smcp_message_set_code(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE));
		goto bail;
	}

	// Node should always be set by the time we get here.
	require_action(node, bail, ret = SMCP_STATUS_BAD_ARGUMENT);

	if(next_node && next_node[0]) {
		smcp_node_t next;
		node = smcp_node_find_with_path(node, next_node);
		smcp_message_set_code(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT));
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
	next_node = NULL;

	while(node) {
		smcp_node_t next;
		const char* node_name = node->name;

		if(!node_name)
			break;

		if(next_node) {
			if(((int)strlen(node_name) + 4) >
			        (int)((int)content_break_threshold -
			            (int)strlen(replyContent) - 2))
				break;
		} else {
			if((strlen(node_name) + 4) >
			        (sizeof(replyContent) - strlen(replyContent) - 3))
				break;
		}

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
	if(node && next_node) {
		smcp_message_set_code(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT));
		smcp_message_add_header(
			COAP_HEADER_CONTINUATION_REQUEST,
			next_node,
			HEADER_CSTR_LEN
		);
	}

	coap_content_type_t content_type =
	    COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;

	smcp_message_add_header(
		COAP_HEADER_CONTENT_TYPE,
		    (const void*)&content_type,
		1
	);

	smcp_message_set_content(replyContent, COAP_HEADER_CSTR_LEN);

bail:
	if(ret)
		smcp_message_set_code(HTTP_TO_COAP_CODE(smcp_convert_status_to_result_code(ret)));
	smcp_message_send();
	return ret;
}


#pragma mark -
#pragma mark Nodes

smcp_node_t
smcp_daemon_get_root_node(smcp_daemon_t self) {
	return &self->root_node;
}
