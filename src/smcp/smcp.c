/*	@file smcp.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#define __APPLE_USE_RFC_3542 1

#include "assert-macros.h"

#if CONTIKI
#include "contiki.h"
#include "net/uip-udp-packet.h"
#include "net/uiplib.h"
#if UIP_CONF_IPV6
#include "net/uip-ds6.h"
#endif
#include "net/tcpip.h"
#include "net/resolv.h"
extern uint16_t uip_slen;
#endif

#include <stdarg.h>

#include "smcp-opts.h"
#include "smcp.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ll.h"

#include "url-helpers.h"
#include "smcp-logging.h"
#include "smcp-auth.h"

#if SMCP_USE_BSD_SOCKETS
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "smcp-helpers.h"

#include "smcp-timer.h"
#include "smcp-internal.h"

#pragma mark -

#if SMCP_EMBEDDED
struct smcp_s smcp_global_instance;
#else
static smcp_t smcp_current_instance;
void
smcp_set_current_instance(smcp_t x) {
	smcp_current_instance = (x);
}
smcp_t
smcp_get_current_instance() {
	return smcp_current_instance;
}
#endif

#pragma mark -
#pragma mark SMCP Implementation

#if !SMCP_EMBEDDED
smcp_t
smcp_create(uint16_t port) {
	smcp_t ret = NULL;

	ret = (smcp_t)calloc(1, sizeof(struct smcp_s));

	require(ret != NULL, bail);

	ret = smcp_init(ret, port);

bail:
	return ret;
}
#endif

smcp_t
smcp_init(
	smcp_t self, uint16_t port
) {
	SMCP_EMBEDDED_SELF_HOOK;

	require(self != NULL, bail);

	if(port == 0)
		port = COAP_DEFAULT_PORT;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
		.sin6_family	= AF_INET6,
		.sin6_port		= htons(port),
	};
#endif

	// Clear the entire structure.
	memset(self, 0, sizeof(*self));

	// Set up the UDP port for listening.
#if SMCP_USE_BSD_SOCKETS
	uint16_t attempts = 0x7FFF;

	self->mcfd = -1;
	self->fd = -1;
	errno = 0;

	self->fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	int prev_errno = errno;

	require_action_string(
		self->fd >= 0,
		bail, (
			smcp_release(self),
			self = NULL
		),
		strerror(prev_errno)
	);

	// Keep attempting to bind until we find a port that works.
	while(bind(self->fd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
		// We should only continue trying if errno == EADDRINUSE.
		require_action_string(errno == EADDRINUSE, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_release(
				    self); self = NULL; }, "Failed to bind socket");
		port++;

		// Make sure we aren't in an infinite loop.
		require_action_string(--attempts, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_release(
				    self); self = NULL; }, "Failed to bind socket (ran out of ports)");

		saddr.sin6_port = htons(port);
	}

#ifdef IPV6_PREFER_TEMPADDR
#ifndef IP6PO_TEMPADDR_NOTPREFER
#define IP6PO_TEMPADDR_NOTPREFER 0
#endif
	{
		int value = IP6PO_TEMPADDR_NOTPREFER;
		setsockopt(self->fd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR, &value, sizeof(value));
	}
#endif

#elif CONTIKI
	self->udp_conn = udp_new(NULL, 0, NULL);
	uip_udp_bind(self->udp_conn, htons(port));
	self->udp_conn->rport = 0;

#if UIP_CONF_IPV6
	{
		uip_ipaddr_t all_coap_nodes_addr;
		if(uiplib_ipaddrconv(
			COAP_MULTICAST_IP6_ALLDEVICES,
			&all_coap_nodes_addr
		)) {
			uip_ds6_maddr_add(&all_coap_nodes_addr);
		}
	}
#endif
#endif

	// Go ahead and start listening on our multicast address as well.
#if SMCP_USE_BSD_SOCKETS
	{   // Join the multicast group for COAP_MULTICAST_IP6_ALLDEVICES
		struct ipv6_mreq imreq;
		int btrue = 1;
		struct hostent *tmp = gethostbyname2(COAP_MULTICAST_IP6_ALLDEVICES,
			AF_INET6);
		memset(&imreq, 0, sizeof(imreq));
		self->mcfd = socket(AF_INET6, SOCK_DGRAM, 0);

		require(!h_errno && tmp, skip_mcast);
		require(tmp->h_length > 1, skip_mcast);

		memcpy(&imreq.ipv6mr_multiaddr.s6_addr, tmp->h_addr_list[0], 16);

		require(0 ==
			setsockopt(self->mcfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
				&btrue,
				sizeof(btrue)), skip_mcast);

		// Do a precautionary leave group, to clear any stake kernel data.
		setsockopt(self->mcfd,
			IPPROTO_IPV6,
			IPV6_LEAVE_GROUP,
			&imreq,
			sizeof(imreq));

		require(0 ==
			setsockopt(self->mcfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &imreq,
				sizeof(imreq)), skip_mcast);

	skip_mcast:
		(void)0;
	}
#endif

	self->is_processing_message = false;

bail:
	return self;
}

void
smcp_release(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	require(self, bail);

	// Delete all pending transactions
	while(self->transactions) {
		smcp_transaction_end(self, self->transactions);
	}

	// Delete all timers
	while(self->timers) {
		smcp_timer_t timer = self->timers;
		if(timer->cancel)
			timer->cancel(self, timer->context);
		smcp_invalidate_timer(self, timer);
	}

#if SMCP_USE_BSD_SOCKETS
	if(self->fd>=0)
		close(self->fd);
	if(self->mcfd>=0)
		close(self->mcfd);
#elif CONTIKI
	if(self->udp_conn)
		uip_udp_remove(self->udp_conn);
#endif

#if !SMCP_EMBEDDED
	free(self);
#endif

bail:
	return;
}

uint16_t
smcp_get_port(smcp_t self) {
#if SMCP_USE_BSD_SOCKETS
	SMCP_EMBEDDED_SELF_HOOK;
	struct sockaddr_in6 saddr;
	socklen_t socklen = sizeof(saddr);
	getsockname(self->fd, (struct sockaddr*)&saddr, &socklen);
	return ntohs(saddr.sin6_port);
#elif CONTIKI
	SMCP_EMBEDDED_SELF_HOOK;
	return ntohs(self->udp_conn->lport);
#endif
}

#if SMCP_USE_BSD_SOCKETS
int
smcp_get_fd(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	return self->fd;
}
#elif defined(CONTIKI)
struct uip_udp_conn*
smcp_get_udp_conn(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	return self->udp_conn;
}
#endif

void
smcp_set_proxy_url(smcp_t self,const char* url) {
	SMCP_EMBEDDED_SELF_HOOK;
	assert(self);
	free((void*)self->proxy_url);
	if(url)
		self->proxy_url = strdup(url);
	else
		self->proxy_url = NULL;
	DEBUG_PRINTF("CoAP Proxy URL set to %s",self->proxy_url);
}

void
smcp_set_default_request_handler(smcp_t self,smcp_request_handler_func request_handler, void* context)
{
	SMCP_EMBEDDED_SELF_HOOK;
	assert(self);
	self->request_handler = request_handler;
	self->request_handler_context = context;
}

#pragma mark -

smcp_status_t
smcp_process(
	smcp_t self, cms_t cms
) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_status_t ret = 0;

#if SMCP_USE_BSD_SOCKETS
	int tmp;
	struct pollfd pollee = { self->fd, POLLIN | POLLHUP, 0 };

	if(cms >= 0)
		cms = MIN(cms, smcp_get_timeout(self));
	else
		cms = smcp_get_timeout(self);

	errno = 0;

	tmp = poll(&pollee, 1, cms);

	// Ensure that poll did not fail with an error.
	require_action_string(errno == 0,
		bail,
		ret = SMCP_STATUS_ERRNO,
		strerror(errno)
	);

	if(tmp > 0) {
		char packet[SMCP_MAX_PACKET_LENGTH+1];
		size_t packet_length = SMCP_MAX_PACKET_LENGTH;
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

		ret = smcp_inbound_start_packet(self, packet, packet_length);
		require(ret==SMCP_STATUS_OK,bail);

		ret = smcp_inbound_set_srcaddr((struct sockaddr*)&packet_saddr,packet_saddr_len);
		require(ret==SMCP_STATUS_OK,bail);

		// TODO: Call `smcp_inbound_set_destaddr()`, too!

		ret = smcp_inbound_finish_packet();
		require(ret==SMCP_STATUS_OK,bail);
	}
#else
	(void)cms;
#endif

	smcp_set_current_instance(self);
	smcp_handle_timers(self);

bail:
	smcp_set_current_instance(NULL);
	self->is_responding = false;
	return ret;
}

#pragma mark -
#pragma mark VHost Support

#if SMCP_CONF_ENABLE_VHOSTS
smcp_status_t
smcp_vhost_add(smcp_t self,const char* name,smcp_request_handler_func func, void* context) {
	smcp_status_t ret = SMCP_STATUS_OK;
	struct smcp_vhost_s *vhost;
	SMCP_EMBEDDED_SELF_HOOK;

	DEBUG_PRINTF("Adding VHost \"%s\": handler:%p context:%p",name,func,context);

	require_action(name && (name[0]!=0),bail,ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(self->vhost_count<SMCP_MAX_VHOSTS,bail,ret = SMCP_STATUS_FAILURE);

	vhost = &self->vhost[self->vhost_count++];

	strncpy(vhost->name,name,sizeof(vhost->name)-1);
	vhost->func = func;
	vhost->context = context;

bail:
	return ret;
}

smcp_status_t
smcp_vhost_route(smcp_request_handler_func* func, void** context) {
	smcp_t const self = smcp_get_current_instance();
	coap_option_key_t key;

	if(self->vhost_count) {
		const uint8_t* value;
		size_t value_len = 0;

		smcp_inbound_reset_next_option();

		while((key = smcp_inbound_next_option(&value,&value_len))!=COAP_OPTION_INVALID) {
			if(key >= COAP_OPTION_URI_HOST)
				break;
		}

		if(value_len>(sizeof(self->vhost[0].name)-1))
			return SMCP_STATUS_INVALID_ARGUMENT;

		if(key == COAP_OPTION_URI_HOST) {
			int i;
			for(i=0;i<self->vhost_count;i++) {
				if(strncmp(self->vhost[i].name,(const char*)value,value_len) && self->vhost[i].name[value_len]==0) {
					*func = self->vhost[i].func;
					*context = self->vhost[i].context;
					break;
				}
			}
		}
	}

	return SMCP_STATUS_OK;
}

#endif

#pragma mark -
#pragma mark Asynchronous Response Support

smcp_status_t
smcp_outbound_set_async_response(struct smcp_async_response_s* x) {
	smcp_status_t ret = 0;
	smcp_t const self = smcp_get_current_instance();
	self->inbound.packet = &x->request.header;
	self->inbound.packet_len = x->request_len;
	self->inbound.content_ptr = (char*)x->request.header.token + x->request.header.token_len;
	self->inbound.last_option_key = 0;
	self->inbound.this_option = x->request.header.token;
	self->outbound.packet->tt = x->request.header.tt;
	self->inbound.is_fake = true;
	self->is_processing_message = true;
	self->did_respond = false;

	ret = smcp_outbound_set_token(x->request.header.token, x->request.header.token_len);
	require_noerr(ret, bail);

#if SMCP_USE_BSD_SOCKETS
	ret = smcp_outbound_set_destaddr((void*)&x->saddr,x->socklen);
#elif CONTIKI
	ret = smcp_outbound_set_destaddr(&x->toaddr,x->toport);
#endif

	require_noerr(ret, bail);

	assert(coap_verify_packet((const char*)x->request.bytes, x->request_len));
bail:
	return ret;
}

smcp_status_t
smcp_start_async_response(struct smcp_async_response_s* x,int flags) {
	smcp_status_t ret = 0;
	smcp_t const self = smcp_get_current_instance();

	require_action_string(x!=NULL,bail,ret=SMCP_STATUS_INVALID_ARGUMENT,"NULL async_response arg");

	require_action_string(
		smcp_inbound_get_packet_length()-smcp_inbound_get_content_len()<=sizeof(x->request),
		bail,
		(smcp_outbound_quick_response(COAP_RESULT_413_REQUEST_ENTITY_TOO_LARGE,NULL),ret=SMCP_STATUS_FAILURE),
		"Request too big for async response"
	);

	x->request_len = smcp_inbound_get_packet_length()-smcp_inbound_get_content_len();
	memcpy(x->request.bytes,smcp_inbound_get_packet(),x->request_len);

	assert(coap_verify_packet((const char*)x->request.bytes, x->request_len));

#if SMCP_USE_BSD_SOCKETS
	x->socklen = self->inbound.socklen;
	memcpy(&x->saddr,self->inbound.saddr,sizeof(x->saddr));
#elif CONTIKI
	memcpy(&x->toaddr,&self->inbound.toaddr,sizeof(x->toaddr));
	x->toport = self->inbound.toport;
#endif

	if(	!(flags & SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK)
		&& self->inbound.packet->tt==COAP_TRANS_TYPE_CONFIRMABLE
	) {
		// Fake inbound packets are created to tickle
		// content out of nodes by the pairing system.
		// Since we are asynchronous, this clearly isn't
		// going to work. Support for this will have to
		// come in the future.
		require_action(!self->inbound.is_fake,bail,ret = SMCP_STATUS_NOT_IMPLEMENTED);

		ret = smcp_outbound_begin_response(COAP_CODE_EMPTY);
		require_noerr(ret, bail);

		ret = smcp_outbound_send();
		require_noerr(ret, bail);
	}

	if(self->inbound.is_dupe) {
		ret = SMCP_STATUS_DUPE;
		goto bail;
	}

bail:
	return ret;
}

smcp_status_t
smcp_finish_async_response(struct smcp_async_response_s* x) {
	// This method is largely a hook for future functionality.
	// It doesn't really do much at the moment, but it may later.
	x->request_len = 0;
	return SMCP_STATUS_OK;
}

bool
smcp_inbound_is_related_to_async_response(struct smcp_async_response_s* x)
{
	smcp_t const self = smcp_get_current_instance();
#if SMCP_USE_BSD_SOCKETS
	return (x->socklen == self->inbound.socklen)
		&& (0==memcmp(&x->saddr,self->inbound.saddr,sizeof(x->saddr)));
#elif CONTIKI
	return (x->toport == self->inbound.toport)
		&& (0==memcmp(&x->toaddr,&self->inbound.toaddr,sizeof(x->toaddr)));
#endif
}

#pragma mark -
#pragma mark Other

coap_msg_id_t
smcp_get_next_msg_id(smcp_t self) {
	static coap_msg_id_t next_msg_id;

	if(!next_msg_id)
		next_msg_id = SMCP_FUNC_RANDOM_UINT32();

#if DEBUG
	next_msg_id++;
#else
	next_msg_id = next_msg_id*23873 + 41;
#endif

	return next_msg_id;
}

#if !SMCP_EMBEDDED || DEBUG
const char* smcp_status_to_cstr(int x) {
	switch(x) {
	case SMCP_STATUS_OK: return "OK"; break;
	case SMCP_STATUS_HOST_LOOKUP_FAILURE: return "Hostname Lookup Failure";
		break;
	case SMCP_STATUS_FAILURE: return "Unspecified Failure"; break;
	case SMCP_STATUS_INVALID_ARGUMENT: return "Invalid Argument"; break;
	case SMCP_STATUS_UNSUPPORTED_URI: return "Unsupported URI"; break;
	case SMCP_STATUS_MALLOC_FAILURE: return "Malloc Failure"; break;
	case SMCP_STATUS_TRANSACTION_INVALIDATED: return "Handler Invalidated";
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

	case SMCP_STATUS_NOT_ALLOWED: return "Not Allowed"; break;

	case SMCP_STATUS_BAD_OPTION: return "Bad Option"; break;
	case SMCP_STATUS_DUPE: return "Duplicate"; break;

	case SMCP_STATUS_RESET: return "Transaction Reset"; break;
	case SMCP_STATUS_URI_PARSE_FAILURE: return "URI Parse Failure"; break;

	case SMCP_STATUS_ERRNO:
#if SMCP_USE_BSD_SOCKETS
		return strerror(errno); break;
#else
		return "ERRNO!?"; break;
#endif
	default:
		{
			static char cstr[30];
			sprintf(cstr, "Unknown Status (%d)", x);
			return cstr;
		}
		break;
	}
	return NULL;
}
#endif

int smcp_convert_status_to_result_code(smcp_status_t status) {
	int ret = COAP_RESULT_500_INTERNAL_SERVER_ERROR;

	switch(status) {
	case SMCP_STATUS_OK:
		ret = COAP_RESULT_200;
		break;
	case SMCP_STATUS_NOT_FOUND:
		ret = COAP_RESULT_404_NOT_FOUND;
		break;
	case SMCP_STATUS_NOT_IMPLEMENTED:
		ret = COAP_RESULT_501_NOT_IMPLEMENTED;
		break;
	case SMCP_STATUS_NOT_ALLOWED:
		ret = COAP_RESULT_405_METHOD_NOT_ALLOWED;
		break;
	case SMCP_STATUS_UNSUPPORTED_URI:
		ret = COAP_RESULT_400_BAD_REQUEST;
		break;
	case SMCP_STATUS_BAD_OPTION:
		ret = COAP_RESULT_402_BAD_OPTION;
		break;
	case SMCP_STATUS_MALLOC_FAILURE:
		ret = COAP_RESULT_503_SERVICE_UNAVAILABLE;
		break;
	}

	return ret;
}

