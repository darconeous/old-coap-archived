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

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert_macros.h"

#if CONTIKI
#include "contiki.h"
#include "net/uip-udp-packet.h"
#include "net/uiplib.h"
#include "net/tcpip.h"
#include "net/resolv.h"
extern uint16_t uip_slen;
#endif

#include <stdarg.h>

#include "smcp.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ll.h"

#include "url-helpers.h"
#include "smcp-node.h"
#include "smcp-logging.h"

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
#pragma mark SMCP Globals

#if SMCP_NO_MALLOC
static struct smcp_transaction_s smcp_transaction_pool[SMCP_CONF_MAX_TRANSACTIONS];
#endif // SMCP_NO_MALLOC

#pragma mark -
#pragma mark SMCP Implementation

#if !SMCP_NO_MALLOC && !SMCP_EMBEDDED
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
	smcp_t ret, uint16_t port
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

	// Set up the UDP port for listening.
#if SMCP_USE_BSD_SOCKETS
	uint16_t attempts = 0x7FFF;
	ret->fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	require_action_string(ret->fd > 0, bail, { smcp_release(
				ret); ret = NULL; }, "Failed to create socket");

	// Keep attempting to bind until we find a port that works.
	while(bind(ret->fd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
		// We should only continue trying if errno == EADDRINUSE.
		require_action_string(errno == EADDRINUSE, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_release(
				    ret); ret = NULL; }, "Failed to bind socket");
		port++;

		// Make sure we aren't in an infinite loop.
		require_action_string(--attempts, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_release(
				    ret); ret = NULL; }, "Failed to bind socket (ran out of ports)");

		saddr.sin6_port = htons(port);
	}
#elif CONTIKI
	ret->udp_conn = udp_new(NULL, 0, NULL);
	uip_udp_bind(ret->udp_conn, htons(port));
	ret->udp_conn->rport = 0;
#endif

	// Go ahead and start listening on our multicast address as well.
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
	require_string(
		smcp_node_init(&ret->root_node,NULL,NULL) != NULL,
		bail,
		"Unable to initialize root node"
	);

bail:
	return ret;
}

void
smcp_release(smcp_t self) {
	require(self, bail);

	// Delete all pending transactions
	while(self->transactions) {
		smcp_invalidate_transaction(self, self->transactions->tid);
	}

	// Delete all timers
	while(self->timers) {
		smcp_timer_t timer = self->timers;
		if(timer->cancel)
			timer->cancel(self, timer->context);
		smcp_invalidate_timer(self, timer);
	}

	// Delete all nodes
	smcp_node_delete(smcp_get_root_node(self));

#if SMCP_USE_BSD_SOCKETS
	close(self->fd);
	close(self->mcfd);
#elif CONTIKI
	if(self->udp_conn)
		uip_udp_remove(self->udp_conn);
#endif

#if !SMCP_NO_MALLOC && !SMCP_EMBEDDED
	// TODO: Make sure we were actually alloc'd!
	free(self);
#endif

bail:
	return;
}

uint16_t
smcp_get_port(smcp_t self) {
#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr;
	socklen_t socklen = sizeof(saddr);
	getsockname(self->fd, (struct sockaddr*)&saddr, &socklen);
	return ntohs(saddr.sin6_port);
#elif CONTIKI
	return ntohs(self->udp_conn->lport);
#endif
}

#if SMCP_USE_BSD_SOCKETS
int
smcp_get_fd(smcp_t self) {
	return self->fd;
}
#elif defined(CONTIKI)
struct uip_udp_conn*
smcp_get_udp_conn(smcp_t self) {
	return self->udp_conn;
}
#endif

void
smcp_set_proxy_url(smcp_t self,const char* url) {
	free(self->proxy_url);
	if(url)
		self->proxy_url = strdup(url);
	else
		self->proxy_url = NULL;
	DEBUG_PRINTF("CoAP Proxy URL set to %s",self->proxy_url);
}

#if !SMCP_EMBEDDED
smcp_node_t
smcp_get_root_node(smcp_t self) {
	return &self->root_node;
}
#endif

#pragma mark -
#pragma mark Inbound packet parsing functions

void
smcp_inbound_reset_next_option() {
	smcp_t const self = smcp_get_current_instance();
	self->inbound.last_option_key = 0;
	self->inbound.options_left = self->inbound.packet->option_count;
	self->inbound.this_option = self->inbound.packet->options;
}

static coap_option_key_t
smcp_inbound_next_option_(const uint8_t** value, size_t* len) {
	smcp_t const self = smcp_get_current_instance();
	if(self->inbound.options_left) {
		self->inbound.this_option = coap_decode_option(
			self->inbound.this_option,
			&self->inbound.last_option_key,
			value,
			len
		);

		// TODO: Handle when this options are unlimited;
		self->inbound.options_left--;
	} else {
		self->inbound.last_option_key = COAP_HEADER_INVALID;
	}
	return self->inbound.last_option_key;
}

coap_option_key_t
smcp_inbound_next_option(const uint8_t** value, size_t* len) {
	coap_option_key_t ret;
	do {
		ret = smcp_inbound_next_option_(value, len);
	} while(ret==COAP_HEADER_TOKEN); // Skip tokens
	return ret;
}

coap_option_key_t
smcp_inbound_peek_option(const uint8_t** value, size_t* len) {
	smcp_t const self = smcp_get_current_instance();
	coap_option_key_t ret = self->inbound.last_option_key;
	if(self->inbound.last_option_key!=COAP_HEADER_INVALID && self->inbound.options_left) {
		coap_decode_option(
			self->inbound.this_option,
			&ret,
			value,
			len
		);

	} else {
		ret = COAP_HEADER_INVALID;
	}
	return ret;
}

bool
smcp_inbound_option_strequal(coap_option_key_t key,const char* cstr) {
	smcp_t const self = smcp_get_current_instance();
	coap_option_key_t curr_key = self->inbound.last_option_key;
	const char* value;
	size_t value_len;
	size_t i;

	if(!self->inbound.this_option)
		return false;

	coap_decode_option(self->inbound.this_option, &curr_key, (const uint8_t**)&value, &value_len);

	if(curr_key != key)
		return false;

	for(i=0;i<value_len;i++) {
		if(!cstr[i] || (value[i]!=cstr[i]))
			return false;
	}
	return cstr[i]==0;
}

const struct coap_header_s*
smcp_inbound_get_packet() {
	return smcp_get_current_instance()->inbound.packet;
}

const char*
smcp_inbound_get_content_ptr() {
	return smcp_get_current_instance()->inbound.content_ptr;
}

size_t
smcp_inbound_get_content_len() {
	return smcp_get_current_instance()->inbound.content_len;
}

coap_content_type_t
smcp_inbound_get_content_type() {
	return smcp_get_current_instance()->inbound.content_type;
}


#if SMCP_USE_BSD_SOCKETS
struct sockaddr* smcp_inbound_get_saddr() {
	return smcp_get_current_instance()->inbound.saddr;
}

socklen_t smcp_inbound_get_socklen() {
	return smcp_get_current_instance()->inbound.socklen;
}
#elif defined(CONTIKI)
const uip_ipaddr_t* smcp_inbound_get_ipaddr() {
	return &smcp_get_current_instance()->inbound.toaddr;
}

const uint16_t smcp_inbound_get_ipport() {
	return smcp_get_current_instance()->inbound.toport;
}
#endif

bool
smcp_inbound_is_dupe() {
	return smcp_get_current_instance()->inbound.is_dupe;
}

#pragma mark -

smcp_status_t
smcp_handle_inbound_packet(
	smcp_t	self,
	char*			buffer,
	size_t			packet_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	struct coap_header_s* const packet = (void*)buffer; // Should not use stack space.

	smcp_set_current_instance(self);

	DEBUG_PRINTF(CSTR("%p: Inbound packet!"), self);

	// Reset all inbound packet state.
	memset(&self->inbound,0,sizeof(self->inbound));

	// We are processing a message.
	self->is_processing_message = true;
	self->did_respond = false;

	self->inbound.packet = packet;

#if SMCP_USE_BSD_SOCKETS
	self->inbound.saddr = saddr;
	self->inbound.socklen = socklen;
#elif CONTIKI
	memcpy(&self->inbound.toaddr,toaddr,sizeof(*toaddr));
	self->inbound.toport = toport;
#endif

	// TODO: Set `self->inbound.was_sent_to_multicast` properly!

	{
		// Update dupe hash.
		fasthash_start(0);
#if SMCP_USE_BSD_SOCKETS
		fasthash_feed((void*)self->inbound.saddr,self->inbound.socklen);
#elif CONTIKI
		fasthash_feed((void*)&self->inbound.toaddr,sizeof(self->inbound.toaddr));
		fasthash_feed((void*)&self->inbound.toport,sizeof(self->inbound.toport));
#endif
		fasthash_feed_byte(self->inbound.packet->code);
		fasthash_feed((const uint8_t*)&self->inbound.packet->tid,sizeof(self->inbound.packet->tid));

		self->inbound.transaction_hash = fasthash_finish_uint32();
		int i = SMCP_CONF_DUPE_BUFFER_SIZE;
		while(i--) {
			if(self->dupe[i].hash == self->inbound.transaction_hash) {
				self->inbound.is_dupe = true;
				break;
			}
		}
	}

	// Version check.
	require_action(packet->version==COAP_VERSION,bail,ret=SMCP_STATUS_FAILURE);

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	// Kind of a hack, but very convenient.
	buffer[packet_length] = 0;

	if(self->inbound.was_sent_to_multicast) {
		// If this was multicast, make sure it isn't confirmable.
		require_action(
			packet->tt!=COAP_TRANS_TYPE_CONFIRMABLE,
			bail,
			ret=SMCP_STATUS_FAILURE
		);
	}

	DEBUG_PRINTF(CSTR("%p: tt=%d"), self,packet->tt);
	DEBUG_PRINTF(CSTR("%p: http.code=%d, coap.code=%d"),self,coap_to_http_code(packet->code),packet->code);

	smcp_inbound_reset_next_option();

	{	// Initial options scan.
		coap_option_key_t key;
		do {
			const uint8_t* value;
			size_t value_len;
			key = smcp_inbound_peek_option(&value,&value_len);
			if(key==COAP_HEADER_TOKEN) {
				self->inbound.token_option = self->inbound.this_option;
			} else if(key==COAP_HEADER_CONTENT_TYPE) {
				self->inbound.content_type = self->inbound.this_option[1];
			} else if(key==COAP_HEADER_OBSERVE) {
				self->inbound.has_observe_option = 1;
			} else if(key==COAP_HEADER_MAX_AGE) {
				uint8_t i;
				self->inbound.max_age = 0;
				for(i = 0; i < value_len; i++)
					self->inbound.max_age = (self->inbound.max_age << 8) + value[i];
			}
		} while(smcp_inbound_next_option_(NULL,NULL)!=COAP_HEADER_INVALID);

		// Now that we are at the end of the options, we know
		// where the content starts.
		self->inbound.content_ptr = (char*)self->inbound.this_option;
		self->inbound.content_len = packet_length-(self->inbound.content_ptr-buffer);
	}

	smcp_inbound_reset_next_option();

#if SMCP_USE_CASCADE_COUNT
	self->cascade_count--;
#endif

	if(COAP_CODE_IS_REQUEST(packet->code)) {
		ret = smcp_handle_request(self);
	} else if(COAP_CODE_IS_RESULT(packet->code)) {
		ret = smcp_handle_response(self);
	}

	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

	if(	(ret == SMCP_STATUS_OK)
		&& !self->inbound.is_fake
		&& !self->inbound.is_dupe
		&& (self->inbound.packet->code != COAP_METHOD_GET
			|| (self->did_respond
				&& self->outbound.packet->code == COAP_CODE_EMPTY
				&& self->outbound.packet->tt == COAP_TRANS_TYPE_ACK
			)
		)
	) {
		// This is not a dupe, add it to the list.
		self->dupe[self->dupe_index].hash = self->inbound.transaction_hash;
		self->dupe_index++;
		self->dupe_index%=SMCP_CONF_DUPE_BUFFER_SIZE;
	}

	// Check to make sure we have responded by now. If not, we need to.
	if(!self->did_respond && (packet->tt==COAP_TRANS_TYPE_CONFIRMABLE)) {
		if(COAP_CODE_IS_REQUEST(packet->code)) {
			int result_code = smcp_convert_status_to_result_code(ret);
			if(self->inbound.is_dupe)
				ret = 0;
			if(ret == SMCP_STATUS_OK) {
				if(packet->code==COAP_METHOD_GET)
					result_code = COAP_RESULT_205_CONTENT;
				else if(packet->code==COAP_METHOD_POST || packet->code==COAP_METHOD_PUT)
					result_code = COAP_RESULT_204_CHANGED;
				else if(packet->code==COAP_METHOD_DELETE)
					result_code = COAP_RESULT_202_DELETED;
			}
			smcp_outbound_begin_response(result_code);
		} else {
			smcp_outbound_begin_response(0);
			if(ret && !self->inbound.is_dupe)
				self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			else
				self->outbound.packet->tt = COAP_TRANS_TYPE_ACK;
		}
		ret = smcp_outbound_send();
	}

bail:
	smcp_set_current_instance(NULL);
	self->is_processing_message = false;
	self->force_current_outbound_code = false;
	self->inbound.content_ptr = NULL;
	self->inbound.content_len = 0;
	return ret;
}

smcp_status_t
smcp_process(
	smcp_t self, cms_t cms
) {
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

		ret = smcp_handle_inbound_packet(
			self,
			packet,
			packet_length,
			(struct sockaddr*)&packet_saddr,
			packet_saddr_len
		);
	}
#endif

	smcp_set_current_instance(self);
	smcp_handle_timers(self);

bail:
	smcp_set_current_instance(NULL);
	self->is_responding = false;
	return ret;
}


#pragma mark -
#pragma mark Transaction Support

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

void
smcp_internal_delete_transaction_(
	smcp_transaction_t handler,
	smcp_t			self
) {
	DEBUG_PRINTF(CSTR(
			"%p: Deleting response handler w/tid=%d"), self, handler->tid);

	if(!smcp_get_current_instance())
		smcp_set_current_instance(self);

	check(self==smcp_get_current_instance());

	// Remove the timer associated with this handler.
	smcp_invalidate_timer(self, &handler->timer);

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		(*handler->callback)(
			SMCP_STATUS_TRANSACTION_INVALIDATED,
			handler->context
		);
	}

#if SMCP_NO_MALLOC
	handler->callback = NULL;
#else
	free(handler);
#endif
}

static int smcp_rtt = COAP_RESPONSE_TIMEOUT;

static int
calc_retransmit_timeout(int retries_) {
	int ret = smcp_rtt;

	ret = (ret<<retries_);

	ret *= (1000 - 150) + (SMCP_FUNC_RANDOM_UINT32() % 300);

	ret /= 1000;

	if(ret > 5000)
		ret = 5000;

	return ret;
}

void
smcp_internal_transaction_timeout_(
	smcp_t			self,
	smcp_transaction_t handler
) {
	smcp_status_t status = SMCP_STATUS_TIMEOUT;
	smcp_response_handler_func callback = handler->callback;
	void* context = handler->context;

	self->current_transaction = handler;

	if((convert_timeval_to_cms(&handler->expiration) > 0)) {
		if(handler->waiting_for_async_response && !(handler->flags&SMCP_TRANSACTION_OBSERVE)) {
			status = SMCP_STATUS_OK;
			smcp_schedule_timer(
				self,
				&handler->timer,
				convert_timeval_to_cms(&handler->expiration)
			);
		} else if(handler->resendCallback) {
			// Resend.
			self->outbound.next_tid = handler->tid;
			self->is_processing_message = false;
			self->is_responding = false;
			self->did_respond = false;

			status = handler->resendCallback(context);

			if(status == SMCP_STATUS_WAIT_FOR_DNS) {
				smcp_schedule_timer(
					self,
					&handler->timer,
					100
				);
			} else if(status == SMCP_STATUS_OK) {
				smcp_schedule_timer(
					self,
					&handler->timer,
					calc_retransmit_timeout(handler->attemptCount++)
				);
			}
		}
	}

	if(status) {
		if(handler->flags&SMCP_TRANSACTION_OBSERVE) {
			// If we are an observing transaction, we need to clean up
			// first. TODO: Implement this!
		}
		if(callback) {
			handler->callback = NULL;
			smcp_invalidate_transaction(self, handler->tid);
			(*callback)(
				status,
				context
			);
		} else {
			smcp_invalidate_transaction(self, handler->tid);
		}
	}

	self->current_transaction = NULL;
}

smcp_status_t
smcp_begin_transaction(
	smcp_t				self,
	coap_transaction_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_inbound_resend_func resendCallback,
	smcp_response_handler_func	callback,
	void*						context
) {
	smcp_status_t ret = 0;
	smcp_transaction_t handler;

	require_action(callback != NULL,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT);

#if SMCP_NO_MALLOC
	{
		uint8_t i;
		for(i=0;i<SMCP_CONF_MAX_TRANSACTIONS;i++) {
			handler = &smcp_transaction_pool[i];
			if(handler->callback) {
				handler = NULL;
				continue;
			}
		}
	}
#else
	handler = (smcp_transaction_t)calloc(sizeof(*handler), 1);
#endif

	require_action(handler, bail, ret = SMCP_STATUS_MALLOC_FAILURE);

	DEBUG_PRINTF(CSTR("%p: Adding response handler w/tid=%d"), self, tid);

	handler->tid = tid;
	handler->resendCallback = resendCallback;
	handler->callback = callback;
	handler->context = context;
	handler->flags = flags;
	handler->waiting_for_async_response = false;
	convert_cms_to_timeval(&handler->expiration, cmsExpiration);
	handler->attemptCount = 0;

	if(resendCallback) {
		// In this case we will be reattempting for a given duration.
		// The first attempt should happen pretty much immediately.
		cmsExpiration = 0;

		if(flags&SMCP_TRANSACTION_DELAY_START) {
			// Unless this flag is set. Then we need to wait a moment.
			cmsExpiration = 10 + (SMCP_FUNC_RANDOM_UINT32() % 290);
		}
	}

	smcp_schedule_timer(
		self,
		smcp_timer_init(
			&handler->timer,
			(smcp_timer_callback_t)&smcp_internal_transaction_timeout_,
			NULL,
			handler
		),
		cmsExpiration
	);

	bt_insert(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)smcp_internal_delete_transaction_,
		self
	);

	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)bt_count((void**)&self->transactions));

bail:
	return ret;
}

smcp_status_t
smcp_invalidate_transaction(
	smcp_t			self,
	coap_transaction_id_t	tid
) {
	bt_remove(
		    (void**)&self->transactions,
		    (void*)&tid,
		    (bt_compare_func_t)smcp_transaction_compare_tid,
		    (bt_delete_func_t)smcp_internal_delete_transaction_,
		self
	);
	return 0;
}

#pragma mark -
#pragma mark Request/Response Handlers

smcp_status_t
smcp_default_request_handler(
   smcp_node_t node,
   smcp_method_t method
) {
   if(method == COAP_METHOD_GET) {
	   return smcp_handle_list(node,method);
   }
   return SMCP_STATUS_NOT_ALLOWED;
}

smcp_status_t
smcp_handle_request(
	smcp_t	self
) {
	smcp_status_t ret = 0;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(
			"smcp(%p): Incoming request!",
			self
		);
		coap_dump_header(
			SMCP_DEBUG_OUT_FILE,
			"    ",
			self->inbound.packet,
			0
		);
	}
#endif

	smcp_node_t node = smcp_get_root_node(self);
	smcp_inbound_handler_func request_handler = &smcp_default_request_handler;

	// TODO: Add authentication here!

	{
		const uint8_t* prev_option_ptr = self->inbound.this_option;
		coap_option_key_t prev_key = 0;
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		while((key=smcp_inbound_next_option_(&value, &value_len))!=COAP_HEADER_INVALID) {
			if(key>COAP_HEADER_URI_PATH) {
				self->inbound.this_option = prev_option_ptr;
				self->inbound.last_option_key = prev_key;
				self->inbound.options_left++;
				break;
			} else if(key==COAP_HEADER_PROXY_URI) {
				// Skip the proxy URI for now.
			} else if(key==COAP_HEADER_URI_PATH) {
				smcp_node_t next = smcp_node_find(
					node,
					(const char*)value,
					value_len
				);
				if(next) {
					node = next;
				} else {
					self->inbound.this_option = prev_option_ptr;
					self->inbound.last_option_key = prev_key;
					self->inbound.options_left++;
					break;
				}
			} else if(key==COAP_HEADER_URI_HOST) {
				// Skip host at the moment,
				// because we don't do virtual hosting yet.
			} else if(key==COAP_HEADER_URI_PORT) {
				// Skip port at the moment,
				// because we don't do virtual hosting yet.
			} else if(key==COAP_HEADER_CONTENT_TYPE) {
				// Skip the content type for now,
				// but we will need to keep track of this later.
			} else {
				if(COAP_HEADER_IS_REQUIRED(key)) {
					ret=SMCP_STATUS_BAD_OPTION;
					assert_printf("Unrecognized option %d, \"%s\"",
						key,
						coap_option_key_to_cstr(key, false)
					);
					goto bail;
				}
			}
			prev_option_ptr = self->inbound.this_option;
			prev_key = self->inbound.last_option_key;
		}
	}

	if(node->request_handler)
		request_handler = node->request_handler;

	// By returning directly here we can
	// possibly avoid having the overhead of
	// the current function on the stack.
	return (*request_handler)(
	    node,
	    self->inbound.packet->code
	);

bail:
	return ret;
}

smcp_status_t
smcp_handle_response(
	smcp_t	self
) {
	smcp_status_t ret = 0;
	smcp_transaction_t handler = NULL;
	coap_transaction_id_t tid;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(
			"smcp(%p): Incoming response! tid=%d",
			self,
			smcp_inbound_get_tid()
		);
		coap_dump_header(
			SMCP_DEBUG_OUT_FILE,
			"    ",
			self->inbound.packet,
			0
		);
	}
#endif

	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)bt_count((void**)&self->transactions));

	tid = smcp_inbound_get_tid();

	handler = (smcp_transaction_t)bt_find(
		(void**)&self->transactions,
		(void*)&tid,
		(bt_compare_func_t)smcp_transaction_compare_tid,
		self
	);

	if(!handler && self->inbound.token_option) {
		coap_transaction_id_t tid;
		memcpy(&tid,self->inbound.token_option+1,sizeof(tid));
		handler = (smcp_transaction_t)bt_find(
			(void**)&self->transactions,
			(void*)&tid,
			(bt_compare_func_t)smcp_transaction_compare_tid,
			self
		);
		if(handler && !handler->waiting_for_async_response)
			handler = NULL;
	}

	// TODO: Make sure this packet didn't originate from multicast.

	if(!handler) {
		if(self->inbound.packet->tt <= COAP_TRANS_TYPE_NONCONFIRMABLE) {
			// We don't know what they are talking
			// about, so send them a reset so that they
			// will shut up.

			ret = smcp_outbound_begin_response(0);
			require_noerr(ret,bail);

			self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;

			ret = smcp_outbound_send();
			require_noerr(ret,bail);
		}
	} else if(	(	self->inbound.packet->tt == COAP_TRANS_TYPE_ACK
			|| self->inbound.packet->tt == COAP_TRANS_TYPE_NONCONFIRMABLE
		)
		&& !self->inbound.packet->code
	) {
		DEBUG_PRINTF("Inbound: Async Response");
		handler->waiting_for_async_response = true;
	} else if(handler->callback) {
		if(handler->flags & SMCP_TRANSACTION_OBSERVE) {
			(*handler->callback)(
				self->inbound.packet->tt==COAP_TRANS_TYPE_RESET?SMCP_STATUS_RESET:self->inbound.packet->code,
				handler->context
			);

			if(self->inbound.has_observe_option) {
				handler->waiting_for_async_response = true;
			}

			handler->attemptCount = 0;
			handler->timer.cancel = NULL;

			smcp_invalidate_timer(self, &handler->timer);
			cms_t cms = convert_timeval_to_cms(&handler->expiration);
			cms_t max_age = 0; // TODO: Calculate this from max-age

			if(!max_age) {
				if(self->inbound.has_observe_option)
					max_age = CMS_DISTANT_FUTURE;
				else
					max_age = SMCP_OBSERVATION_DEFAULT_MAX_AGE;
			}

			if(cms>max_age)
				cms = max_age;

			if(	(handler->flags&SMCP_TRANSACTION_KEEPALIVE)
				&& cms>SMCP_OBSERVATION_KEEPALIVE_INTERVAL
			) {
				cms = SMCP_OBSERVATION_KEEPALIVE_INTERVAL;
			}

			smcp_schedule_timer(
				self,
				smcp_timer_init(
					&handler->timer,
					(smcp_timer_callback_t)&smcp_internal_transaction_timeout_,
					NULL,
					handler
				),
				cms
			);
		} else {
			if(handler->flags & SMCP_TRANSACTION_ALWAYS_TIMEOUT) {
				if(!(handler->flags & SMCP_TRANSACTION_OBSERVE)) {
					handler->resendCallback = NULL;
				}
				(*handler->callback)(
					self->inbound.packet->tt==COAP_TRANS_TYPE_RESET?SMCP_STATUS_RESET:self->inbound.packet->code,
					handler->context
				);
			} else {
				smcp_response_handler_func callback = handler->callback;
				handler->resendCallback = NULL;
				handler->callback = NULL;
				(*callback)(
					self->inbound.packet->tt==COAP_TRANS_TYPE_RESET?SMCP_STATUS_RESET:self->inbound.packet->code,
					handler->context
				);
			}
			smcp_invalidate_transaction(self, tid);
		}
	}

bail:
	return ret;
}

#pragma mark -
#pragma mark Asynchronous Response Support

smcp_status_t
smcp_outbound_set_async_response(struct smcp_async_response_s* x) {
	smcp_status_t ret = 0;
	smcp_t const self = smcp_get_current_instance();
	self->outbound.packet->tt = x->tt;

#if SMCP_USE_BSD_SOCKETS
	ret = smcp_outbound_set_destaddr((void*)&x->saddr,x->socklen);
#elif CONTIKI
	ret = smcp_outbound_set_destaddr(&x->toaddr,x->toport);
#endif

	require_noerr(ret, bail);

	ret = smcp_outbound_add_option(COAP_HEADER_TOKEN, (const char*)x->token_value, x->token_len);
	require_noerr(ret, bail);
bail:
	return ret;
}

smcp_status_t
smcp_start_async_response(struct smcp_async_response_s* x,int flags) {
	smcp_status_t ret = 0;
	smcp_t const self = smcp_get_current_instance();

	require_action_string(x!=NULL,bail,ret=SMCP_STATUS_INVALID_ARGUMENT,"NULL async_response arg");

	if(!(flags & SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK)) {
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

	x->original_tid = self->inbound.packet->tid;
	x->tt = self->inbound.packet->tt;

	if(self->inbound.token_option) {
		x->token_len = self->inbound.token_option[0] & 0x0F;
		memcpy(x->token_value,self->inbound.token_option+1,x->token_len);
	} else {
		x->token_len = 0;
	}

#if SMCP_USE_BSD_SOCKETS
	x->socklen = self->inbound.socklen;
	memcpy(&x->saddr,self->inbound.saddr,sizeof(x->saddr));
#elif CONTIKI
	memcpy(&x->toaddr,&self->inbound.toaddr,sizeof(x->toaddr));
	x->toport = self->inbound.toport;
#endif

bail:
	return ret;
}

smcp_status_t
smcp_finish_async_response(struct smcp_async_response_s* x) {
	// This method is largely a hook for future functionality.
	// It doesn't really do much at the moment, but it may later.

	return SMCP_STATUS_OK;
}

#pragma mark -
#pragma mark Other

coap_transaction_id_t
smcp_get_next_tid(smcp_t self, void* context) {
	static uint16_t table[16];
	uint8_t hash;

	fasthash_start(0x31337);
	fasthash_feed((uint8_t*)&context, sizeof(void*));
	hash = fasthash_finish_uint8();

	if(!table[hash])
		table[hash] = (uint16_t)SMCP_FUNC_RANDOM_UINT32();

	table[hash] = table[hash]*23873+41;

	return table[hash];
}

const char* smcp_status_to_cstr(int x) {
	switch(x) {
	case SMCP_STATUS_OK: return "OK"; break;
	case SMCP_STATUS_HOST_LOOKUP_FAILURE: return "Hostname Lookup Failure";
		break;
	case SMCP_STATUS_FAILURE: return "Unspecified Failure"; break;
	case SMCP_STATUS_INVALID_ARGUMENT: return "Invalid Argument"; break;
	case SMCP_STATUS_BAD_NODE_TYPE: return "Bad Node Type"; break;
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
	case SMCP_STATUS_BAD_NODE_TYPE:
	case SMCP_STATUS_UNSUPPORTED_URI:
		ret = COAP_RESULT_400_BAD_REQUEST;
		break;
	case SMCP_STATUS_BAD_OPTION:
		ret = COAP_RESULT_402_BAD_OPTION;
		break;
	}

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
#pragma mark -
#pragma mark Fasthash

static struct {
	uint32_t hash;
	uint32_t bytes;
	uint32_t next;
} global_fasthash_state;

static void
fasthash_feed_block(uint32_t blk) {
	blk ^= (global_fasthash_state.bytes>>2);
	global_fasthash_state.hash ^= blk;
	global_fasthash_state.hash = global_fasthash_state.hash*1664525 + 1013904223;
}

void
fasthash_start(uint32_t salt) {
	bzero((void*)&global_fasthash_state,sizeof(global_fasthash_state));
	fasthash_feed_block(salt);
}

void
fasthash_feed_byte(uint8_t data) {
	global_fasthash_state.next |= (data<<(8*(global_fasthash_state.bytes++&3)));
	if((global_fasthash_state.bytes&3)==0) {
		fasthash_feed_block(global_fasthash_state.next);
		global_fasthash_state.next = 0;
	}
}

void
fasthash_feed(const uint8_t* data, uint8_t len) {
	while(len--)
		fasthash_feed_byte(*data++);
}

uint32_t
fasthash_finish_uint32() {
	if(global_fasthash_state.bytes&3) {
		fasthash_feed_block(global_fasthash_state.next);
		global_fasthash_state.bytes = 0;
	}
	return global_fasthash_state.hash;
}

uint16_t
fasthash_finish_uint16() {
	return global_fasthash_state.hash>>16;
}

uint8_t
fasthash_finish_uint8() {
	return global_fasthash_state.hash>>24;
}
