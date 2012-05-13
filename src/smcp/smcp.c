/*	Simple Home Automation Protocol (SMCP)
**	Stack Implementation
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
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
extern u16_t uip_slen;
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
#else
// TODO: Make thread safe!
static smcp_daemon_t smcp_daemon_current_instance;

smcp_daemon_t
smcp_get_current_daemon() {
	return smcp_daemon_current_instance;
}

void
smcp_set_current_daemon(smcp_daemon_t x) {
	smcp_daemon_current_instance = (x);
}
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

	case SMCP_STATUS_BAD_OPTION: return "Bad Option"; break;

	case SMCP_STATUS_ERRNO:
#if SMCP_USE_BSD_SOCKETS
		return strerror(errno); break;
#else
		return "ERRNO"; break;
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
	smcp_method_t	method
);

smcp_status_t smcp_invalidate_transaction(
	smcp_daemon_t self,
	coap_transaction_id_t tid
);

smcp_status_t smcp_daemon_handle_request(smcp_daemon_t	self);

smcp_status_t smcp_daemon_handle_response(smcp_daemon_t	self);

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
	uint16_t attempts = 0x7FFF;
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

	// Keep attempting to bind until we find a port that works.
	while(bind(ret->fd, (struct sockaddr*)&saddr, sizeof(saddr)) != 0) {
		// We should only continue trying if errno == EADDRINUSE.
		require_action_string(errno == EADDRINUSE, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_daemon_release(
				    ret); ret = NULL; }, "Failed to bind socket");
		port++;

		// Make sure we aren't in an infinite loop.
		require_action_string(--attempts, bail,
			{ DEBUG_PRINTF(CSTR("errno=%d"), errno); smcp_daemon_release(
				    ret); ret = NULL; }, "Failed to bind socket (ran out of ports)");

		saddr.sin6_port = htons(port);
	}
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

	// Delete all pending transactions
	while(self->transactions) {
		smcp_invalidate_transaction(self, self->transactions->tid);
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
smcp_daemon_get_fd(smcp_daemon_t self) {
	return self->fd;
}
#elif defined(CONTIKI)
struct uip_udp_conn*
smcp_daemon_get_udp_conn(smcp_daemon_t self) {
	return self->udp_conn;
}
#endif

void
smcp_daemon_set_proxy_url(smcp_daemon_t self,const char* url) {
	DEBUG_PRINTF("CoAP Proxy URL set to %s",url);
	self->proxy_url = url;
}

void
smcp_current_request_reset_next_header() {
	smcp_daemon_t self = smcp_get_current_daemon();
	self->inbound.last_option_key = 0;
	self->inbound.options_left = self->inbound.packet->option_count;
	self->inbound.this_option = self->inbound.packet->options;
}

static coap_option_key_t
smcp_current_request_next_header_(const uint8_t** value, size_t* len) {
	smcp_daemon_t self = smcp_get_current_daemon();
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
smcp_current_request_next_header(const uint8_t** value, size_t* len) {
	coap_option_key_t ret;
	do {
		ret = smcp_current_request_next_header_(value, len);
	} while(ret==COAP_HEADER_TOKEN); // Skip tokens
	return ret;
}

coap_option_key_t
smcp_current_request_peek_header(const uint8_t** value, size_t* len) {
	smcp_daemon_t self = smcp_get_current_daemon();
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

/*
void
smcp_current_request_rewind_last_header() {
#warning TODO: Update to new direct-parsing mechanism.
	// TODO: Update to new format
	if( smcp_get_current_daemon()->current_option
		&& smcp_get_current_daemon()->current_option != smcp_get_current_daemon()->inbound.options
	)
		smcp_get_current_daemon()->current_option--;
}
*/

bool
smcp_current_request_header_strequal(coap_option_key_t key,const char* cstr) {
	smcp_daemon_t self = smcp_get_current_daemon();
	coap_option_key_t curr_key = self->inbound.last_option_key;
	const uint8_t* next;
	const char* value;
	size_t value_len;

	if(!self->inbound.this_option)
		return false;

	next = coap_decode_option(self->inbound.this_option, &curr_key, (const uint8_t**)&value, &value_len);

	if(curr_key != key)
		return false;

	size_t i;
	for(i=0;i<value_len;i++) {
		if(!cstr[i] || (value[i]!=cstr[i]))
			return false;
	}
	return cstr[i]==0;
}

const struct coap_header_s*
smcp_current_request_get_packet() {
	return smcp_get_current_daemon()->inbound.packet;
}

coap_transaction_id_t
smcp_daemon_get_current_tid() {
	assert(smcp_get_current_daemon()->inbound.packet);
	return smcp_get_current_daemon()->inbound.packet->tid;
}

const char*
smcp_daemon_get_current_inbound_content_ptr() {
	return smcp_get_current_daemon()->inbound.content_ptr;
}

size_t
smcp_daemon_get_current_inbound_content_len() {
	return smcp_get_current_daemon()->inbound.content_len;
}

coap_content_type_t
smcp_daemon_get_current_inbound_content_type() {
	return smcp_get_current_daemon()->inbound.content_type;
}


#if SMCP_USE_BSD_SOCKETS
struct sockaddr* smcp_daemon_get_current_request_saddr() {
	return smcp_get_current_daemon()->inbound.saddr;
}

socklen_t smcp_daemon_get_current_request_socklen() {
	return smcp_get_current_daemon()->inbound.socklen;
}
#elif defined(CONTIKI)
const uip_ipaddr_t* smcp_daemon_get_current_request_ipaddr() {
	return &smcp_get_current_daemon()->inbound.toaddr;
}

const uint16_t smcp_daemon_get_current_request_ipport() {
	return smcp_get_current_daemon()->inbound.toport;
}
#endif

smcp_status_t
smcp_daemon_handle_inbound_packet(
	smcp_daemon_t	self,
	char*			buffer,
	size_t			packet_length,
	SMCP_SOCKET_ARGS
) {
	smcp_status_t ret = 0;
	struct coap_header_s* const packet = (void*)buffer;
	const coap_code_t code = packet->code;
	smcp_set_current_daemon(self);

	DEBUG_PRINTF(CSTR("%p: Inbound packet!"), self);

	require_action(packet->version==COAP_VERSION,bail,ret=SMCP_STATUS_FAILURE);

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	// Kind of a hack.
	buffer[packet_length] = 0;

	self->inbound.packet = packet;
	self->inbound.token_option = NULL;

	DEBUG_PRINTF(CSTR("%p: tt=%d"), self,packet->tt);
	DEBUG_PRINTF(CSTR("%p: http.code=%d, coap.code=%d"),self,coap_to_http_code(code),code);

	self->inbound.content_type = 0;
	smcp_current_request_reset_next_header();

	{	// Initial options scan.
		coap_option_key_t key;
		do {
			key = smcp_current_request_peek_header(NULL,NULL);
			if(key==COAP_HEADER_TOKEN) {
				self->inbound.token_option = self->inbound.this_option;
			} else if(key==COAP_HEADER_CONTENT_TYPE) {
				self->inbound.content_type = self->inbound.this_option[1];
			}
		} while(smcp_current_request_next_header_(NULL,NULL)!=COAP_HEADER_INVALID);
		self->inbound.content_ptr = (char*)self->inbound.this_option;
		self->inbound.content_len = packet_length-(self->inbound.content_ptr-buffer);
	}

#if SMCP_USE_BSD_SOCKETS
	self->inbound.saddr = saddr;
	self->inbound.socklen = socklen;
#elif CONTIKI
	self->inbound.toaddr = *toaddr;
	self->inbound.toport = toport;
#endif

	self->is_processing_message = true;
	self->did_respond = (packet->tt != COAP_TRANS_TYPE_CONFIRMABLE);

	smcp_current_request_reset_next_header();

//	self->cascade_count--;

	if(COAP_CODE_IS_REQUEST(code)) {
		ret = smcp_daemon_handle_request(self);
	} else if(COAP_CODE_IS_RESULT(code)) {
		ret = smcp_daemon_handle_response(self);
	}

	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

	// Check to make sure we have responded by now. If not, we need to.
	if((packet->tt==COAP_TRANS_TYPE_CONFIRMABLE) && !self->did_respond) {
		if(COAP_CODE_IS_REQUEST(code)) {
			int result_code = smcp_convert_status_to_result_code(ret);
			if(ret == SMCP_STATUS_OK) {
				if(code==COAP_METHOD_GET)
					result_code = COAP_RESULT_205_CONTENT;
				else if(code==COAP_METHOD_POST || code==COAP_METHOD_PUT)
					result_code = COAP_RESULT_204_CHANGED;
			}
			smcp_message_begin_response(result_code);
		} else {
			smcp_message_begin_response(0);
			if(ret)
				self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			else
				self->outbound.packet->tt = COAP_TRANS_TYPE_ACK;
		}
		smcp_message_send();
	}

bail:
	smcp_set_current_daemon(NULL);
	self->is_processing_message = false;
	self->force_current_outbound_code = false;
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

bail:
	smcp_set_current_daemon(NULL);
	self->is_responding = false;
	return ret;
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

	if(!smcp_get_current_daemon())
		smcp_set_current_daemon(self);

	check(self==smcp_get_current_daemon());

	// Remove the timer associated with this handler.
	smcp_daemon_invalidate_timer(self, &handler->timer);

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		    (*handler->callback)(
			SMCP_STATUS_HANDLER_INVALIDATED,
			handler->context
		);
	}

	free(handler);
}

//static int smcp_rtt = COAP_RESPONSE_TIMEOUT;
static int smcp_rtt = 500;

static int calc_retransmit_timeout(int retries_) {
	int ret = smcp_rtt;

	ret = (ret<<retries_);

	ret *= (1000 - 150) + (SMCP_FUNC_RANDOM_UINT32() % 300);

	ret /= 1000;

	if(ret > 5000)
		ret = 5000;

	return ret;
}

void
smcp_internal_handler_timeout_(
	smcp_daemon_t			self,
	smcp_transaction_t handler
) {
	smcp_status_t status = SMCP_STATUS_TIMEOUT;
	smcp_response_handler_func callback = handler->callback;
	void* context = handler->context;

	if((convert_timeval_to_cms(&handler->expiration) > 0)) {
		if(handler->waiting_for_async_response) {
			status = SMCP_STATUS_OK;
			smcp_daemon_schedule_timer(
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
				smcp_daemon_schedule_timer(
					self,
					&handler->timer,
					100
				);
			} else if(status == SMCP_STATUS_OK) {
				smcp_daemon_schedule_timer(
					self,
					&handler->timer,
					calc_retransmit_timeout(handler->attemptCount++)
				);
			}
		}
	}
	
	if(status) {
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
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)smcp_internal_delete_handler_,
		self
	);

	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)bt_count((void**)&self->transactions));

bail:
	return ret;
}

smcp_status_t
smcp_invalidate_transaction(
	smcp_daemon_t			self,
	coap_transaction_id_t	tid
) {
	bt_remove(
		    (void**)&self->transactions,
		    (void*)&tid,
		    (bt_compare_func_t)smcp_transaction_compare_tid,
		    (bt_delete_func_t)smcp_internal_delete_handler_,
		self
	);
	return 0;
}

smcp_status_t
smcp_daemon_handle_response(
	smcp_daemon_t	self
) {
	smcp_status_t ret = 0;
	smcp_transaction_t handler = NULL;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(
			"smcp_daemon(%p): Incoming response! tid=%d",
			self,
			smcp_daemon_get_current_tid()
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

	coap_transaction_id_t tid = smcp_daemon_get_current_tid();

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

	if(!handler) {
		if(self->inbound.packet->tt == COAP_TRANS_TYPE_CONFIRMABLE) {
			ret = smcp_message_begin_response(0);
			require_noerr(ret,bail);
			self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			ret = smcp_message_send();
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
		if(handler->flags & SMCP_TRANSACTION_ALWAYS_TIMEOUT) {
			handler->resendCallback = NULL;
			(*handler->callback)(
				self->inbound.packet->code,
				handler->context
			);
		} else {
			smcp_response_handler_func callback = handler->callback;
			handler->resendCallback = NULL;
			handler->callback = NULL;
			(*callback)(
			    self->inbound.packet->code,
			    handler->context
			);
		}
		smcp_invalidate_transaction(self, tid);
	}

bail:
	return ret;
}

#pragma mark -

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

smcp_status_t
smcp_message_set_async_response(struct smcp_async_response_s* x) {
	smcp_status_t ret = 0;
	smcp_daemon_t const self = smcp_get_current_daemon();
	self->outbound.packet->tt = x->tt;

#if SMCP_USE_BSD_SOCKETS
	ret = smcp_message_set_destaddr((void*)&x->saddr,x->socklen);
#elif CONTIKI
	ret = smcp_message_set_destaddr(&x->toaddr,x->toport);
#endif

	require_noerr(ret, bail);

	ret = smcp_message_add_header(COAP_HEADER_TOKEN, x->token_value, x->token_len);
	require_noerr(ret, bail);
bail:
	return ret;
}

smcp_status_t
smcp_start_async_response(struct smcp_async_response_s* x) {
	smcp_status_t ret = 0;
	smcp_daemon_t const self = smcp_get_current_daemon();

	require_action(x!=NULL,bail,ret=SMCP_STATUS_INVALID_ARGUMENT);

	ret = smcp_message_begin_response(COAP_CODE_EMPTY);

	require_noerr(ret, bail);

	ret = smcp_message_send();

	require_noerr(ret, bail);

	// TODO: Make duplicate detection better!
	if(x->original_tid && x->original_tid == self->inbound.packet->tid) {
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
	x->toaddr = self->inbound.toaddr;
	x->toport = self->inbound.toport;
#endif

bail:
	return ret;
}

smcp_status_t
smcp_finish_async_response(struct smcp_async_response_s* x) {
	smcp_status_t ret = 0;

	// TODO: Add more stuff!

	x->original_tid = 0;

	require_noerr(ret, bail);

bail:
	return ret;
}

#pragma mark -
#pragma mark SMCP Request Handlers

smcp_status_t
smcp_daemon_handle_request(
	smcp_daemon_t	self
) {
	smcp_status_t ret = 0;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(
			"smcp_daemon(%p): Incoming request! tid=%d",
			self,
			smcp_daemon_get_current_tid()
		);
		coap_dump_header(
			SMCP_DEBUG_OUT_FILE,
			"    ",
			self->inbound.packet,
			0
		);
	}
#endif

	smcp_node_t node = smcp_daemon_get_root_node(self);
	smcp_request_handler_func request_handler = &smcp_default_request_handler;

	// TODO: Add authentication!

	{
		uint8_t* prev_option_ptr = self->inbound.this_option;
		coap_option_key_t prev_key = 0;
		coap_option_key_t key;
		uint8_t* value;
		size_t value_len;
		while((key=smcp_current_request_next_header_(&value, &value_len))!=COAP_HEADER_INVALID) {
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
					value,
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

	ret = (*request_handler)(
	    node,
	    self->inbound.packet->code
	);

	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

bail:
	return ret;
}

smcp_status_t
smcp_default_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	if(method == COAP_METHOD_GET) {
		return smcp_daemon_handle_list(node,method);
	}
	return SMCP_STATUS_NOT_IMPLEMENTED;
}

smcp_status_t
smcp_daemon_handle_list(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;
	char* next_node = NULL;
	char replyContent[SMCP_MAX_PATH_LENGTH + 32 + 1];
	size_t content_break_threshold = 120;
	size_t content_offset = 0;
	const char* prefix = NULL;
	memset(replyContent, 0, sizeof(replyContent));

	if(!node->parent) {
		if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,".well-known")) {
			smcp_current_request_next_header(NULL, NULL);
			if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"core")) {
				smcp_current_request_next_header(NULL, NULL);
				prefix = "/";
			} else {
				ret = SMCP_STATUS_NOT_ALLOWED;
				goto bail;
			}
		}
	}

	coap_option_key_t key;
	const uint8_t* value;
	size_t value_len;
	{
		while((key=smcp_current_request_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {
			require_action(key!=COAP_HEADER_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);
			if(key == COAP_HEADER_URI_QUERY) {
				// Skip URI query components for now.
			} else
			if(key == COAP_HEADER_CONTINUATION_RESPONSE) {
				next_node = alloca(value_len + 1);
				memcpy(next_node, value, value_len);
				next_node[value_len] = 0;
			} else if(key == COAP_HEADER_SIZE_REQUEST) {
				uint8_t i;
				content_break_threshold = 0;
				for(i = 0; i < value_len; i++)
					content_break_threshold =
						(content_break_threshold << 8) + value[i];
				if(content_break_threshold >= sizeof(replyContent)) {
					DEBUG_PRINTF(
						"Requested size (%d) is too large, trimming to %d.",
						(int)content_break_threshold,
						(int)sizeof(replyContent) - 1
					);
					content_break_threshold = sizeof(replyContent) - 1;
				}
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
		}
	}

	if((content_break_threshold == 0) || (content_offset && !next_node)) {
		// We don't support content offsets right now.
		// TODO: Think about the implications of content offsets.
		smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE));
		smcp_message_send();
		goto bail;
	}

	// Node should always be set by the time we get here.
	require_action(node, bail, ret = SMCP_STATUS_BAD_ARGUMENT);

	smcp_message_begin_response(COAP_RESULT_205_CONTENT);

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

		if(prefix)
			strlcat(replyContent, prefix, sizeof(replyContent));

		{
			size_t len = strlen(replyContent);
			if(sizeof(replyContent)-1>len)
				url_encode_cstr(replyContent+len, node_name, sizeof(replyContent) - len);
		}

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

	smcp_message_set_content_type(COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);

	// If there are more nodes, indicate as such in the headers.
	if(node && next_node) {
		smcp_message_set_code(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT));
		smcp_message_add_header(
			COAP_HEADER_CONTINUATION_REQUEST,
			next_node,
			HEADER_CSTR_LEN
		);
	}

	smcp_message_set_content(replyContent, COAP_HEADER_CSTR_LEN);

	smcp_message_send();

bail:
	return ret;
}


#pragma mark -
#pragma mark Nodes

smcp_node_t
smcp_daemon_get_root_node(smcp_daemon_t self) {
	return &self->root_node;
}
