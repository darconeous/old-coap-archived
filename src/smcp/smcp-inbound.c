/*	@file smcp-inbound.c
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

#include "smcp.h"
#include "smcp-internal.h"
#include "smcp-logging.h"
#include "smcp-auth.h"
#include "smcp-timer.h"

#include "url-helpers.h"
#include "ll.h"

#if CONTIKI
#include "contiki.h"
#include "net/ip/tcpip.h"
#include "net/ip/resolv.h"
#endif // CONTIKI

#if SMCP_USE_BSD_SOCKETS
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#endif // SMCP_USE_BSD_SOCKETS


#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


#pragma mark -
#pragma mark Simple inbound getters

const struct coap_header_s*
smcp_inbound_get_packet(smcp_t self) {
	return self->inbound.packet;
}

coap_size_t smcp_inbound_get_packet_length(smcp_t self) {
	return self->inbound.packet_len;
}

const char*
smcp_inbound_get_content_ptr(smcp_t self) {
	return self->inbound.content_ptr;
}

coap_size_t
smcp_inbound_get_content_len(smcp_t self) {
	return self->inbound.content_len;
}

coap_content_type_t
smcp_inbound_get_content_type(smcp_t self) {
	return self->inbound.content_type;
}

bool
smcp_inbound_is_dupe(smcp_t self) {
	return self->inbound.is_dupe;
}

bool
smcp_inbound_is_fake(smcp_t self) {
	return self->inbound.is_fake;
}

#pragma mark -
#pragma mark Option Parsing

void
smcp_inbound_reset_next_option(smcp_t self) {
	self->inbound.last_option_key = 0;
	self->inbound.this_option = self->inbound.packet->token + self->inbound.packet->token_len;
}

coap_option_key_t
smcp_inbound_next_option(smcp_t self, const uint8_t** value, coap_size_t* len) {
	if(self->inbound.this_option < ((uint8_t*)self->inbound.packet+self->inbound.packet_len)
		&& self->inbound.this_option[0]!=0xFF
	) {
		self->inbound.this_option = coap_decode_option(
			self->inbound.this_option,
			&self->inbound.last_option_key,
			value,
			len
		);
	} else {
		self->inbound.last_option_key = COAP_OPTION_INVALID;
	}
	return self->inbound.last_option_key;
}

coap_option_key_t
smcp_inbound_peek_option(smcp_t self, const uint8_t** value, coap_size_t* len) {
	coap_option_key_t ret = self->inbound.last_option_key;
	if(self->inbound.last_option_key!=COAP_OPTION_INVALID
		&& self->inbound.this_option<((uint8_t*)self->inbound.packet+self->inbound.packet_len)
		&& self->inbound.this_option[0]!=0xFF
	) {
		coap_decode_option(
			self->inbound.this_option,
			&ret,
			value,
			len
		);

	} else {
		ret = COAP_OPTION_INVALID;
	}
	return ret;
}

bool
smcp_inbound_option_strequal(smcp_t self, coap_option_key_t key,const char* cstr) {
	coap_option_key_t curr_key = self->inbound.last_option_key;
	const char* value;
	coap_size_t value_len;
	coap_size_t i;

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

#pragma mark -
#pragma mark Nontrivial inbound getters

bool
smcp_inbound_origin_is_local(smcp_t self) {
	const smcp_sockaddr_t* const saddr = smcp_inbound_get_srcaddr(self);

	if(!saddr)
		return false;

	// TODO: Are these checks adequate?

	if(saddr->smcp_port!=htonl(smcp_get_port(self)))
		return false;

	return SMCP_IS_ADDR_LOOPBACK(&saddr->smcp_addr);
}

char*
smcp_inbound_get_path(smcp_t self, char* where, uint8_t flags) {
	coap_option_key_t		last_option_key = self->inbound.last_option_key;
	const uint8_t*			this_option = self->inbound.this_option;

	char* filename;
	coap_size_t filename_len;
	coap_option_key_t key;
	char* iter;

	if(!where)
		where = calloc(1,SMCP_MAX_URI_LENGTH+1);

	if(!where)
		return 0;

	iter = where;

	if(!(flags&SMCP_GET_PATH_REMAINING))
		smcp_inbound_reset_next_option(self);

	while((key = smcp_inbound_peek_option(self, NULL, NULL))!=COAP_OPTION_URI_PATH
		&& key != COAP_OPTION_INVALID
	) {
		smcp_inbound_next_option(self, NULL, NULL);
	}

	while(smcp_inbound_next_option(self, (const uint8_t**)&filename, &filename_len)==COAP_OPTION_URI_PATH) {
		char old_end = filename[filename_len];
		if(iter!=where || (flags&SMCP_GET_PATH_LEADING_SLASH))
			*iter++='/';
		filename[filename_len] = 0;
		iter+=url_encode_cstr(iter, filename, SMCP_MAX_URI_LENGTH-(iter-where));
		filename[filename_len] = old_end;
	}

	if(flags&SMCP_GET_PATH_INCLUDE_QUERY) {
		smcp_inbound_reset_next_option(self);
		while((key = smcp_inbound_peek_option(self, (const uint8_t**)&filename, &filename_len))!=COAP_OPTION_URI_QUERY
			&& key!=COAP_OPTION_INVALID
		) {
			smcp_inbound_next_option(self,NULL,NULL);
		}
		if(key==COAP_OPTION_URI_QUERY) {
			*iter++='?';
			while(smcp_inbound_next_option(self, (const uint8_t**)&filename, &filename_len)==COAP_OPTION_URI_QUERY) {
				char old_end = filename[filename_len];
				char* equal_sign;

				if(iter[-1]!='?')
					*iter++=';';

				filename[filename_len] = 0;
				equal_sign = strchr(filename,'=');

				if(equal_sign)
					*equal_sign = 0;

				iter+=url_encode_cstr(iter, filename, SMCP_MAX_URI_LENGTH-(iter-where));

				if(equal_sign) {
					*iter++='=';
					iter+=url_encode_cstr(iter, equal_sign+1, SMCP_MAX_URI_LENGTH-(iter-where));
					*equal_sign = '=';
				}
				filename[filename_len] = old_end;
			}
		}
	}

	*iter = 0;

	self->inbound.last_option_key = last_option_key;
	self->inbound.this_option = this_option;
	return where;
}

#pragma mark -
#pragma mark Inbound packet processing

smcp_status_t
smcp_inbound_start_packet(
	smcp_t	self,
	char*			buffer,
	coap_size_t			packet_length
) {
	smcp_status_t ret = 0;
	struct coap_header_s* const packet = (void*)buffer; // Should not use stack space.

	require_action(coap_verify_packet(buffer,packet_length),bail,ret=SMCP_STATUS_BAD_PACKET);

#if defined(SMCP_DEBUG_INBOUND_DROP_PERCENT)
	if((uint32_t)(SMCP_DEBUG_INBOUND_DROP_PERCENT*SMCP_RANDOM_MAX)>SMCP_FUNC_RANDOM_UINT32()) {
		DEBUG_PRINTF("Dropping inbound packet for debugging!");
		goto bail;
	}
#endif

	// Reset all inbound packet state.
	memset(&self->inbound,0,sizeof(self->inbound));

	// We are processing a message.
	self->is_processing_message = true;
	self->did_respond = false;

	self->inbound.packet = packet;
	self->inbound.packet_len = packet_length;
	self->inbound.content_type = COAP_CONTENT_TYPE_UNKNOWN;

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	// Kind of a hack, but very convenient.
	buffer[packet_length] = 0;

bail:
	return ret;
}

smcp_status_t
smcp_inbound_set_srcaddr(smcp_t self, const smcp_sockaddr_t* sockaddr) {
	if(!self->is_processing_message)
		return SMCP_STATUS_FAILURE;
	memcpy(&self->inbound.saddr, sockaddr, sizeof(self->inbound.saddr));

	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_inbound_set_destaddr(smcp_t self, const smcp_sockaddr_t* sockaddr) {
	if(!self->is_processing_message)
		return SMCP_STATUS_FAILURE;

	self->inbound.was_sent_to_multicast = SMCP_IS_ADDR_MULTICAST(&sockaddr->smcp_addr);

#if SMCP_USE_BSD_SOCKETS
#if SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET6
	self->inbound.pktinfo.ipi6_addr = sockaddr->smcp_addr;
	self->inbound.pktinfo.ipi6_ifindex = 0;
#elif SMCP_BSD_SOCKETS_NET_FAMILY==AF_INET
	self->inbound.pktinfo.ipi_addr = sockaddr->smcp_addr;
	self->inbound.pktinfo.ipi_ifindex = 0;
#endif
#endif

	return SMCP_STATUS_OK;
}

const smcp_sockaddr_t* smcp_inbound_get_srcaddr(smcp_t self) {
	return (const smcp_sockaddr_t*)&self->inbound.saddr;
}

smcp_status_t
smcp_inbound_finish_packet(smcp_t self) {
	smcp_status_t ret = SMCP_STATUS_OK;
	struct coap_header_s* const packet = (void*)self->inbound.packet;

	require_action(self->is_processing_message,bail,ret=SMCP_STATUS_FAILURE);

#if VERBOSE_DEBUG
	{
		char addr_str[50] = "???";
		uint16_t port = ntohs(self->inbound.saddr.smcp_port);
		SMCP_ADDR_NTOP(addr_str,sizeof(addr_str),&self->inbound.saddr.smcp_addr);
		DEBUG_PRINTF("smcp(%p): Inbound packet from [%s]:%d", self,addr_str,(int)port);
		coap_dump_header(
			SMCP_DEBUG_OUT_FILE,
			"Inbound:\t",
			(struct coap_header_s*)self->inbound.packet,
			self->inbound.packet_len
		);
	}
#endif

	if(self->inbound.was_sent_to_multicast) {
		// If this was multicast, make sure it isn't confirmable.
		require_action(
			packet->tt!=COAP_TRANS_TYPE_CONFIRMABLE,
			bail,
			ret=SMCP_STATUS_FAILURE
		);
	}

#if SMCP_USE_CASCADE_COUNT
	self->cascade_count = 100;
#endif

	// Calculate the message-id hash (address+port+message_id)
	fasthash_start(0);
	fasthash_feed((void*)&self->inbound.saddr,sizeof(self->inbound.saddr));
	fasthash_feed((const uint8_t*)&packet->msg_id,sizeof(packet->msg_id));
	self->inbound.transaction_hash = fasthash_finish_uint32();

	// SEC-TODO: This is not a good way to determine if a packet is a duplicate!
	{	// Check to see if this packet is a duplicate.
		unsigned int i = SMCP_CONF_DUPE_BUFFER_SIZE;
		while(i--) {
			if(self->dupe[i].hash == self->inbound.transaction_hash) {
				self->inbound.is_dupe = true;
				break;
			}
		}
	}

	{	// Initial scan thru all of the options.
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;

		// Reset option scanner for initial option scan.
		smcp_inbound_reset_next_option(self);

		while((key = smcp_inbound_next_option(self,&value,&value_len)) != COAP_OPTION_INVALID) {
			switch(key) {
			case COAP_OPTION_CONTENT_TYPE:
				self->inbound.content_type = coap_decode_uint32(value,(uint8_t)value_len);
				break;

			case COAP_OPTION_OBSERVE:
				self->inbound.observe_value = coap_decode_uint32(value,(uint8_t)value_len);
				self->inbound.has_observe_option = 1;
				break;

			case COAP_OPTION_MAX_AGE:
				self->inbound.max_age = coap_decode_uint32(value,(uint8_t)value_len);
				self->inbound.max_age++;
				if(self->inbound.max_age < 5)
					self->inbound.max_age = 5;
				break;

			case COAP_OPTION_BLOCK2:
				self->inbound.block2_value = coap_decode_uint32(value,(uint8_t)value_len);
				break;

#if SMCP_USE_CASCADE_COUNT
			case COAP_OPTION_CASCADE_COUNT:
				self->cascade_count = coap_decode_uint32(value,(uint8_t)value_len);
				break;
#endif

			default:
				break;
			}
		}
	}

	// Sanity check on debug builds.
	check(((unsigned)(self->inbound.this_option-(uint8_t*)packet)==self->inbound.packet_len) || self->inbound.this_option[0]==0xFF);

	// Now that we are at the end of the options, we know
	// where the content starts.
	self->inbound.content_ptr = (char*)self->inbound.this_option;
	self->inbound.content_len = self->inbound.packet_len-((uint8_t*)self->inbound.content_ptr-(uint8_t*)packet);

	// Move past start-of-content marker.
	if(self->inbound.content_len) {
		self->inbound.content_ptr++;
		self->inbound.content_len--;
	}

	// Be nice and reset the option scanner for the handler.
	smcp_inbound_reset_next_option(self);

	if(COAP_CODE_IS_REQUEST(packet->code)) {
		// See code below.
		ret = smcp_handle_request();
	} else if(COAP_CODE_IS_RESULT(packet->code)) {
		// See implementation in `smcp-transaction.c`.
		ret = smcp_handle_response();
	}

	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

	if(	(ret == SMCP_STATUS_OK)
		&& !self->inbound.is_fake
		&& !self->inbound.is_dupe
	) {
		// This is not a dupe, add it to the list.
		self->dupe[self->dupe_index].hash = self->inbound.transaction_hash;
		self->dupe_index++;
		self->dupe_index %= SMCP_CONF_DUPE_BUFFER_SIZE;
	}

	// Check to make sure we have responded by now. If not, we need to.
	if(!self->did_respond && (packet->tt==COAP_TRANS_TYPE_CONFIRMABLE)) {
		smcp_outbound_reset(self);
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
			smcp_outbound_begin_response(self, result_code);

			// For an ISE, let's give a little more information.
			if(result_code==COAP_RESULT_500_INTERNAL_SERVER_ERROR) {
				smcp_outbound_set_var_content_int(self, ret);
			}
		} else {
			smcp_outbound_begin_response(self, 0);
			if(ret && !self->inbound.is_dupe)
				self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			else
				self->outbound.packet->tt = COAP_TRANS_TYPE_ACK;
			smcp_outbound_set_token(self, NULL, 0);
		}
		ret = smcp_outbound_send(self);
	}

bail:
	self->is_processing_message = false;
	self->force_current_outbound_code = false;
	self->inbound.packet = NULL;
	self->inbound.content_ptr = NULL;
	self->inbound.content_len = 0;
	return ret;
}

#pragma mark -
#pragma mark Request Handler

smcp_status_t
smcp_handle_request(smcp_t self) {
	smcp_status_t ret = SMCP_STATUS_NOT_FOUND;
	smcp_request_handler_func request_handler = self->request_handler;
	void* context = self->request_handler_context;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(
			"smcp(%p): %sIncoming request!",
			self,
			(self->inbound.is_fake)?"(FAKE) ":""
		);
	}
#endif

	// TODO: Add proxy-server handler.

	// Authenticate the request.
	ret = smcp_auth_inbound_init(self);
	require_noerr(ret,bail);

#if SMCP_CONF_ENABLE_VHOSTS
	{
		extern smcp_status_t smcp_vhost_route(smcp_request_handler_func* func, void** context);
		smcp_vhost_route(&request_handler, &context);
		require_noerr(ret,bail);
	}
#endif

	require_action(NULL!=request_handler,bail,ret=SMCP_STATUS_NOT_IMPLEMENTED);

	smcp_inbound_reset_next_option(self);

	return (*request_handler)(self, context);

bail:
	return ret;
}
