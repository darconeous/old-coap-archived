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
#include "smcp-timer.h"

#include "url-helpers.h"
#include "ll.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


// MARK: -
// MARK: Simple inbound getters

const struct coap_header_s*
smcp_inbound_get_packet() {
	return smcp_get_current_instance()->inbound.packet;
}

coap_size_t smcp_inbound_get_packet_length() {
	return smcp_get_current_instance()->inbound.packet_len;
}

const char*
smcp_inbound_get_content_ptr() {
	return smcp_get_current_instance()->inbound.content_ptr;
}

coap_size_t
smcp_inbound_get_content_len() {
	return smcp_get_current_instance()->inbound.content_len;
}

coap_content_type_t
smcp_inbound_get_content_type() {
	return smcp_get_current_instance()->inbound.content_type;
}

bool
smcp_inbound_is_dupe() {
	return smcp_get_current_instance()->inbound.is_dupe;
}

bool
smcp_inbound_is_fake() {
	return smcp_get_current_instance()->inbound.is_fake;
}

// MARK: -
// MARK: Option Parsing

void
smcp_inbound_reset_next_option() {
	smcp_t const self = smcp_get_current_instance();
	self->inbound.last_option_key = 0;
	self->inbound.this_option = self->inbound.packet->token + self->inbound.packet->token_len;
}

coap_option_key_t
smcp_inbound_next_option(const uint8_t** value, coap_size_t* len) {
	smcp_t const self = smcp_get_current_instance();

	if ( self->inbound.this_option    <  ((uint8_t*)self->inbound.packet+self->inbound.packet_len)
	  && self->inbound.this_option[0] != 0xFF
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
smcp_inbound_peek_option(const uint8_t** value, coap_size_t* len) {
	smcp_t const self = smcp_get_current_instance();
	coap_option_key_t ret = self->inbound.last_option_key;

	if ( self->inbound.last_option_key != COAP_OPTION_INVALID
	  && self->inbound.this_option     <  ((uint8_t*)self->inbound.packet+self->inbound.packet_len)
	  && self->inbound.this_option[0]  != 0xFF
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
smcp_inbound_option_strequal(coap_option_key_t key,const char* cstr) {
	smcp_t const self = smcp_get_current_instance();
	coap_option_key_t curr_key = self->inbound.last_option_key;
	const char* value;
	coap_size_t value_len;
	coap_size_t i;

	if (!self->inbound.this_option) {
		return false;
	}

	coap_decode_option(self->inbound.this_option, &curr_key, (const uint8_t**)&value, &value_len);

	if (curr_key != key) {
		return false;
	}

	for (i = 0; i < value_len; i++) {
		if(!cstr[i] || (value[i] != cstr[i])) {
			return false;
		}
	}
	return cstr[i]==0;
}

// MARK: -
// MARK: Nontrivial inbound getters

bool
smcp_inbound_origin_is_local() {
	const smcp_sockaddr_t* const saddr = smcp_plat_get_remote_sockaddr();

	if (NULL == saddr) {
		return false;
	}

	if (htonl(smcp_plat_get_port(smcp_get_current_instance())) != saddr->smcp_port) {
		return false;
	}

	return SMCP_IS_ADDR_LOOPBACK(&saddr->smcp_addr);
}

char*
smcp_inbound_get_path(char* where, uint8_t flags)
{
	smcp_t const self = smcp_get_current_instance();

	coap_option_key_t		last_option_key = self->inbound.last_option_key;
	const uint8_t*			this_option = self->inbound.this_option;

	char* filename;
	coap_size_t filename_len;
	coap_option_key_t key;
	char* iter;

#if !SMCP_AVOID_MALLOC
	if (!where) {
		where = calloc(1,SMCP_MAX_URI_LENGTH+1);
	}
#endif

	require(where != NULL, bail);

	iter = where;

	if ((flags & SMCP_GET_PATH_REMAINING) != SMCP_GET_PATH_REMAINING) {
		smcp_inbound_reset_next_option();
	}

	while ((key = smcp_inbound_peek_option(NULL,NULL))!=COAP_OPTION_URI_PATH
		&& key!=COAP_OPTION_INVALID
	) {
		smcp_inbound_next_option(NULL,NULL);
	}

	while (smcp_inbound_next_option((const uint8_t**)&filename, &filename_len)==COAP_OPTION_URI_PATH) {
		char old_end = filename[filename_len];
		if(iter!=where || (flags&SMCP_GET_PATH_LEADING_SLASH))
			*iter++='/';
		filename[filename_len] = 0;
		iter+=url_encode_cstr(iter, filename, SMCP_MAX_URI_LENGTH-(iter-where));
		filename[filename_len] = old_end;
	}

	if (flags & SMCP_GET_PATH_INCLUDE_QUERY) {
		smcp_inbound_reset_next_option();
		while((key = smcp_inbound_peek_option((const uint8_t**)&filename, &filename_len))!=COAP_OPTION_URI_QUERY
			&& key!=COAP_OPTION_INVALID
		) {
			smcp_inbound_next_option(NULL,NULL);
		}
		if (key == COAP_OPTION_URI_QUERY) {
			*iter++='?';
			while (smcp_inbound_next_option((const uint8_t**)&filename, &filename_len)==COAP_OPTION_URI_QUERY) {
				char old_end = filename[filename_len];
				char* equal_sign;

				if (iter[-1] != '?') {
					*iter++=';';
				}

				filename[filename_len] = 0;
				equal_sign = strchr(filename,'=');

				if (equal_sign) {
					*equal_sign = 0;
				}

				iter+=url_encode_cstr(iter, filename, SMCP_MAX_URI_LENGTH-(iter-where));

				if (equal_sign) {
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

bail:
	return where;
}

// MARK: -
// MARK: Inbound packet processing

smcp_status_t
smcp_inbound_packet_process(
	smcp_t self,
	char* buffer,
	coap_size_t packet_length,
	int flags
) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_status_t ret = 0;
	struct coap_header_s* const packet = (void*)buffer; // Should not use stack space.

	require_action(coap_verify_packet(buffer,packet_length),bail,ret=SMCP_STATUS_BAD_PACKET);

#if defined(SMCP_DEBUG_INBOUND_DROP_PERCENT)
	if ((uint32_t)(SMCP_DEBUG_INBOUND_DROP_PERCENT*SMCP_RANDOM_MAX)>SMCP_FUNC_RANDOM_UINT32()) {
		DEBUG_PRINTF("Dropping inbound packet for debugging!");
		goto bail;
	}
#endif

	smcp_set_current_instance(self);

	// Reset all inbound packet state.
	memset(&self->inbound,0,sizeof(self->inbound));

	// We are processing a message.
	self->is_processing_message = true;
	self->did_respond = false;

	self->inbound.packet = packet;
	self->inbound.packet_len = packet_length;
	self->inbound.content_type = COAP_CONTENT_TYPE_UNKNOWN;

	self->current_transaction = NULL;

#if SMCP_USE_CASCADE_COUNT
	self->cascade_count = SMCP_MAX_CASCADE_COUNT;
#endif

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	// Kind of a hack, but very convenient.
	buffer[packet_length] = 0;

#if VERBOSE_DEBUG
	{
		char addr_str[50] = "???";
		uint16_t port = ntohs(smcp_plat_get_remote_sockaddr()->smcp_port);
		SMCP_ADDR_NTOP(addr_str,sizeof(addr_str),&smcp_plat_get_remote_sockaddr()->smcp_addr);
		DEBUG_PRINTF("smcp(%p): Inbound packet from [%s]:%d", self, addr_str, (int)port);
		coap_dump_header(
			SMCP_DEBUG_OUT_FILE,
			"Inbound:\t",
			(struct coap_header_s*)self->inbound.packet,
			self->inbound.packet_len
		);
	}
#endif

	if (self->inbound.was_sent_to_multicast) {
		// If this was multicast, make sure it isn't confirmable.
		require_action(
			packet->tt != COAP_TRANS_TYPE_CONFIRMABLE,
			bail,
			ret = SMCP_STATUS_FAILURE
		);
	}

	if ((flags & SMCP_INBOUND_PACKET_TRUNCATED) == SMCP_INBOUND_PACKET_TRUNCATED) {
		ret = smcp_outbound_quick_response(
			COAP_RESULT_413_REQUEST_ENTITY_TOO_LARGE,
			"too-big"
		);
		check_noerr(ret);
		goto bail;
	}

	if (!self->inbound.is_fake) {
		self->inbound.is_dupe = smcp_inbound_dupe_check();
	}

	{	// Initial scan thru all of the options.
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;

		// Reset option scanner for initial option scan.
		smcp_inbound_reset_next_option();

		while((key = smcp_inbound_next_option(&value,&value_len)) != COAP_OPTION_INVALID) {
			switch(key) {
			case COAP_OPTION_CONTENT_TYPE:
				self->inbound.content_type = (coap_content_type_t)coap_decode_uint32(value,(uint8_t)value_len);
				break;

			case COAP_OPTION_OBSERVE:
				self->inbound.observe_value = coap_decode_uint32(value,(uint8_t)value_len);
				self->inbound.has_observe_option = 1;
				break;

			case COAP_OPTION_MAX_AGE:
				self->inbound.max_age = coap_decode_uint32(value,(uint8_t)value_len);
				self->inbound.max_age++;
				if (self->inbound.max_age < 5)
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
	self->inbound.content_len = (self->inbound.packet_len-(coap_size_t)((uint8_t*)self->inbound.content_ptr-(uint8_t*)packet));

	// Move past start-of-content marker.
	if (self->inbound.content_len > 0) {
		self->inbound.content_ptr++;
		self->inbound.content_len--;
	}

	// Be nice and reset the option scanner for the handler.
	smcp_inbound_reset_next_option();

	// Dispatch the packet to the appropriate handler.
	if (COAP_CODE_IS_REQUEST(packet->code)) {
		// Implementation of the following function is further
		// down in this file.
		ret = smcp_handle_request();
	} else if (COAP_CODE_IS_RESULT(packet->code)) {
		// See implementation in `smcp-transaction.c`.
		ret = smcp_handle_response();
	}

	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

	// Check to make sure we have responded by now. If not, we need to.
	if (!self->did_respond && (packet->tt==COAP_TRANS_TYPE_CONFIRMABLE)) {
		smcp_status_t original_ret = ret;

#if SMCP_USE_BSD_SOCKETS
		int original_errno = errno;
#endif

		smcp_outbound_reset();

		if (COAP_CODE_IS_REQUEST(packet->code)) {
			coap_code_t result_code = smcp_convert_status_to_result_code(original_ret);

			if(self->inbound.is_dupe) {
				ret = 0;
			}

			if (ret == SMCP_STATUS_OK) {
				if (packet->code == COAP_METHOD_GET) {
					result_code = COAP_RESULT_205_CONTENT;
				} else if (packet->code == COAP_METHOD_POST || packet->code == COAP_METHOD_PUT) {
					result_code = COAP_RESULT_204_CHANGED;
				} else if (packet->code == COAP_METHOD_DELETE) {
					result_code = COAP_RESULT_202_DELETED;
				}
			}

			ret = smcp_outbound_begin_response(result_code);

			require_noerr(ret, bail);

			// For an ISE, let's give a little more information.
			if (result_code == COAP_RESULT_500_INTERNAL_SERVER_ERROR) {
				smcp_outbound_set_var_content_int(original_ret);
#if SMCP_USE_BSD_SOCKETS
				smcp_outbound_append_content(";d=\"", SMCP_CSTR_LEN);
				errno = original_errno;
				smcp_outbound_append_content(smcp_status_to_cstr(original_ret), SMCP_CSTR_LEN);
				smcp_outbound_append_content("\"", SMCP_CSTR_LEN);
#endif
			}
		} else { // !COAP_CODE_IS_REQUEST(packet->code)
			// This isn't a request, so we send either an ACK,
			// or a RESET.
			ret = smcp_outbound_begin_response(COAP_CODE_EMPTY);

			require_noerr(ret, bail);

			if ((ret != SMCP_STATUS_OK) && !self->inbound.is_dupe) {
				self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			} else {
				self->outbound.packet->tt = COAP_TRANS_TYPE_ACK;
			}

			smcp_outbound_set_token(NULL, 0);
		}
		ret = smcp_outbound_send();
	}

bail:
	self->is_processing_message = false;
	self->force_current_outbound_code = false;
	self->inbound.packet = NULL;
	self->inbound.content_ptr = NULL;
	self->inbound.content_len = 0;
	smcp_set_current_instance(NULL);
	return ret;
}

// MARK: -
// MARK: Request Handler

smcp_status_t
smcp_handle_request() {
	smcp_status_t ret = SMCP_STATUS_NOT_FOUND;
	smcp_t const self = smcp_get_current_instance();
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

#if SMCP_CONF_ENABLE_VHOSTS
	{
		extern smcp_status_t smcp_vhost_route(smcp_request_handler_func* func, void** context);
		ret = smcp_vhost_route(&request_handler, &context);
		require_noerr(ret, bail);
	}
#endif

	require_action(NULL!=request_handler,bail,ret=SMCP_STATUS_NOT_IMPLEMENTED);

	smcp_inbound_reset_next_option();

	return (*request_handler)(context);

bail:
	return ret;
}
