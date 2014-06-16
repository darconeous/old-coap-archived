/*	@file smcp-outbound.c
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

#define __APPLE_USE_RFC_3542 1

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert-macros.h"

#include "smcp.h"
#include "smcp-internal.h"
#include "smcp-logging.h"
#include "smcp-auth.h"

#include "ll.h"
#include "url-helpers.h"

#if SMCP_USE_UIP
#include "net/ip/uiplib.h"
extern void *uip_sappdata;
#endif


#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static uint8_t
smcp_calc_uint32_option_size(uint32_t big_endian_value)
{
	if (((uint8_t*)(&big_endian_value))[0] != 0) {
		return 4;
	} else if (((uint8_t*)(&big_endian_value))[1] != 0) {
		return 3;
	} else if (((uint8_t*)(&big_endian_value))[2] != 0) {
		return 2;
	} else if (((uint8_t*)(&big_endian_value))[3] != 0) {
		return 1;
	}

	return 0;
}

// MARK: -
// MARK: Constrained sending API

void
smcp_outbound_drop() {
	smcp_t self = smcp_get_current_instance();

	self->is_responding = false;
	self->did_respond = true;
}

void
smcp_outbound_reset()
{
	memset(&smcp_get_current_instance()->outbound, 0, sizeof(smcp_get_current_instance()->outbound));
	smcp_get_current_instance()->is_responding = false;
	smcp_get_current_instance()->did_respond = false;
}

smcp_status_t
smcp_outbound_begin(
	smcp_t self, coap_code_t code, coap_transaction_type_t tt
) {
	SMCP_EMBEDDED_SELF_HOOK;

#if !SMCP_EMBEDDED
	if(!self)
		self = smcp_get_current_instance();
#endif

	check(!smcp_get_current_instance() || smcp_get_current_instance()==self);

	smcp_set_current_instance(self);

#if SMCP_USE_CASCADE_COUNT
	if(self->cascade_count == 1)
		return SMCP_STATUS_CASCADE_LOOP;
#endif

	self->outbound.max_packet_len = SMCP_MAX_PACKET_LENGTH;
#if SMCP_USE_BSD_SOCKETS
	self->outbound.packet = (struct coap_header_s*)self->outbound.packet_bytes;
	memset(&self->outbound.saddr,0,sizeof(self->outbound.saddr));
#elif SMCP_USE_UIP
	uip_udp_conn = self->udp_conn;
	self->outbound.packet = (struct coap_header_s*)uip_sappdata;

	if(self->outbound.packet == self->inbound.packet) {
		// We want to preserve at least the headers from the inbound packet,
		// so we will put the outbound packet immediately after the last
		// header option of the inbound packet.
		self->outbound.packet = (struct coap_header_s*)self->inbound.content_ptr;

		// Fix the alignment for 32-bit platforms.
		self->outbound.packet = (struct coap_header_s*)((uintptr_t)((uint8_t*)self->outbound.packet+7)&~(uintptr_t)0x7);

		int space_remaining = UIP_BUFSIZE-((uint8_t*)self->outbound.packet-(uint8_t*)uip_buf);
		if (space_remaining-4<0) {
			self->outbound.packet = (struct coap_header_s*)uip_sappdata;
		} else {
			self->outbound.max_packet_len = space_remaining;
		}
	}
#endif
	assert(NULL!=self->outbound.packet);

	self->outbound.packet->tt = tt;
	self->outbound.packet->msg_id = self->outbound.next_tid;
	self->outbound.packet->code = code;
	self->outbound.packet->version = COAP_VERSION;

	// Set the token.
	if(	self->is_processing_message
		&& self->inbound.packet
		&& self->inbound.packet->token_len
		&& code
	) {
		self->outbound.packet->token_len = self->inbound.packet->token_len;
		memcpy(self->outbound.packet->token,self->inbound.packet->token,self->outbound.packet->token_len);
	} else if(code && (code < COAP_RESULT_100) && self->current_transaction) {
		// For sending a request.
		self->outbound.packet->token_len = sizeof(self->current_transaction->token);
		memcpy(self->outbound.packet->token,(void*)&self->current_transaction->token,self->outbound.packet->token_len);
	} else {
		self->outbound.packet->token_len = 0;
	}

	self->outbound.last_option_key = 0;

	self->outbound.content_ptr = (char*)self->outbound.packet->token + self->outbound.packet->token_len;
	*self->outbound.content_ptr++ = 0xFF;  // start-of-content marker
	self->outbound.content_len = 0;
	self->force_current_outbound_code = false;
	self->is_responding = false;

	smcp_auth_outbound_init();

	return SMCP_STATUS_OK;
}

smcp_status_t smcp_outbound_begin_response(coap_code_t code) {
	smcp_status_t ret;
	smcp_t const self = smcp_get_current_instance();

	ret = SMCP_STATUS_OK;

	require_action_string(!self->did_respond,
		bail,
		ret = SMCP_STATUS_RESPONSE_NOT_ALLOWED,
		"Attempted to send more than one response!"
	);

	// If we have already started responding, don't bother.
	require_quiet(!self->is_responding, bail);

	if(self->is_processing_message)
		self->outbound.next_tid = smcp_inbound_get_msg_id();
	ret = smcp_outbound_begin(
		self,
		code,
		(self->inbound.packet->tt==COAP_TRANS_TYPE_NONCONFIRMABLE)?COAP_TRANS_TYPE_NONCONFIRMABLE:COAP_TRANS_TYPE_ACK
	);
	require_noerr(ret, bail);
	self->is_responding = true;

	if(self->is_processing_message) {
		require_noerr(ret=smcp_outbound_set_msg_id(smcp_inbound_get_msg_id()),bail);

		ret = smcp_outbound_set_destaddr(&self->inbound.saddr);
		require_noerr(ret, bail);
	}
bail:
	if (ret!=SMCP_STATUS_OK) {
		self->is_responding = false;
	}
	return ret;
}

smcp_status_t
smcp_outbound_set_msg_id(coap_msg_id_t tid) {
	assert(smcp_get_current_instance()->outbound.packet);
	smcp_get_current_instance()->outbound.packet->msg_id = tid;
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_outbound_set_code(coap_code_t code) {
	smcp_t const self = smcp_get_current_instance();
	if(!self->force_current_outbound_code)
		self->outbound.packet->code = code;
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_outbound_set_token(const uint8_t *token,uint8_t token_length) {
	smcp_status_t ret;
	smcp_t const self = smcp_get_current_instance();

	ret = SMCP_STATUS_OK;

	require_action(token_length<=8,bail,ret=SMCP_STATUS_INVALID_ARGUMENT);

	if(self->outbound.packet->token_len != token_length) {
		self->outbound.packet->token_len = token_length;
		self->outbound.content_ptr = (char*)self->outbound.packet->token+self->outbound.packet->token_len;
		self->outbound.content_len = 0;
		*self->outbound.content_ptr++ = 0xFF;
	}

	if(token_length)
		memcpy(self->outbound.packet->token,token,token_length);

bail:
	return ret;
}

static smcp_status_t
smcp_outbound_add_option_(
	coap_option_key_t key, const char* value, coap_size_t len
) {
	smcp_t const self = smcp_get_current_instance();

	if(len == SMCP_CSTR_LEN)
		len = (coap_size_t)strlen(value);

	if(	smcp_outbound_get_space_remaining() < len + 8 ) {
		// We ran out of room!
		return SMCP_STATUS_MESSAGE_TOO_BIG;
	}

	if(key<self->outbound.last_option_key) {
		assert_printf("warning: Out of order header: %s",coap_option_key_to_cstr(key, self->is_responding));
	}

	if(self->outbound.content_ptr!=(char*)self->outbound.packet->token+self->outbound.packet->token_len)
		self->outbound.content_ptr--;	// remove end-of-options marker

	self->outbound.content_ptr += coap_insert_option(
		(uint8_t*)self->outbound.packet->token+self->outbound.packet->token_len,
		(uint8_t*)self->outbound.content_ptr,
		key,
		(const uint8_t*)value,
		len
	);

	if(key>self->outbound.last_option_key)
		self->outbound.last_option_key = key;

	*self->outbound.content_ptr++ = 0xFF;  // Add end-of-options marker

#if OPTION_DEBUG
	coap_dump_header(
		SMCP_DEBUG_OUT_FILE,
		"Option-Debug >>> ",
		self->outbound.packet,
		self->outbound.content_ptr-(char*)self->outbound.packet
	);
#endif

	return SMCP_STATUS_OK;
}

static smcp_status_t
smcp_outbound_add_options_up_to_key_(
	coap_option_key_t key
) {
	smcp_status_t ret;
	smcp_t const self = smcp_get_current_instance();

	(void)self;
	ret = SMCP_STATUS_OK;

#if SMCP_CONF_TRANS_ENABLE_BLOCK2
	if(	(self->current_transaction
		&& self->current_transaction->next_block2)
		&& self->outbound.last_option_key<COAP_OPTION_BLOCK2
		&& key>COAP_OPTION_BLOCK2
	) {
		uint32_t block2 = htonl(self->current_transaction->next_block2);
		uint8_t size = smcp_calc_uint32_option_size(block2);
		ret = smcp_outbound_add_option_(
			COAP_OPTION_BLOCK2,
			(char*)&block2+4-size,
			size
		);
	}
#endif

#if SMCP_CONF_TRANS_ENABLE_OBSERVING
	if(	(self->current_transaction && self->current_transaction->flags&SMCP_TRANSACTION_OBSERVE)
		&& self->outbound.last_option_key<COAP_OPTION_OBSERVE
		&& key>COAP_OPTION_OBSERVE
	) {
		if(self->outbound.packet->code && self->outbound.packet->code<COAP_RESULT_100) {
			// For sending a request.
			ret = smcp_outbound_add_option_(
				COAP_OPTION_OBSERVE,
				(void*)NULL,
				0
			);
		}
	}
#endif

#if SMCP_USE_CASCADE_COUNT
	if(	self->outbound.last_option_key<COAP_OPTION_CASCADE_COUNT
		&& key>COAP_OPTION_CASCADE_COUNT
		&& self->cascade_count
	) {
		uint8_t cc = self->cascade_count-1;
		ret = smcp_outbound_add_option_(
			COAP_OPTION_CASCADE_COUNT,
			(char*)&cc,
			1
		);
	}
#endif

	return ret;
}

smcp_status_t
smcp_outbound_add_option(
	coap_option_key_t key, const char* value, coap_size_t len
) {
	smcp_status_t ret;

	ret = smcp_outbound_add_options_up_to_key_(key);
	require_noerr(ret, bail);

#if SMCP_CONF_TRANS_ENABLE_BLOCK2
	if(key==COAP_OPTION_BLOCK2
		&& smcp_get_current_instance()->current_transaction
		&& smcp_get_current_instance()->current_transaction->next_block2
	) {
		goto bail;
	}
#endif

	ret = smcp_outbound_add_option_(key,value,len);
	require_noerr(ret, bail);

bail:
	return ret;
}

smcp_status_t
smcp_outbound_add_option_uint(coap_option_key_t key,uint32_t value) {
	uint8_t size;

	value = htonl(value);
	size = smcp_calc_uint32_option_size(value);

	return smcp_outbound_add_option(key, ((char*)&value)+(4-size), size);
}

smcp_status_t
smcp_outbound_set_destaddr(const smcp_sockaddr_t* sockaddr) {
	smcp_t const self = smcp_get_current_instance();
	memcpy(
		&self->outbound.saddr,
		sockaddr,
		sizeof(self->outbound.saddr)
	);

	if(self->current_transaction) {
		memcpy(
			&self->current_transaction->saddr,
			sockaddr,
			sizeof(self->current_transaction->saddr)
		);
		self->current_transaction->multicast = SMCP_IS_ADDR_MULTICAST(&sockaddr->smcp_addr);
	}
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_outbound_set_destaddr_from_host_and_port(const char* addr_str,uint16_t toport) {
	smcp_status_t ret;
	SMCP_NON_RECURSIVE smcp_sockaddr_t saddr;

	DEBUG_PRINTF("Outbound: Dest host [%s]:%d",addr_str,toport);

	// Check to see if this host is a group we know about.
	if (strcasecmp(addr_str, COAP_MULTICAST_STR_ALLDEVICES) == 0) {
		addr_str = SMCP_COAP_MULTICAST_ALLDEVICES_ADDR;
	}

	ret = smcp_internal_lookup_hostname(addr_str, &saddr);
	require_noerr(ret,bail);

	saddr.smcp_port = htons(toport);

	ret = smcp_outbound_set_destaddr(&saddr);
	require_noerr(ret, bail);

	if (SMCP_IS_ADDR_MULTICAST(&saddr.smcp_addr)) {
		smcp_t const self = smcp_get_current_instance();
		check(self->outbound.packet->tt != COAP_TRANS_TYPE_CONFIRMABLE);
		if(self->outbound.packet->tt == COAP_TRANS_TYPE_CONFIRMABLE) {
			self->outbound.packet->tt = COAP_TRANS_TYPE_NONCONFIRMABLE;
		}
	}

bail:
	return ret;
}

smcp_status_t
smcp_outbound_set_uri(
	const char* uri, char flags
) {
	smcp_status_t ret = SMCP_STATUS_OK;
	smcp_t const self = smcp_get_current_instance();
	SMCP_NON_RECURSIVE struct url_components_s components;
	SMCP_NON_RECURSIVE uint16_t toport;
	SMCP_NON_RECURSIVE char* uri_copy;

	memset((void*)&components, 0, sizeof(components));
	toport = COAP_DEFAULT_PORT;
	uri_copy = NULL;

	require_action(uri, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	{
#if HAVE_ALLOCA
		uri_copy = alloca(strlen(uri) + 1);
		strcpy(uri_copy, uri);
#elif SMCP_AVOID_MALLOC
		// Well, we can't use the stack and we can't
		// use malloc. Let's use what room we have left
		// in the packet buffer, since this is temporary anyway...
		// It helps a bunch that we know the user hasn't written
		// any content yet (because that would be an API violation)
		if (smcp_outbound_get_space_remaining() > strlen(uri) + 8) {
			uri_copy = self->outbound.content_ptr + self->outbound.content_len;

			// The options section may be expanding as we parse this, so
			// we should move ahead by a few bytes. We are helped out
			// by the fact that we will be writing the options in the
			// same order they appear in the URL.
			uri_copy += 8;

			strcpy(uri_copy, uri);
		}
#else
		uri_copy = strdup(uri);
#endif

		require_action(uri_copy != NULL, bail, ret = SMCP_STATUS_MALLOC_FAILURE);

		// Parse the URI.
		require_action_string(
			url_parse(
				uri_copy,
				&components
			),
			bail,
			ret = SMCP_STATUS_URI_PARSE_FAILURE,
			"Unable to parse URL"
		);

		if(!components.protocol && !components.host) {
			// Talking to ourself.
			components.protocol = "coap";
			components.host = "::1";
			toport = smcp_get_port(smcp_get_current_instance());
			flags |= SMCP_MSG_SKIP_AUTHORITY;
		} else if(components.port) {
			toport = (uint16_t)atoi(components.port);
		}

		DEBUG_PRINTF(
			"URI Parse: \"%s\" -> host=\"%s\" port=\"%u\" path=\"%s\"",
			uri,
			components.host,
			toport,
			components.path
		);
	}

	if(components.protocol) {
#if SMCP_DTLS
		if(strequal_const(components.protocol, "coaps")) {
			// There is a lot more that is needed for this to work...
			toport = COAP_DEFAULT_TLSPORT;

			require_noerr(ret = smcp_auth_outbound_use_dtls(), bail);
		} else
#endif
		if(!strequal_const(components.protocol, "coap")) {
			require_action_string(
				self->proxy_url,
				bail,
				ret=SMCP_STATUS_INVALID_ARGUMENT,
				"No proxy URL configured"
			);
			require_action(uri!=self->proxy_url,bail,ret = SMCP_STATUS_INVALID_ARGUMENT);

			ret = smcp_outbound_add_option(COAP_OPTION_PROXY_URI, uri, SMCP_CSTR_LEN);
			require_noerr(ret, bail);
			ret = smcp_outbound_set_uri(self->proxy_url,flags);
			goto bail;
		}
	}

	if(!(flags&SMCP_MSG_SKIP_AUTHORITY)) {
		if(components.host && !string_contains_colons(components.host)) {
			ret = smcp_outbound_add_option(COAP_OPTION_URI_HOST, components.host, SMCP_CSTR_LEN);
			require_noerr(ret, bail);
		}
		if(components.port) {
			ret = smcp_outbound_add_option_uint(COAP_OPTION_URI_PORT, toport);
			require_noerr(ret, bail);
		}
	}

	if(	!(flags&SMCP_MSG_SKIP_DESTADDR)
		&& components.host && components.host[0]!=0
	) {
		ret = smcp_outbound_set_destaddr_from_host_and_port(components.host,toport);
		require_noerr(ret, bail);
	}

	if(components.username) {
		ret = smcp_auth_outbound_set_credentials(components.username, components.password);
		require_noerr(ret, bail);
	}

	if(components.path) {
		SMCP_NON_RECURSIVE char* component;
		const bool has_trailing_slash = components.path[0]?('/' == components.path[strlen(components.path)-1]):false;

		// Move past any preceding slashes.
		while(components.path[0] == '/')
			components.path++;

		while(url_path_next_component(&components.path,&component)) {
			ret = smcp_outbound_add_option(COAP_OPTION_URI_PATH, component, SMCP_CSTR_LEN);
			require_noerr(ret,bail);
		}
		if(has_trailing_slash) {
			ret = smcp_outbound_add_option(COAP_OPTION_URI_PATH, NULL, 0);
			require_noerr(ret,bail);
		}
	}

	if(components.query) {
		SMCP_NON_RECURSIVE char* key;

		while(url_form_next_value(&components.query,&key,NULL)) {
			coap_size_t len = (coap_size_t)strlen(key);

			if (len) {
				ret = smcp_outbound_add_option(COAP_OPTION_URI_QUERY, key, len);
			}
			require_noerr(ret,bail);
		}
	}

bail:
	if(ret)
		DEBUG_PRINTF("URI Parse failed for URI: \"%s\"",uri);

#if !HAVE_ALLOCA && !SMCP_AVOID_MALLOC
	free(uri_copy);
#endif

	return ret;
}

coap_size_t
smcp_outbound_get_space_remaining(void)
{
	smcp_t const self = smcp_get_current_instance();
	coap_size_t len = (coap_size_t)(self->outbound.content_ptr-(char*)self->outbound.packet)
		+ self->outbound.content_len;
	if (self->outbound.max_packet_len > len)
		return self->outbound.max_packet_len - len;
	return 0;
}

smcp_status_t
smcp_outbound_append_content(const char* value, coap_size_t len)
{
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();
	coap_size_t max_len = smcp_outbound_get_space_remaining();
	char* dest;

	if (SMCP_CSTR_LEN == len) {
		len = (coap_size_t)strlen(value);
	}

	require_action(max_len>len, bail, ret = SMCP_STATUS_MESSAGE_TOO_BIG);

	dest = smcp_outbound_get_content_ptr(&max_len);
	require(dest,bail);

	dest += self->outbound.content_len;

	memcpy(dest, value, len);

	self->outbound.content_len += len;

	ret = SMCP_STATUS_OK;

bail:
	return ret;
}

char*
smcp_outbound_get_content_ptr(coap_size_t* max_len) {
	smcp_t const self = smcp_get_current_instance();

	// Finish up any remaining automatically-added headers.
	if(self->outbound.packet->code)
		smcp_outbound_add_options_up_to_key_(COAP_OPTION_INVALID);

	if(max_len)
		*max_len = smcp_outbound_get_space_remaining()+self->outbound.content_len;

	return self->outbound.content_ptr;
}

smcp_status_t
smcp_outbound_set_content_len(coap_size_t len) {
	smcp_get_current_instance()->outbound.content_len = len;
	return SMCP_STATUS_OK;
}


// MARK: -

#if !SMCP_AVOID_PRINTF
smcp_status_t
smcp_outbound_set_content_formatted(const char* fmt, ...) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	va_list args;
	char* content = smcp_outbound_get_content_ptr(NULL);
	coap_size_t len = smcp_outbound_get_space_remaining();

	require(content!=NULL, bail);

	content += smcp_get_current_instance()->outbound.content_len;

	va_start(args,fmt);

	len = (coap_size_t)vsnprintf(content,len,fmt,args);

	require(len!=0,bail);

	len += smcp_get_current_instance()->outbound.content_len;
	ret = smcp_outbound_set_content_len(len);

bail:
	va_end(args);
	return ret;
}
#endif

smcp_status_t
smcp_outbound_set_var_content_int(int v) {
#if SMCP_AVOID_PRINTF
	char nstr[12];
	smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	smcp_outbound_append_content("v=", SMCP_CSTR_LEN);
	return smcp_outbound_append_content(int32_to_dec_cstr(nstr,v), SMCP_CSTR_LEN);
#else
	smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	return smcp_outbound_set_content_formatted_const("v=%d",v);
#endif
}

smcp_status_t
smcp_outbound_set_var_content_unsigned_int(unsigned int v) {
#if SMCP_AVOID_PRINTF
	char nstr[11];
	smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	smcp_outbound_append_content("v=", SMCP_CSTR_LEN);
	return smcp_outbound_append_content(uint32_to_dec_cstr(nstr,v), SMCP_CSTR_LEN);
#else
	return smcp_outbound_set_content_formatted_const("v=%u",v);
#endif
}

smcp_status_t
smcp_outbound_set_var_content_unsigned_long_int(unsigned long int v) {
#if SMCP_AVOID_PRINTF
	char nstr[11];
	smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	smcp_outbound_append_content("v=", SMCP_CSTR_LEN);
	return smcp_outbound_append_content(uint32_to_dec_cstr(nstr,v), SMCP_CSTR_LEN);
#else
	return smcp_outbound_set_content_formatted_const("v=%ul",v);
#endif
}


smcp_status_t
smcp_outbound_quick_response(coap_code_t code, const char* body) {
	smcp_outbound_begin_response(code);
	if(body)
		smcp_outbound_append_content(body, SMCP_CSTR_LEN);
	return smcp_outbound_send();
}

smcp_status_t
smcp_outbound_send() {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();

	if(self->outbound.packet->code) {
		ret = smcp_auth_outbound_finalize();
		require_noerr(ret,bail);
	}

#if DEBUG
	{
		coap_size_t header_len = (coap_size_t)(smcp_outbound_get_content_ptr(NULL)-(char*)self->outbound.packet);

		// Remove the start-of-payload marker if we have no payload.
		if(!smcp_get_current_instance()->outbound.content_len)
			header_len--;
		DEBUG_PRINTF("Outbound packet size: %d, %d remaining",header_len+smcp_get_current_instance()->outbound.content_len, smcp_outbound_get_space_remaining());
		assert(header_len+smcp_get_current_instance()->outbound.content_len<=self->outbound.max_packet_len);

		assert(coap_verify_packet((char*)self->outbound.packet,header_len+smcp_get_current_instance()->outbound.content_len));
	}
#endif // DEBUG

	if(self->current_transaction)
		self->current_transaction->sent_code = self->outbound.packet->code;

#if defined(SMCP_DEBUG_OUTBOUND_DROP_PERCENT)
	if(SMCP_DEBUG_OUTBOUND_DROP_PERCENT*SMCP_RANDOM_MAX>SMCP_FUNC_RANDOM_UINT32()) {
		DEBUG_PRINTF("Dropping outbound packet for debugging!");
		if(smcp_get_current_instance()->is_responding)
			smcp_get_current_instance()->did_respond = true;
		smcp_get_current_instance()->is_responding = false;

		ret = SMCP_STATUS_OK;
		goto bail;
	}
#endif

#if SMCP_DTLS
	if(smcp_auth_outbound_is_using_dtls()) {
		extern smcp_status_t smcp_outbound_send_secure_hook();
		require((ret = smcp_outbound_send_secure_hook()) == 0, bail);
	} else
#endif
	{
		extern smcp_status_t smcp_outbound_send_hook();
		require((ret = smcp_outbound_send_hook()) == 0, bail);
	}

	if(smcp_get_current_instance()->is_responding)
		smcp_get_current_instance()->did_respond = true;
	smcp_get_current_instance()->is_responding = false;

	ret = SMCP_STATUS_OK;
bail:
	return ret;
}
