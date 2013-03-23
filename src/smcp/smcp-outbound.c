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

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert-macros.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "smcp-internal.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"
#include "smcp-auth.h"
#include "smcp.h"
#include "ll.h"
#include "url-helpers.h"

#if CONTIKI
#include "contiki.h"
#include "net/uip-udp-packet.h"
#include "net/uiplib.h"
#include "net/tcpip.h"
#include "net/resolv.h"
extern uint16_t uip_slen;
#endif

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

#pragma mark -
#pragma mark Constrained sending API

void
smcp_outbound_drop() {
	smcp_t self = smcp_get_current_instance();

	self->is_responding = false;
	self->did_respond = true;
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

#if SMCP_USE_BSD_SOCKETS
	self->outbound.packet = (struct coap_header_s*)self->outbound.packet_bytes;
	self->outbound.socklen = 0;
#elif CONTIKI
	uip_udp_conn = self->udp_conn;
	self->outbound.packet = (struct coap_header_s*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];

	if(self->outbound.packet == self->inbound.packet) {
		self->outbound.packet = (struct coap_header_s*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN + self->inbound.packet_len + 1];

		// Fix the alignment for 32-bit platforms.
		self->outbound.packet = (struct coap_header_s*)((uintptr_t)(self->outbound.packet+8)&~(uintptr_t)0x7);
	}
#endif

	self->outbound.packet->tt = tt;
	self->outbound.packet->msg_id = self->outbound.next_tid;
	self->outbound.packet->code = code;
	self->outbound.packet->version = COAP_VERSION;

	// Set the token.
	if(	self->is_processing_message
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

	return SMCP_STATUS_OK;
}

smcp_status_t smcp_outbound_begin_response(coap_code_t code) {
	SMCP_NON_RECURSIVE smcp_status_t ret;
	SMCP_NON_RECURSIVE smcp_t const self = smcp_get_current_instance();

	ret = SMCP_STATUS_OK;

	require_action_string(!self->did_respond,
		bail,
		ret = SMCP_STATUS_RESPONSE_NOT_ALLOWED,
		"Attempted to send more than one response!"
	);

	// If we have already started responding, don't bother.
	require(!self->is_responding,bail);

	if(self->is_processing_message)
		self->outbound.next_tid = smcp_inbound_get_msg_id();
	smcp_outbound_begin(self,code,(self->inbound.packet->tt==COAP_TRANS_TYPE_NONCONFIRMABLE)?COAP_TRANS_TYPE_NONCONFIRMABLE:COAP_TRANS_TYPE_ACK);
	self->is_responding = true;

	if(self->is_processing_message)
		smcp_outbound_set_msg_id(smcp_inbound_get_msg_id());

	if(self->is_processing_message) {
#if SMCP_USE_BSD_SOCKETS
		ret = smcp_outbound_set_destaddr(
			self->inbound.saddr,
			self->inbound.socklen
		);
#elif CONTIKI
		ret = smcp_outbound_set_destaddr(
			&self->inbound.toaddr,
			self->inbound.toport
		);
#endif
		require_noerr(ret, bail);
	}
bail:
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
	SMCP_NON_RECURSIVE smcp_status_t ret;
	SMCP_NON_RECURSIVE smcp_t const self = smcp_get_current_instance();

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

#if SMCP_USE_BSD_SOCKETS
smcp_status_t
smcp_outbound_set_destaddr(
	struct sockaddr *sockaddr, socklen_t socklen
) {
	SMCP_NON_RECURSIVE smcp_t const self = smcp_get_current_instance();
	memcpy(
		&self->outbound.saddr,
		sockaddr,
		socklen
	);
	self->outbound.socklen = socklen;

	if(self->current_transaction) {
		const struct sockaddr_in6 const *saddr = (void*)sockaddr;
		self->current_transaction->multicast = IN6_IS_ADDR_MULTICAST(&saddr->sin6_addr);
	}
	return SMCP_STATUS_OK;
}
#elif defined(CONTIKI)
smcp_status_t
smcp_outbound_set_destaddr(
	const uip_ipaddr_t *toaddr, uint16_t toport
) {
	uip_ipaddr_copy(&smcp_get_current_instance()->udp_conn->ripaddr, toaddr);
	smcp_get_current_instance()->udp_conn->rport = toport;

	return SMCP_STATUS_OK;
}
#endif

static smcp_status_t
smcp_outbound_add_option_(
	coap_option_key_t key, const char* value, size_t len
) {
	SMCP_NON_RECURSIVE smcp_t const self = smcp_get_current_instance();

	if(	(	self->outbound.content_ptr
			- (char*)self->outbound.packet
			+ len + 10
		) > SMCP_MAX_PACKET_LENGTH
	) {
		// We ran out of room!
		return SMCP_STATUS_MESSAGE_TOO_BIG;
	}

	if(key<self->outbound.last_option_key) {
		assert_printf("warning: Out of order header: %s",coap_option_key_to_cstr(key, self->is_responding));
	}

	if(len == SMCP_CSTR_LEN)
		len = strlen(value);

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
	SMCP_NON_RECURSIVE smcp_status_t ret;
	SMCP_NON_RECURSIVE smcp_t const self = smcp_get_current_instance();

	ret = SMCP_STATUS_OK;

#if SMCP_CONF_TRANS_ENABLE_BLOCK2
	if(	(self->current_transaction
		&& self->current_transaction->next_block2)
		&& self->outbound.last_option_key<COAP_OPTION_BLOCK2
		&& key>COAP_OPTION_BLOCK2
	) {
		uint32_t block2 = htonl(self->current_transaction->next_block2);
		uint8_t size = 3; // TODO: calculate this properly
		ret = smcp_outbound_add_option_(
			COAP_OPTION_BLOCK2,
			(char*)&block2+sizeof(block2)-size,
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

	if(	self->outbound.last_option_key<COAP_OPTION_AUTHENTICATE
		&& key>COAP_OPTION_AUTHENTICATE
	) {
		ret = smcp_auth_add_options();
	}

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
	coap_option_key_t key, const char* value, size_t len
) {
	SMCP_NON_RECURSIVE smcp_status_t ret;

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
	if(value>>24)
		return value = htonl(value),smcp_outbound_add_option(key, ((char*)&value)+0, 4);
	else if(value>>16)
		return value = htonl(value),smcp_outbound_add_option(key, ((char*)&value)+1, 3);
	else if(value>>8)
		return value = htonl(value),smcp_outbound_add_option(key, ((char*)&value)+2, 2);
	else if(value)
		return value = htonl(value),smcp_outbound_add_option(key, ((char*)&value)+3, 1);
	return smcp_outbound_add_option(key, NULL, 0);
}


smcp_status_t
smcp_outbound_set_destaddr_from_host_and_port(const char* addr_str,uint16_t toport) {
	SMCP_NON_RECURSIVE smcp_status_t ret;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
		.sin6_family	= AF_INET6,
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
	};

	struct addrinfo hint = {
		.ai_flags		= AI_ADDRCONFIG,
		.ai_family		= AF_UNSPEC,
	};

	struct addrinfo *results = NULL;
	struct addrinfo *iter = NULL;

	// Check to see if this host is a group we know about.
	if(strcasecmp(addr_str, "coap-alldevices")==0)
		addr_str = COAP_MULTICAST_IP6_ALLDEVICES;

	int error = getaddrinfo(addr_str, NULL, &hint, &results);

	DEBUG_PRINTF("Outbound: Dest host [%s]:%d",addr_str,toport);
	toport = htons(toport);

	if(error && (inet_addr(addr_str) != INADDR_NONE)) {
		char addr_v4mapped_str[8 + strlen(addr_str)];
		hint.ai_family = AF_INET6;
		hint.ai_flags = AI_ALL | AI_V4MAPPED,
		strcpy(addr_v4mapped_str,"::ffff:");
		strcat(addr_v4mapped_str,addr_str);
		error = getaddrinfo(addr_v4mapped_str,
			NULL,
			&hint,
			&results
		);
	}

	require_action(error!=EAI_AGAIN,bail,ret=SMCP_STATUS_WAIT_FOR_DNS);

#ifdef TM_EWOULDBLOCK
	require_action(error!=TM_EWOULDBLOCK,bail,ret=SMCP_STATUS_WAIT_FOR_DNS);
#endif

	require_action_string(
		!error,
		bail,
		ret = SMCP_STATUS_HOST_LOOKUP_FAILURE,
		gai_strerror(error)
	);

	for(iter = results;iter && (iter->ai_family!=AF_INET6 && iter->ai_family!=AF_INET);iter=iter->ai_next);

	require_action(
		iter,
		bail,
		ret = SMCP_STATUS_HOST_LOOKUP_FAILURE
	);

	if(iter->ai_family == AF_INET) {
		struct sockaddr_in *v4addr = (void*)iter->ai_addr;
		saddr.sin6_addr.s6_addr[10] = 0xFF;
		saddr.sin6_addr.s6_addr[11] = 0xFF;
		memcpy(&saddr.sin6_addr.s6_addr[12], &v4addr->sin_addr.s_addr, 4);
	} else {
		if(saddr.sin6_addr.s6_addr[0]==0xFF) {
			smcp_t const self = smcp_get_current_instance();
			check(self->outbound.packet->tt != COAP_TRANS_TYPE_CONFIRMABLE);
			if(self->outbound.packet->tt == COAP_TRANS_TYPE_CONFIRMABLE) {
				self->outbound.packet->tt = COAP_TRANS_TYPE_NONCONFIRMABLE;
			}
		}
		memcpy(&saddr, iter->ai_addr, iter->ai_addrlen);
	}
	saddr.sin6_port = toport;

	ret = smcp_outbound_set_destaddr((struct sockaddr *)&saddr,sizeof(struct sockaddr_in6));
	require_noerr(ret, bail);

#elif CONTIKI
	SMCP_NON_RECURSIVE uip_ipaddr_t toaddr;
	memset(&toaddr, 0, sizeof(toaddr));

	DEBUG_PRINTF("Outbound: Dest host [%s]:%d",addr_str,toport);
	toport = htons(toport);

	ret = uiplib_ipaddrconv(
		addr_str,
		&toaddr
	) ? SMCP_STATUS_OK : SMCP_STATUS_HOST_LOOKUP_FAILURE;

#if SMCP_CONF_USE_DNS
	if(ret) {
		SMCP_NON_RECURSIVE uip_ipaddr_t *temp = NULL;
		switch(resolv_lookup(addr_str,&temp)) {
			case RESOLV_STATUS_CACHED:
				memcpy(&toaddr, temp, sizeof(uip_ipaddr_t));
				ret = SMCP_STATUS_OK;
				break;
			case RESOLV_STATUS_UNCACHED:
			case RESOLV_STATUS_EXPIRED:
				resolv_query(addr_str);
			case RESOLV_STATUS_RESOLVING:
				ret = SMCP_STATUS_WAIT_FOR_DNS;
				break;
			default:
			case RESOLV_STATUS_ERROR:
			case RESOLV_STATUS_NOT_FOUND:
				ret = SMCP_STATUS_HOST_LOOKUP_FAILURE;
				break;
		}
	}
#endif // SMCP_CONF_USE_DNS

	require_noerr(ret,bail);

	ret = smcp_outbound_set_destaddr(&toaddr,toport);

	require_noerr(ret, bail);
#endif // CONTIKI

bail:
#if SMCP_USE_BSD_SOCKETS
	if(results)
		freeaddrinfo(results);
#endif
	return ret;
}

smcp_status_t
smcp_outbound_set_uri(
	const char* uri, char flags
) {
	SMCP_NON_RECURSIVE smcp_status_t ret;
	SMCP_NON_RECURSIVE smcp_t const self = smcp_get_current_instance();
	SMCP_NON_RECURSIVE char* proto_str;
	SMCP_NON_RECURSIVE char* addr_str;
	SMCP_NON_RECURSIVE char* port_str;
	SMCP_NON_RECURSIVE char* path_str;
	SMCP_NON_RECURSIVE char* query_str;
	SMCP_NON_RECURSIVE char* uri_copy;
	SMCP_NON_RECURSIVE char* username_str;
	SMCP_NON_RECURSIVE char* password_str;
	SMCP_NON_RECURSIVE uint16_t toport;

	ret = SMCP_STATUS_OK;

	proto_str = NULL;
	addr_str = NULL;
	port_str = NULL;
	path_str = NULL;
	query_str = NULL;
	uri_copy = NULL;
	username_str = NULL;
	password_str = NULL;
	toport = SMCP_DEFAULT_PORT;

	require_action(uri, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	{
#if HAVE_ALLOCA
		uri_copy = alloca(strlen(uri) + 1);
		strcpy(uri_copy, uri);
#else
		uri_copy = strdup(uri);
#endif

		require_action(uri_copy!=NULL,bail,ret = SMCP_STATUS_MALLOC_FAILURE);

		// Parse the URI.
		require_action_string(
			url_parse(
				uri_copy,
				&proto_str,
				&username_str,
				&password_str,
				&addr_str,
				&port_str,
				&path_str,
				&query_str
			),
			bail,
			ret = SMCP_STATUS_URI_PARSE_FAILURE,
			"Unable to parse URL"
		);

		if(!proto_str && !addr_str) {
			// Talking to ourself.
			proto_str = "coap";
			addr_str = "::1";
			toport = smcp_get_port(smcp_get_current_instance());
			flags |= SMCP_MSG_SKIP_AUTHORITY;
		} else if(port_str) {
			toport = atoi(port_str);
		}

		DEBUG_PRINTF(
			CSTR("URI Parse: \"%s\" -> host=\"%s\" port=\"%u\" path=\"%s\""),
			uri,
			addr_str,
			toport,
			path_str
		);
	}

	if(	proto_str && !strequal_const(proto_str, "coap") ) {
		require_action_string(
			self->proxy_url,
			bail,
			ret=SMCP_STATUS_INVALID_ARGUMENT,
			"No proxy URL configured"
		);
		require_action(uri!=self->proxy_url,bail,ret = SMCP_STATUS_INVALID_ARGUMENT);

		ret = smcp_outbound_add_option(COAP_OPTION_PROXY_URI, uri, strlen(uri));
		require_noerr(ret, bail);
		ret = smcp_outbound_set_uri(self->proxy_url,flags);
		goto bail;
	}

	if(!(flags&SMCP_MSG_SKIP_AUTHORITY)) {
		if(addr_str && !string_contains_colons(addr_str)) {
			ret = smcp_outbound_add_option(COAP_OPTION_URI_HOST, addr_str, strlen(addr_str));
			require_noerr(ret, bail);
		}
		if(port_str) {
			ret = smcp_outbound_add_option_uint(COAP_OPTION_URI_PORT, toport);
			require_noerr(ret, bail);
		}
	}

	if(	!(flags&SMCP_MSG_SKIP_DESTADDR)
		&& addr_str && addr_str[0]!=0
	) {
		ret = smcp_outbound_set_destaddr_from_host_and_port(addr_str,toport);
		require_noerr(ret, bail);
	}

	if(username_str) {
		ret = smcp_auth_outbound_set_credentials(username_str, password_str);
		require_noerr(ret, bail);
	}

	if(path_str) {
		SMCP_NON_RECURSIVE char* component;
		const bool has_trailing_slash = path_str[0]?('/' == path_str[strlen(path_str)-1]):false;

		// Move past any preceding slashes.
		while(path_str[0] == '/')
			path_str++;

		while(url_path_next_component(&path_str,&component)) {
			ret = smcp_outbound_add_option(COAP_OPTION_URI_PATH, component, SMCP_CSTR_LEN);
			require_noerr(ret,bail);
		}
		if(has_trailing_slash) {
			ret = smcp_outbound_add_option(COAP_OPTION_URI_PATH, NULL, 0);
			require_noerr(ret,bail);
		}
	}

	if(query_str) {
		SMCP_NON_RECURSIVE char* key;

		while(url_form_next_value(&query_str,&key,NULL)) {
			size_t len = strlen(key);
			if(len)
				ret = smcp_outbound_add_option(COAP_OPTION_URI_QUERY, key, len);
			require_noerr(ret,bail);
		}
	}

bail:
	if(ret)
		DEBUG_PRINTF("URI Parse failed for URI: \"%s\"",uri);

#if !HAVE_ALLOCA
	free(uri_copy);
#endif

	return ret;
}

smcp_status_t
smcp_outbound_append_content(const char* value,size_t len) {
	SMCP_NON_RECURSIVE smcp_status_t ret;
	SMCP_NON_RECURSIVE smcp_t const self = smcp_get_current_instance();
	SMCP_NON_RECURSIVE size_t max_len;
	SMCP_NON_RECURSIVE char* dest;

	ret = SMCP_STATUS_FAILURE;
	max_len = self->outbound.content_len;

	if(len == SMCP_CSTR_LEN)
		len = strlen(value);

	max_len += len;

	dest = smcp_outbound_get_content_ptr(&max_len);

	require(dest,bail);

	dest += self->outbound.content_len;

	require(max_len-self->outbound.content_len>=len,bail);

	memcpy(dest, value, len);

	smcp_outbound_set_content_len(len+self->outbound.content_len);

	ret = SMCP_STATUS_OK;

bail:
	return ret;
}

char*
smcp_outbound_get_content_ptr(size_t* max_len) {
	smcp_t const self = smcp_get_current_instance();

	// Finish up any remaining automatically-added headers.
	if(self->outbound.packet->code)
		smcp_outbound_add_options_up_to_key_(COAP_OPTION_INVALID);

	if(max_len)
		*max_len = SMCP_MAX_PACKET_LENGTH-(self->outbound.content_ptr-(char*)self->outbound.packet);

	return self->outbound.content_ptr;
}

smcp_status_t
smcp_outbound_set_content_len(size_t len) {
	smcp_get_current_instance()->outbound.content_len = len;
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_outbound_send() {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();
	size_t header_len;

	if(self->outbound.packet->code) {
		ret = smcp_auth_outbound_finish();
		require_noerr(ret,bail);
	}

	header_len = (smcp_outbound_get_content_ptr(NULL)-(char*)self->outbound.packet);

	// Remove the start-of-payload marker if we have no payload.
	if(!smcp_get_current_instance()->outbound.content_len)
		header_len--;

#if VERBOSE_DEBUG
	{
		char addr_str[50] = "???";
		uint16_t port = 0;
#if SMCP_USE_BSD_SOCKETS
		inet_ntop(AF_INET6,&smcp_get_current_instance()->outbound.saddr.sin6_addr,addr_str,sizeof(addr_str)-1);
		port = ntohs(smcp_get_current_instance()->outbound.saddr.sin6_port);
#elif CONTIKI
		port = ntohs(smcp_get_current_instance()->udp_conn->rport);
#define CSTR_FROM_6ADDR(dest,addr) sprintf(dest,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
		CSTR_FROM_6ADDR(addr_str,&smcp_get_current_instance()->udp_conn->ripaddr);
#endif
		DEBUG_PRINTF("Outbound:\tTO -> [%s]:%d",addr_str,(int)port);
		coap_dump_header(
			SMCP_DEBUG_OUT_FILE,
			"Outbound:\t",
			self->outbound.packet,
			header_len+smcp_get_current_instance()->outbound.content_len
		);
	}
#endif

	assert(coap_verify_packet((char*)self->outbound.packet,header_len+smcp_get_current_instance()->outbound.content_len));

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

#if SMCP_USE_BSD_SOCKETS

	require_string(smcp_get_current_instance()->outbound.socklen,bail,"Destaddr not set");

	ssize_t sent_bytes = sendto(
		smcp_get_current_instance()->fd,
		smcp_get_current_instance()->outbound.packet_bytes,
		header_len +
		smcp_get_current_instance()->outbound.content_len,
		0,
		(struct sockaddr *)&smcp_get_current_instance()->outbound.saddr,
		smcp_get_current_instance()->outbound.socklen
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
	uip_slen = header_len +	smcp_get_current_instance()->outbound.content_len;

	if(self->outbound.packet!=(struct coap_header_s*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN]) {
		memmove(
			&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN],
			(char*)self->outbound.packet,
			uip_slen
		);
		self->outbound.packet = (struct coap_header_s*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
	}

	uip_udp_conn = smcp_get_current_instance()->udp_conn;

	uip_process(UIP_UDP_SEND_CONN);

#if UIP_CONF_IPV6
	tcpip_ipv6_output();
#else
	if(uip_len > 0)
		tcpip_output();
#endif
	uip_slen = 0;

	memset(&smcp_get_current_instance()->udp_conn->ripaddr, 0, sizeof(uip_ipaddr_t));
	smcp_get_current_instance()->udp_conn->rport = 0;
#endif
	if(smcp_get_current_instance()->is_responding)
		smcp_get_current_instance()->did_respond = true;
	smcp_get_current_instance()->is_responding = false;

	ret = SMCP_STATUS_OK;
bail:
	return ret;
}

#pragma mark -

#if !SMCP_AVOID_PRINTF
smcp_status_t
smcp_outbound_set_content_formatted(const char* fmt, ...) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	size_t len = 0;
	va_list args;
	char* content = smcp_outbound_get_content_ptr(&len);

	content += smcp_get_current_instance()->outbound.content_len;
	len -= smcp_get_current_instance()->outbound.content_len;

	va_start(args,fmt);

	require(content!=NULL,bail);

	len = vsnprintf(content,len,fmt,args);

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
	int32_to_dec_cstr(nstr,v);
	smcp_outbound_append_content(nstr, SMCP_CSTR_LEN);
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
	smcp_outbound_append_content(uint32_to_dec_cstr(nstr,v), SMCP_CSTR_LEN);
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
	smcp_outbound_append_content(uint32_to_dec_cstr(nstr,v), SMCP_CSTR_LEN);
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
