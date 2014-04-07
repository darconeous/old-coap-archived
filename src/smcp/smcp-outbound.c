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
#define VERBOSE_DEBUG 1
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

#if CONTIKI
#include "contiki.h"
#include "net/ip/tcpip.h"
#include "net/ip/resolv.h"
#endif

#if SMCP_USE_UIP
#include "net/ip/uip-udp-packet.h"
#include "net/ip/uiplib.h"
extern uint16_t uip_slen;
extern void *uip_sappdata;
#endif

#if SMCP_USE_BSD_SOCKETS
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#pragma mark -
#pragma mark Constrained sending API

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
	self->outbound.socklen = 0;
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
	require(!self->is_responding,bail);

	if(self->is_processing_message)
		self->outbound.next_tid = smcp_inbound_get_msg_id();
	ret = smcp_outbound_begin(
		self,
		code,
		(self->inbound.packet->tt==COAP_TRANS_TYPE_NONCONFIRMABLE)?COAP_TRANS_TYPE_NONCONFIRMABLE:COAP_TRANS_TYPE_ACK
	);
	require_noerr(ret, bail);
	self->is_responding = true;

	if(self->is_processing_message)
		require_noerr(ret=smcp_outbound_set_msg_id(smcp_inbound_get_msg_id()),bail);

	if(self->is_processing_message) {
#if SMCP_USE_BSD_SOCKETS
		ret = smcp_outbound_set_destaddr(
			(void*)&self->inbound.saddr,
			self->inbound.socklen
		);
#elif SMCP_USE_UIP
		ret = smcp_outbound_set_destaddr(
			&self->inbound.toaddr,
			self->inbound.toport
		);
#endif
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

#if SMCP_USE_BSD_SOCKETS
smcp_status_t
smcp_outbound_set_destaddr(
	struct sockaddr *sockaddr, socklen_t socklen
) {
	smcp_t const self = smcp_get_current_instance();
	memcpy(
		&self->outbound.saddr,
		sockaddr,
		socklen
	);
	self->outbound.socklen = socklen;

	if(self->current_transaction) {
		const struct sockaddr_in6 * const saddr = (void*)sockaddr;
		self->current_transaction->multicast = IN6_IS_ADDR_MULTICAST(&saddr->sin6_addr);
	}
	return SMCP_STATUS_OK;
}
#elif defined(SMCP_USE_UIP)
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
	coap_option_key_t key, const char* value, coap_size_t len
) {
	smcp_t const self = smcp_get_current_instance();

	if(len == SMCP_CSTR_LEN)
		len = strlen(value);

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
	smcp_status_t ret;

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

#elif SMCP_USE_UIP
	SMCP_NON_RECURSIVE uip_ipaddr_t toaddr;
	memset(&toaddr, 0, sizeof(toaddr));

	DEBUG_PRINTF("Outbound: Dest host [%s]:%d",addr_str,toport);
	toport = htons(toport);

	ret = uiplib_ipaddrconv(
		addr_str,
		&toaddr
	) ? SMCP_STATUS_OK : SMCP_STATUS_HOST_LOOKUP_FAILURE;

#if SMCP_CONF_USE_DNS
#if CONTIKI
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
#else // CONTIKI
#error SMCP_CONF_USE_DNS was set, but no DNS lookup mechamism is known!
#endif
#endif // SMCP_CONF_USE_DNS

	require_noerr(ret,bail);

	ret = smcp_outbound_set_destaddr(&toaddr,toport);

	require_noerr(ret, bail);
#endif // SMCP_USE_UIP

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
	smcp_status_t ret;
	smcp_t const self = smcp_get_current_instance();
	SMCP_NON_RECURSIVE struct url_components_s components;
	SMCP_NON_RECURSIVE uint16_t toport;
	SMCP_NON_RECURSIVE char* uri_copy;

	ret = SMCP_STATUS_OK;

	memset((void*)&components,0,sizeof(components));
	toport = COAP_DEFAULT_PORT;
	uri_copy = NULL;

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
			toport = atoi(components.port);
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

			ret = smcp_outbound_add_option(COAP_OPTION_PROXY_URI, uri, strlen(uri));
			require_noerr(ret, bail);
			ret = smcp_outbound_set_uri(self->proxy_url,flags);
			goto bail;
		}
	}

	if(!(flags&SMCP_MSG_SKIP_AUTHORITY)) {
		if(components.host && !string_contains_colons(components.host)) {
			ret = smcp_outbound_add_option(COAP_OPTION_URI_HOST, components.host, strlen(components.host));
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
			coap_size_t len = strlen(key);
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

coap_size_t
smcp_outbound_get_space_remaining(void)
{
	smcp_t const self = smcp_get_current_instance();
	coap_size_t len = (self->outbound.content_ptr-(char*)self->outbound.packet)
		+ self->outbound.content_len;
	if (self->outbound.max_packet_len > len)
		return self->outbound.max_packet_len - len;
	return 0;
}

smcp_status_t
smcp_outbound_append_content(const char* value,coap_size_t len) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();
	coap_size_t max_len = smcp_outbound_get_space_remaining();
	char* dest;

	if(len == SMCP_CSTR_LEN)
		len = strlen(value);

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


#pragma mark -

#if !SMCP_AVOID_PRINTF
smcp_status_t
smcp_outbound_set_content_formatted(const char* fmt, ...) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	va_list args;
	char* content = smcp_outbound_get_content_ptr(NULL);
	int len = smcp_outbound_get_space_remaining();

	require(content!=NULL, bail);

	content += smcp_get_current_instance()->outbound.content_len;

	va_start(args,fmt);

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
		coap_size_t header_len = (smcp_outbound_get_content_ptr(NULL)-(char*)self->outbound.packet);

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
