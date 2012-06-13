/*	@file smcp-send.c
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

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "smcp-internal.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"
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

smcp_status_t
smcp_outbound_begin(
	smcp_t self, coap_code_t code, coap_transaction_type_t tt
) {
	if(!self)
		self = smcp_get_current_instance();

	check(!smcp_get_current_instance() || smcp_get_current_instance()==self);
	smcp_set_current_instance(self);

#if SMCP_USE_BSD_SOCKETS
	self->outbound.packet = (struct coap_header_s*)smcp_get_current_instance()->outbound.packet_bytes;
#elif CONTIKI
	uip_udp_conn = smcp_get_current_instance()->udp_conn;
	self->outbound.packet = (struct coap_header_s*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
#else
#error WRITEME!
#endif

	self->outbound.packet->tt = tt;
	self->outbound.packet->tid = self->outbound.next_tid;
	self->outbound.packet->code = code;
	self->outbound.packet->version = COAP_VERSION;
	self->outbound.packet->option_count = 0;

	self->outbound.last_option_key = 0;

	self->outbound.content_ptr = (char*)self->outbound.packet->options;
	self->outbound.content_len = 0;
	self->force_current_outbound_code = false;
	self->is_responding = false;

#if SMCP_USE_BSD_SOCKETS
	self->outbound.socklen = 0;
#elif defined(CONTIKI)
	// Writeme!
#endif
	return SMCP_STATUS_OK;
}

smcp_status_t smcp_outbound_begin_response(coap_code_t code) {
	smcp_status_t ret = SMCP_STATUS_OK;
	smcp_t const self = smcp_get_current_instance();

	require_action_string(!self->did_respond,
		bail,
		ret = SMCP_STATUS_RESPONSE_NOT_ALLOWED,
		"Attempted to send more than one response!"
	);

	// If we have already started responding, don't bother.
	require(!self->is_responding,bail);

	if(self->is_processing_message)
		self->outbound.next_tid = self->inbound.packet->tid;
	smcp_outbound_begin(self,code,COAP_TRANS_TYPE_ACK);
	self->is_responding = true;

	if(self->is_processing_message)
		smcp_outbound_set_tid(self->inbound.packet->tid);

//	if(self->has_cascade_count) {
//		ret = smcp_outbound_add_option(
//			COAP_HEADER_CASCADE_COUNT,
//			(char*)&self->cascade_count,
//			1
//		);
//	}

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
smcp_outbound_set_tid(coap_transaction_id_t tid) {
	assert(smcp_get_current_instance()->outbound.packet);
	smcp_get_current_instance()->outbound.packet->tid = tid;
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_outbound_set_code(coap_code_t code) {
	smcp_t const self = smcp_get_current_instance();
	if(!self->force_current_outbound_code)
		self->outbound.packet->code = code;
	return SMCP_STATUS_OK;
}

#if SMCP_USE_BSD_SOCKETS
smcp_status_t
smcp_outbound_set_destaddr(
	struct sockaddr *sockaddr, socklen_t socklen
) {
	memcpy(
		&smcp_get_current_instance()->outbound.saddr,
		sockaddr,
		socklen
	);
	smcp_get_current_instance()->outbound.socklen = socklen;

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
smcp_outbound_add_header_(
	coap_option_key_t key, const char* value, size_t len
) {
	smcp_t const self = smcp_get_current_instance();
	uint8_t option_count;

#warning TODO: Check for overflow!

	if(key<self->outbound.last_option_key) {
		assert_printf("Out of order header: %s",coap_option_key_to_cstr(key, self->is_responding));
		return SMCP_STATUS_INVALID_ARGUMENT;
	}

	if(len == HEADER_CSTR_LEN)
		len = strlen(value);

	if(self->outbound.packet->option_count==0xF)
		self->outbound.content_ptr--;	// remove end-of-options marker

	option_count = self->outbound.packet->option_count;

	self->outbound.content_ptr = (char*)coap_encode_option(
		(uint8_t*)self->outbound.content_ptr,
		&option_count,
		self->outbound.last_option_key,
		key,
		(const uint8_t*)value,
		len
	);

	self->outbound.last_option_key = key;
	self->outbound.packet->option_count = MIN(15,option_count);

	if(self->outbound.packet->option_count==0xF)
		*self->outbound.content_ptr++ = 0xF0;  // Add end-of-options marker

	return SMCP_STATUS_OK;
}

static smcp_status_t
smcp_outbound_add_headers_up_to_key_(
	coap_option_key_t key
) {
	smcp_t const self = smcp_get_current_instance();
	if(	self->outbound.last_option_key<COAP_HEADER_TOKEN
		&& key>COAP_HEADER_TOKEN
	) {
		if(	self->is_processing_message
			&& self->is_responding
			&& self->inbound.token_option
		) {
			const uint8_t* value;
			size_t len;
			coap_decode_option(self->inbound.token_option, NULL, &value, &len);
			return smcp_outbound_add_header_(COAP_HEADER_TOKEN,(void*)value,len);
		} else if(self->outbound.packet->code && self->outbound.packet->code<COAP_RESULT_100) {
			return smcp_outbound_add_header_(
				COAP_HEADER_TOKEN,
				(void*)&self->outbound.packet->tid,
				sizeof(self->outbound.packet->tid)
			);
		}
	}
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_outbound_add_option(
	coap_option_key_t key, const char* value, size_t len
) {
	smcp_status_t ret = 0;

	ret = smcp_outbound_add_headers_up_to_key_(key);
	require_noerr(ret, bail);

	ret = smcp_outbound_add_header_(key,value,len);
	require_noerr(ret, bail);

bail:
	return ret;
}

smcp_status_t
smcp_outbound_set_destaddr_from_host_and_port(const char* addr_str,uint16_t toport) {
	smcp_status_t ret = SMCP_STATUS_OK;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
		.sin6_family	= AF_INET6,
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
	};

	struct addrinfo hint = {
#if 0
		.ai_flags		= AI_ADDRCONFIG | AI_ALL | AI_V4MAPPED,
		.ai_family		= AF_INET6,
#else
		.ai_flags		= AI_ADDRCONFIG,
		.ai_family		= AF_UNSPEC,
#endif
	};

	struct addrinfo *results = NULL;
	struct addrinfo *iter = NULL;

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
		memcpy(&saddr, iter->ai_addr, iter->ai_addrlen);
	}
	saddr.sin6_port = toport;

	ret = smcp_outbound_set_destaddr((struct sockaddr *)&saddr,sizeof(struct sockaddr_in6));
	require_noerr(ret, bail);

#elif CONTIKI
	uip_ipaddr_t toaddr;
	memset(&toaddr, 0, sizeof(toaddr));

	DEBUG_PRINTF("Outbound: Dest host [%s]:%d",addr_str,toport);
	toport = htons(toport);

	ret = uiplib_ipaddrconv(
		addr_str,
		&toaddr
	) ? SMCP_STATUS_OK : SMCP_STATUS_HOST_LOOKUP_FAILURE;

#if SMCP_CONF_USE_DNS
	if(ret) {
		uip_ipaddr_t *temp = NULL;
#if RESOLV_SUPPORTS_LOOKUP2_API
		switch(resolv_lookup2(addr_str,&temp)) {
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
#else // RESOLV_SUPPORTS_LOOKUP2_API
		// Fall back for older versions of contiki
		// which don't have the more advanced DNS resolver API.
		temp = resolv_lookup(addr_str);
		if(temp) {
			memcpy(&toaddr, temp, sizeof(uip_ipaddr_t));
			ret = SMCP_STATUS_OK;
		} else {
			resolv_query(addr_str);
			ret = SMCP_STATUS_WAIT_FOR_DNS;
		}
#endif // !RESOLV_SUPPORTS_LOOKUP2_API
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
	smcp_status_t ret = SMCP_STATUS_OK;
	smcp_t const self = smcp_get_current_instance();
	char* proto_str = NULL;
	char* addr_str = NULL;
	char* port_str = NULL;
	char* path_str = NULL;
	char* query_str = NULL;
	char* uri_copy = NULL;
	uint16_t toport = SMCP_DEFAULT_PORT;

	require_action(uri, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	if(!url_is_absolute(uri)) {
		// Pairing with ourselves
		addr_str = "::1";
		toport = smcp_get_port(smcp_get_current_instance());
	} else {
#if HAS_ALLOCA
		uri_copy = alloca(strlen(uri) + 1);
		strcpy(uri_copy, uri);
#else
		uri_copy = strdup(uri);
#endif

		// Parse the URI.
		require_action_string(
			url_parse(
				uri_copy,
				&proto_str,
				NULL,
				NULL,
				&addr_str,
				&port_str,
				&path_str,
				&query_str
			),
			bail,
			ret = SMCP_STATUS_URI_PARSE_FAILURE,
			"Unable to parse URL"
		);

		if(port_str) {
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

	if(	proto_str
		&& !strequal_const(proto_str, "coap")
		&& !strequal_const(proto_str, "smcp")
	) {
		require_action_string(
			self->proxy_url,
			bail,
			ret=SMCP_STATUS_INVALID_ARGUMENT,
			"No proxy URL configured"
		);
		require_action(uri!=self->proxy_url,bail,ret = SMCP_STATUS_INVALID_ARGUMENT);

		ret = smcp_outbound_add_option(COAP_HEADER_PROXY_URI, uri, strlen(uri));
		require_noerr(ret, bail);
		ret = smcp_outbound_set_uri(self->proxy_url,flags);
		goto bail;
	}

	if(!(flags&SMCP_MSG_SKIP_AUTHORITY)) {
		if(addr_str) {
			ret = smcp_outbound_add_option(COAP_HEADER_URI_HOST, addr_str, strlen(addr_str));
			require_noerr(ret, bail);
		}
		if(port_str) {
			toport = htons(toport);
			ret = smcp_outbound_add_option(COAP_HEADER_URI_PORT, (char*)&toport, sizeof(toport));
			toport = ntohs(toport);
			require_noerr(ret, bail);
		}
	}

	if(	!(flags&SMCP_MSG_SKIP_DESTADDR)
		&& addr_str && addr_str[0]!=0
	) {
		ret = smcp_outbound_set_destaddr_from_host_and_port(addr_str,toport); // TODO: Handle port
		require_noerr(ret, bail);
	}

	if(path_str) {
		char* component;

		// Move past any preceding slashes.
		while(path_str[0] == '/')
			path_str++;

		while(url_path_next_component(&path_str,&component)) {
			int len = strlen(component);
			if(len)
				ret = smcp_outbound_add_option(COAP_HEADER_URI_PATH, component, HEADER_CSTR_LEN);
			require_noerr(ret,bail);
		}
	}

	if(query_str) {
		char* key;

		while(url_form_next_value(&query_str,&key,NULL)) {
			int len = strlen(key);
			if(len)
				ret = smcp_outbound_add_option(COAP_HEADER_URI_QUERY, key, len);
			require_noerr(ret,bail);
		}
	}

bail:
#if !HAS_ALLOCA
	free(uri_copy);
#endif
	return ret;
}

smcp_status_t
smcp_outbound_append_content(const char* value,size_t len) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();

	size_t max_len = self->outbound.content_len;
	char* dest;

	if(len==HEADER_CSTR_LEN)
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
		smcp_outbound_add_headers_up_to_key_(200);

	if(max_len)
		*max_len = SMCP_MAX_PACKET_LENGTH-(self->outbound.content_ptr-(char*)self->outbound.packet);

	return self->outbound.content_ptr;
}

smcp_status_t
smcp_outbound_set_content_len(size_t len) {
	smcp_get_current_instance()->outbound.content_len = len;
	DEBUG_PRINTF("Outbound: content length = %d",len);
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_outbound_send() {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();
	const size_t header_len = (smcp_outbound_get_content_ptr(NULL)-(char*)self->outbound.packet);
#if VERBOSE_DEBUG
	DEBUG_PRINTF("Outbound: tt=%d",smcp_get_current_instance()->outbound.packet->tt);
	coap_dump_header(
		SMCP_DEBUG_OUT_FILE,
		"Outbound: ",
		self->outbound.packet,
		header_len
	);
	DEBUG_PRINTF("Outbound: packet length = %d",header_len+smcp_get_current_instance()->outbound.content_len);
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
	uip_udp_conn = smcp_get_current_instance()->udp_conn;
	uip_slen = header_len +
		smcp_get_current_instance()->outbound.content_len;

	uip_process(UIP_UDP_SEND_CONN);

#if UIP_CONF_IPV6
	tcpip_ipv6_output();
#else
	if(uip_len > 0)
		tcpip_output();
#endif
	uip_slen = 0;

	memset(&smcp_get_current_instance()->udp_conn->ripaddr, 0,
		sizeof(uip_ipaddr_t));
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

smcp_status_t
smcp_outbound_set_content_type(coap_content_type_t t) {
	return smcp_outbound_add_option(COAP_HEADER_CONTENT_TYPE, (char*)&t, 1);
}

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

smcp_status_t
smcp_outbound_set_var_content_int(int v) {
	smcp_outbound_set_content_type(SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
//#if SMCP_AVOID_PRINTF
//	smcp_outbound_append_content("v=", HEADER_CSTR_LEN);
//
//#else
	return smcp_outbound_set_content_formatted_const("v=%d",v);
//#endif
}

smcp_status_t
smcp_outbound_set_var_content_unsigned_int(unsigned int v) {
	smcp_outbound_set_content_type(SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	return smcp_outbound_set_content_formatted_const("v=%u",v);
}

smcp_status_t
smcp_outbound_set_var_content_unsigned_long_int(unsigned long int v) {
	smcp_outbound_set_content_type(SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	return smcp_outbound_set_content_formatted_const("v=%ul",v);
}
