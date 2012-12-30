/*	@file smcp_pairing.c
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

#include "assert_macros.h"

#if !SMCP_DEBUG_TIMERS && !VERBOSE_DEBUG
#undef assert_printf
#define assert_printf(fmt, ...) do { } while(0)
#endif

#include "smcp.h"
#include "smcp-logging.h"

#if SMCP_ENABLE_PAIRING

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ll.h"

#include "smcp-pairing.h"
#include "smcp-node.h"
#include "smcp-timer.h"
#include "smcp-internal.h"
#include "smcp-variable_node.h"

#include "smcp-helpers.h"
#include "url-helpers.h"

#pragma mark -
#pragma mark Paring

#define SHOULD_CONFIRM_EVENT_FOR_PAIRING(pairing)		((pairing->flags&SMCP_PARING_FLAG_RELIABILITY_MASK) || !(pairing->seq&0x7))

#define SMCP_PAIRING_CON_EVENT_EXPIRATION	(30*MSEC_PER_SEC)
#define SMCP_PAIRING_NON_EVENT_EXPIRATION	(1*MSEC_PER_SEC)

static smcp_status_t
smcp_pairing_node_request_handler(
	smcp_pairing_node_t	pairing,
	smcp_method_t	method
);

static smcp_status_t
smcp_pairing_node_variable_func(
	smcp_pairing_node_t		pairing,
	uint8_t action,
	uint8_t i,
	char* value
);

static smcp_status_t
smcp_pairing_path_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
);


smcp_status_t
smcp_pair_inbound_observe_update() {
	smcp_status_t ret = SMCP_STATUS_OK;
	smcp_t const self = smcp_get_current_instance();

	if(self->inbound.is_fake || self->inbound.is_dupe) {
		goto bail;
	}


	if(self->inbound.has_observe_option) {
		const char* path = NULL;
		char* uri = NULL;
		smcp_node_t path_node = NULL;
		smcp_pairing_node_t pairing = NULL;

		path = smcp_inbound_get_path(NULL,0); // path must be free()'d after this!

		require_action_string(path && path[0], bail, (free((void*)path),ret = SMCP_STATUS_INVALID_ARGUMENT),"Trying to observe bad path");

		DEBUG_PRINTF("Adding observer to \"%s\" . . .",path);

		while(path[0] == '/' && path[1] != 0) path++;

		path_node = smcp_node_find(
			self->root_pairing_node,
			path,
			strlen(path)
		);

		if(!path_node) {
			DEBUG_PRINTF("Can't find existing node for \"%s\", Making a new one . . .",path);
			path_node = smcp_node_alloc();
			require_action(path_node!=NULL, bail, { free((void*)path); ret = SMCP_STATUS_MALLOC_FAILURE; });
			path_node = smcp_node_init(path_node, self->root_pairing_node, path); // we will free path later now.
			path_node->request_handler = &smcp_pairing_path_request_handler;
		} else {
			DEBUG_PRINTF("Found existing node (%s), usng it.",path_node->name);
			free((void*)path);
			path = path_node->name;
		}

		require_action(path_node!=NULL, bail, ret = SMCP_STATUS_FAILURE);

		pairing = calloc(1, sizeof(*pairing));
		require_action(pairing, bail, ret = SMCP_STATUS_MALLOC_FAILURE);

		pairing->node.node.finalize = (void*)&free;

		ret = smcp_start_async_response(&pairing->async_response,SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK);
		require_string(ret==0,bail,smcp_status_to_cstr(ret));

		{
			char token_str[COAP_MAX_TOKEN_SIZE*2+2+1];
			int i;
			token_str[0]='o';
			token_str[1]='-';
			for(i=0;i<pairing->async_response.request.header.token_len;i++)
				sprintf(token_str+i*2+2,"%02x",pairing->async_response.request.header.token[i]);
			uri=strdup(token_str);
		}
		DEBUG_PRINTF("\"%s\" -> \"%s\"",path,uri);

		if(smcp_node_find(path_node, uri, strlen(uri))) {
			free(uri);
			DEBUG_PRINTF("Pairing already found...!");
			ret = smcp_outbound_add_option_uint(COAP_OPTION_OBSERVE, pairing->seq);
			goto bail;
		}

		pairing = (void*)smcp_variable_node_init(&pairing->node, path_node, uri);

		require_action(pairing!=NULL,bail,{ free(uri); ret = SMCP_STATUS_FAILURE;});

		pairing->node.node.request_handler = (smcp_inbound_handler_func)&smcp_pairing_node_request_handler;
		pairing->node.func = (smcp_variable_node_func)&smcp_pairing_node_variable_func;

		pairing->flags = SMCP_PARING_FLAG_OBSERVE;
//		pairing->content_type = COAP_CONTENT_TYPE_UNKNOWN;

		if(self->inbound.packet->tt==COAP_TRANS_TYPE_CONFIRMABLE)
			pairing->flags |= SMCP_PARING_FLAG_RELIABILITY_ASAP;
		else
			pairing->flags |= SMCP_PARING_FLAG_RELIABILITY_NONE;

#if SMCP_CONF_USE_SEQ
//#if DEBUG
		pairing->seq = pairing->ack = 0;
//#else
//		pairing->seq = pairing->ack = SMCP_FUNC_RANDOM_UINT32();
//#endif
		ret = smcp_outbound_add_option_uint(COAP_OPTION_OBSERVE, pairing->seq);
#else
		ret = smcp_outbound_add_option_uint(COAP_OPTION_OBSERVE, 0);
#endif
	} else {
//		// Look up and remove the pairing if it exists.
//		const char* path = NULL;
//		char* uri = NULL;
//		smcp_node_t path_node = NULL;
//		smcp_pairing_node_t pairing = NULL;
//
//		path = smcp_inbound_get_path(NULL);
//		require(path && path[0], bail);
//
//		while(path[0] == '/' && path[1] != 0) path++;
//
//		path_node = smcp_node_find(
//			self->root_pairing_node,
//			path,
//			strlen(path)
//		);
//
//		free((void*)path);
//
//		if(!path_node) {
//			return 0;
//		}
//
//		path = path_node->name;
//
//		{
//			char token_str[COAP_MAX_TOKEN_SIZE*2+2+1];
//			int i;
//			token_str[0]='o';
//			token_str[1]='-';
//			for(i=0;i<pairing->async_response.token_len;i++)
//				sprintf(token_str+i*2+2,"%02x",pairing->async_response.token_value[i]);
//			uri=strdup(token_str);
//		}
//
//		pairing = (smcp_pairing_node_t)smcp_node_find(path_node, uri, strlen(uri));
//
//		if(pairing) {
//			DEBUG_PRINTF("Removing observer from \"%s\" . . .",path);
//			smcp_delete_pairing(pairing);
//		}
//
//		free(uri);
	}

bail:
	return ret;
}

#if !SMCP_CONF_OBSERVING_ONLY
smcp_status_t
smcp_pair_with_sockaddr(
	smcp_t	self,
	const char*		path,
	const char*		uri,
	SMCP_SOCKET_ARGS,
	int				flags,
	uintptr_t*		idVal
) {
	smcp_status_t ret = SMCP_STATUS_OK;
	SMCP_EMBEDDED_SELF_HOOK;

	smcp_node_t path_node = NULL;
	smcp_pairing_node_t pairing = NULL;

	require_action(path, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(uri, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	while(path[0] == '/' && path[1] != 0) path++;

	path_node = smcp_node_find(
		self->root_pairing_node,
		path,
		strlen(path)
	);

	if(!path_node) {
		path_node = smcp_node_alloc();
		require_action(path_node, bail, ret = SMCP_STATUS_MALLOC_FAILURE);
		path_node = smcp_node_init(path_node, self->root_pairing_node, strdup(path));
		path_node->request_handler = &smcp_pairing_path_request_handler;
	}

	require_action(path_node, bail, ret = SMCP_STATUS_FAILURE);

	pairing = calloc(1, sizeof(*pairing));

	require_action(pairing, bail, ret = SMCP_STATUS_MALLOC_FAILURE);

	pairing->node.node.finalize = (void*)&free;

	smcp_variable_node_init(&pairing->node, path_node, strdup(uri));

	pairing->node.node.request_handler = (smcp_inbound_handler_func)&smcp_pairing_node_request_handler;
	pairing->node.func = (smcp_variable_node_func)&smcp_pairing_node_variable_func;

	pairing->flags = flags;

//	pairing->content_type = COAP_CONTENT_TYPE_UNKNOWN;

#if SMCP_USE_BSD_SOCKETS
	if(saddr)
		memcpy(&pairing->saddr,saddr,sizeof(pairing->saddr));
#elif CONTIKI
	if(toaddr) {
		memcpy(&pairing->toaddr,toaddr,sizeof(pairing->toaddr));
		pairing->toport = toport;
	}
#endif

	if(idVal)
		*idVal = (uintptr_t)pairing;

#if SMCP_CONF_USE_SEQ
#if DEBUG
	pairing->seq = pairing->ack = 0;
#else
	pairing->seq = pairing->ack = SMCP_FUNC_RANDOM_UINT32();
#endif
	assert(pairing->seq == pairing->ack);
#endif

bail:
	return ret;
}

smcp_status_t
smcp_pair_with_uri(
	smcp_t	self,
	const char*		path,
	const char*		uri,
	int				flags,
	uintptr_t*		idVal
) {
	SMCP_EMBEDDED_SELF_HOOK;
#if SMCP_USE_BSD_SOCKETS
	return smcp_pair_with_sockaddr(self, path, uri, NULL, 0, flags, idVal);
#elif CONTIKI
	return smcp_pair_with_sockaddr(self, path, uri, 0, 0, flags, idVal);
#else
	return SMCP_STATUS_NOT_IMPLEMENTED;
#endif
}
#endif //!SMCP_CONF_OBSERVING_ONLY


smcp_pairing_node_t
smcp_get_first_pairing_for_path(
	smcp_t self, const char* path
) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_pairing_node_t ret = NULL;
	smcp_node_t path_node = NULL;

	assert(self->root_pairing_node!=NULL);

	// Remove all preceeding slashes
	while(path[0] == '/' && path[1] != 0) path++;

	path_node = smcp_node_find(
		self->root_pairing_node,
		path,
		strlen(path)
	);

	require_quiet(path_node,bail);
	require_quiet(path_node->children,bail);

	ret = bt_first(path_node->children);

bail:
	return ret;
}

smcp_pairing_node_t
smcp_next_pairing(
	smcp_pairing_node_t pairing
) {
	smcp_pairing_node_t ret = NULL;

	require(pairing != NULL, bail);

	ret = bt_next((void*)pairing);

bail:
	return ret;
}

static smcp_status_t
smcp_retry_custom_event(smcp_pairing_node_t pairing) {
	smcp_status_t status;
	const smcp_t const self = smcp_get_current_instance();
	smcp_event_tracker_t event = pairing->currentEvent;

	coap_content_type_t content_type;
	if(event->contentFetcher) {
		status = (*event->contentFetcher)(
			event->contentFetcherContext,
			NULL,
			NULL,
			&content_type
		);
		require_noerr(status,bail);
	}

	if(pairing->flags & SMCP_PARING_FLAG_OBSERVE) {
		status = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		require_noerr(status,bail);

		status = smcp_outbound_set_async_response(&pairing->async_response);
		require_noerr(status,bail);

		if(event->contentFetcher) {
			status = smcp_outbound_set_content_type(content_type);
			check_noerr(status);
		}

#if SMCP_CONF_USE_SEQ
		status = smcp_outbound_add_option_uint(COAP_OPTION_OBSERVE, pairing->seq);
#else
		status = smcp_outbound_add_option_uint(COAP_OPTION_OBSERVE, 0);
#endif
		require_noerr(status,bail);

		self->outbound.packet->tt = SHOULD_CONFIRM_EVENT_FOR_PAIRING(pairing)?COAP_TRANS_TYPE_CONFIRMABLE:COAP_TRANS_TYPE_NONCONFIRMABLE;

#if !SMCP_CONF_OBSERVING_ONLY
	} else {
		status = smcp_outbound_begin(
			self,
			COAP_METHOD_POST,
			SHOULD_CONFIRM_EVENT_FOR_PAIRING(pairing)?COAP_TRANS_TYPE_CONFIRMABLE:COAP_TRANS_TYPE_NONCONFIRMABLE
		);
		require_noerr(status,bail);

#if SMCP_USE_BSD_SOCKETS
		if(((struct sockaddr*)&pairing->saddr)->sa_family)
			status = smcp_outbound_set_destaddr((struct sockaddr*)&pairing->saddr, sizeof(pairing->saddr));
#elif CONTIKI
		if(pairing->toport)
			status = smcp_outbound_set_destaddr(&pairing->toaddr,pairing->toport);
#endif
		require_noerr(status,bail);

		status = smcp_outbound_set_uri(smcp_pairing_get_uri_cstr(pairing),0);
		require_noerr(status,bail);

		status = smcp_outbound_add_option(SMCP_OPTION_ORIGIN, smcp_pairing_get_path_cstr(pairing), HEADER_CSTR_LEN);
		require_noerr(status,bail);

//#if SMCP_CONF_USE_SEQ
//		char cseq[24];
//#if __AVR__
//		snprintf_P(
//			cseq,
//			sizeof(cseq),
//			PSTR("%lX POST"),
//			(long unsigned int)pairing->seq
//		);
//#else
//		snprintf(cseq,
//			sizeof(cseq),
//			"%lX POST",
//			(long unsigned int)pairing->seq
//		);
//#endif
//		status = smcp_outbound_add_option(SMCP_OPTION_CSEQ, cseq, HEADER_CSTR_LEN);
//		require_noerr(status,bail);
//#endif
#endif // !SMCP_CONF_OBSERVING_ONLY
	}

	if(event->contentFetcher) {
		size_t len = 0;
		char* ptr;

		ptr = smcp_outbound_get_content_ptr(&len);
		event->contentFetcher(
			event->contentFetcherContext,
			ptr,
			&len,
			&content_type
		);
		smcp_outbound_set_content_len(len);
	}

	status = smcp_outbound_send();
	require_noerr(status,bail);

#if SMCP_CONF_PAIRING_STATS
	pairing->send_count++;
#endif

bail:
	return status;
}

static void
smcp_event_tracker_release(smcp_event_tracker_t event) {
	assert(event!=NULL);
	DEBUG_PRINTF("Event:%p: release",event);
	DEBUG_PRINTF("Event:%p: refCount = %d",event,event->refCount-1);
	if(0==--event->refCount) {
		DEBUG_PRINTF("Event:%p: dealloc\n",event);
		if(event->contentFetcher)
			(*event->contentFetcher)(
				event->contentFetcherContext,
				NULL,
				NULL,
				NULL
			);
		free(event);
	}
}

static smcp_status_t
smcp_event_response_handler(
	int statuscode, smcp_pairing_node_t pairing
) {
	DEBUG_PRINTF("Pairing:%p: smcp_event_response_handler(): statuscode=%d",pairing,statuscode);

	if(statuscode==SMCP_STATUS_TIMEOUT) {
		if(SHOULD_CONFIRM_EVENT_FOR_PAIRING(pairing)) {
			if(pairing->flags&SMCP_PARING_FLAG_OBSERVE)
				statuscode = SMCP_STATUS_RESET;
		} else {
			statuscode = SMCP_STATUS_OK;
		}
	}

	if(statuscode!=SMCP_STATUS_TRANSACTION_INVALIDATED) {
		if(statuscode && ((statuscode < COAP_RESULT_200) || (statuscode >= COAP_RESULT_400))) {
			// Looks like we failed to live up to this pairing.
#if SMCP_CONF_PAIRING_STATS
			pairing->errors++;
#endif
			if(	(pairing->flags & SMCP_PARING_FLAG_OBSERVE)
#if SMCP_CONF_PAIRING_STATS
				&& (pairing->errors>=10)
#endif
			) {
				DEBUG_PRINTF("Event:%p: Too many errors!\n",pairing);
				statuscode = SMCP_STATUS_RESET;
			}
			if(statuscode==SMCP_STATUS_RESET && (pairing->flags&SMCP_PARING_FLAG_OBSERVE)) {
				smcp_delete_pairing(pairing);
				return SMCP_STATUS_OK;
			}
#if SMCP_CONF_PAIRING_STATS
			smcp_trigger_event_with_node(
				smcp_get_current_instance(),
				&pairing->node.node,
				"ec"
			);
#endif
		}
#if SMCP_CONF_PAIRING_STATS
		if(pairing->last_error != statuscode) {
			pairing->last_error = statuscode;
			smcp_trigger_event_with_node(
				smcp_get_current_instance(),
				&pairing->node.node,
				"err"
			);
		}
#endif
	}

#if SMCP_CONF_USE_SEQ
	if(!statuscode || ((statuscode >= COAP_RESULT_200) && (statuscode < COAP_RESULT_400)))
		pairing->ack = pairing->seq;
#endif

	// expire the event.
	{
		smcp_event_tracker_t event = pairing->currentEvent;
		pairing->currentEvent = NULL;
		smcp_event_tracker_release(event);
	}
	return SMCP_STATUS_OK;
}

static smcp_status_t
smcp_retry_event(smcp_pairing_node_t pairing) {
	smcp_status_t status;
	const smcp_t const self = smcp_get_current_instance();
	char* original_path = NULL;
	struct coap_header_s* packet;

	if(pairing->flags & SMCP_PARING_FLAG_OBSERVE) {
		status = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		require_noerr(status,bail);

		status = smcp_outbound_set_async_response(&pairing->async_response);
		require_noerr(status,bail);

#if SMCP_CONF_USE_SEQ
		status = smcp_outbound_add_option_uint(
			COAP_OPTION_OBSERVE,
			pairing->seq
		);
#else
		status = smcp_outbound_add_option_uint(
			COAP_OPTION_OBSERVE,
			0
		);
#endif
		require_noerr(status,bail);

		self->outbound.packet->tt = SHOULD_CONFIRM_EVENT_FOR_PAIRING(pairing)?COAP_TRANS_TYPE_CONFIRMABLE:COAP_TRANS_TYPE_NONCONFIRMABLE;

		self->inbound.has_observe_option = true;
		self->is_responding = true;
		self->force_current_outbound_code = true;
#if !SMCP_CONF_OBSERVING_ONLY
	} else {
		status = smcp_outbound_begin(
			self,
			COAP_METHOD_POST,
			SHOULD_CONFIRM_EVENT_FOR_PAIRING(pairing)?COAP_TRANS_TYPE_CONFIRMABLE:COAP_TRANS_TYPE_NONCONFIRMABLE
		);
		require_noerr(status,bail);
		self->is_responding = true;
		self->force_current_outbound_code = true;

#if SMCP_USE_BSD_SOCKETS
		if(((struct sockaddr*)&pairing->saddr)->sa_family)
			status = smcp_outbound_set_destaddr((struct sockaddr*)&pairing->saddr, sizeof(pairing->saddr));
#elif CONTIKI
		if(pairing->toport)
			status = smcp_outbound_set_destaddr(&pairing->toaddr,pairing->toport);
#endif
		require_noerr(status,bail);

		status = smcp_outbound_set_uri(smcp_pairing_get_uri_cstr(pairing),0);
		require_noerr(status,bail);

		status = smcp_outbound_add_option(
			SMCP_OPTION_ORIGIN,
			smcp_pairing_get_path_cstr(pairing),
			HEADER_CSTR_LEN
		);
		require_noerr(status,bail);

//#if SMCP_CONF_USE_SEQ
//		char cseq[24];
//#if __AVR__
//		snprintf_P(
//			cseq,
//			sizeof(cseq),
//			PSTR("%lX POST"),
//			(long unsigned int)pairing->seq
//		);
//#else
//		snprintf(cseq,
//			sizeof(cseq),
//			"%lX POST",
//			(long unsigned int)pairing->seq
//		);
//#endif // !__AVR__
//		status = smcp_outbound_add_option(SMCP_OPTION_CSEQ, cseq, HEADER_CSTR_LEN);
//		require_noerr(status,bail);
//#endif // SMCP_CONF_USE_SEQ
#endif // !SMCP_CONF_OBSERVING_ONLY

#if HAVE_ALLOCA
	packet = alloca(4+strlen(smcp_pairing_get_path_cstr(pairing))+5);
#else
	{
		static char i_really_wish_we_supported_alloca[4+SMCP_MAX_PATH_LENGTH+5];
		packet = (struct coap_header_s*)i_really_wish_we_supported_alloca;
	}
#endif

	// Start building a fake packet.
	packet->code = COAP_METHOD_GET;
	packet->tt = SHOULD_CONFIRM_EVENT_FOR_PAIRING(pairing)?COAP_TRANS_TYPE_CONFIRMABLE:COAP_TRANS_TYPE_NONCONFIRMABLE;
	packet->version = COAP_VERSION;
	packet->token_len = 0;
	self->inbound.packet = packet;
	self->inbound.content_len = 0;
	self->inbound.content_ptr = NULL;
	self->inbound.last_option_key = 0;
	self->inbound.is_fake = true;

	{
		uint8_t* option = packet->token+packet->token_len;
		coap_option_key_t prev_key = 0;
//		uint8_t option_count = 0;
		char* component = NULL;
		char* path = strdup(smcp_pairing_get_path_cstr(pairing));

		original_path = path;

		// TODO: Handle query, too!

		while(url_path_next_component(&path, &component)) {
			DEBUG_PRINTF("Pushing path component \"%s\"",component);
			option = coap_encode_option(
				option,
				prev_key,
				COAP_OPTION_URI_PATH,
				(uint8_t*)component,
				strlen(component)
			);
			prev_key = COAP_OPTION_URI_PATH;
		}
//		*option++ = 0xFF;

		self->inbound.content_ptr = (char*)option;
		self->inbound.packet_len = (char*)option - (char*)packet;

//		if(pairing->content_type != COAP_CONTENT_TYPE_UNKNOWN) {
//
//		}

	}

	self->inbound.this_option = self->inbound.packet->token+self->inbound.packet->token_len;
	}

	self->is_processing_message = true;
	self->did_respond = false;

#if VERBOSE_DEBUG
	coap_dump_header(
		SMCP_DEBUG_OUT_FILE,
		"FAKE Inbound:\t",
		self->inbound.packet,
		self->inbound.packet_len
	);
#endif

//	self->inbound.options_left = self->inbound.packet->option_count;
	status = smcp_handle_request(self);
	require(!status||status==SMCP_STATUS_NOT_FOUND||status==SMCP_STATUS_NOT_ALLOWED,bail);

	if(status) {
		smcp_outbound_set_content_len(0);
		smcp_outbound_send();
	}

#if SMCP_CONF_PAIRING_STATS
	pairing->send_count++;
#endif

bail:
	self->is_processing_message = false;
	self->did_respond = false;
	free(original_path);
	return status;
}

smcp_status_t
smcp_trigger_event(
	smcp_t self,
	const char* path
) {
	smcp_status_t ret = 0;
	smcp_pairing_node_t iter;
	smcp_event_tracker_t event = NULL;
	SMCP_EMBEDDED_SELF_HOOK;

	require_action(self!=NULL,bail,ret=SMCP_STATUS_BAD_ARGUMENT);

	if(!path) path = "";

	// Move past any preceding slashes.
	while(path && path[0] == '/' && path[1] == 0) path++;

	for(iter = smcp_get_first_pairing_for_path(self, path);
	    iter;
	    iter = smcp_next_pairing(iter)
	) {
		smcp_status_t status;

		iter->seq++;

		if(iter->currentEvent) {
			DEBUG_PRINTF("Event:%p: Previous event, %p, is still around!",event,iter->currentEvent);

			// Tickle the existing transaction to make it send again.
			smcp_transaction_tickle(self, &iter->transaction);
			continue;
		}

		if(!event) {
			// Allocate this lazily.
			event = calloc(1,sizeof(*event));

			require_action(event!=NULL, bail, ret=SMCP_STATUS_MALLOC_FAILURE);

			// This is just a placeholder event.
			event->contentFetcher = NULL;
			event->contentFetcherContext = NULL;
			event->refCount = 1;
			DEBUG_PRINTF("Event:%p: alloc",event);
		}

		event->seq = iter->seq;

		smcp_transaction_init(
			&iter->transaction,
			0, // Flags
			(void*)&smcp_retry_event,
			(void*)&smcp_event_response_handler,
			(void*)iter
		);

		status = smcp_transaction_begin(
			self,
			&iter->transaction,
			SHOULD_CONFIRM_EVENT_FOR_PAIRING(iter)?SMCP_PAIRING_CON_EVENT_EXPIRATION:SMCP_PAIRING_NON_EVENT_EXPIRATION
		);

		if(status)
			continue;

		iter->currentEvent = event;
		event->refCount++;
		DEBUG_PRINTF("Event:%p: retain",event);

#if SMCP_CONF_PAIRING_STATS
		// TODO: Trigger an event on the fire count, too?
		iter->fire_count++;
#endif
	}

bail:
	if(event)
		smcp_event_tracker_release(event);
	return ret;
}

smcp_status_t
smcp_trigger_event_with_node(
	smcp_t		self,
	smcp_node_t			node,
	const char*			subpath
) {
	char path[SMCP_MAX_PATH_LENGTH + 1];

	path[sizeof(path) - 1] = 0;

	smcp_node_get_path(node, path, sizeof(path));

	if(subpath) {
		if(path[0])
			strlcat(path, "/", sizeof(path));
		strlcat(path, subpath, sizeof(path));
	}

	{   // Remove trailing slashes.
		size_t len = strlen(path);
		while(len && path[len - 1] == '/')
			path[--len] = 0;
	}

	return smcp_trigger_event(
		self,
		path
	);
}

smcp_status_t
smcp_trigger_custom_event(
	smcp_t		self,
	const char*			path,
	smcp_content_fetcher_func contentFetcher,
	void* context
) {
	smcp_status_t ret = 0;
	smcp_pairing_node_t iter;
	smcp_event_tracker_t event = NULL;
	SMCP_EMBEDDED_SELF_HOOK;

	if(!path) path = "";

	// Move past any preceding slashes.
	while(path && *path == '/') path++;

	for(iter = smcp_get_first_pairing_for_path(self, path);
	    iter;
	    iter = smcp_next_pairing(iter)
	) {
		smcp_status_t status;
		if(!event) {
			// Allocate this lazily.
			event = calloc(1,sizeof(*event));

			require_action(event!=NULL, bail, ret=SMCP_STATUS_MALLOC_FAILURE);

			event->contentFetcher = contentFetcher;
			event->contentFetcherContext = context;
			event->refCount = 1;
			DEBUG_PRINTF("Event:%p: alloc",event);
		}

		if(iter->currentEvent) {
			DEBUG_PRINTF("Event:%p: Previous event, %p, is still around!",event,iter->currentEvent);
			smcp_transaction_end(self, &iter->transaction);
		}

#if SMCP_CONF_USE_SEQ
		iter->seq++;
		event->seq = iter->seq;
#endif

		smcp_transaction_init(
			&iter->transaction,
			0, // Flags
			(void*)&smcp_retry_custom_event,
			(void*)&smcp_event_response_handler,
			(void*)iter
		);

		status = smcp_transaction_begin(
			self,
			&iter->transaction,
			SHOULD_CONFIRM_EVENT_FOR_PAIRING(iter)?SMCP_PAIRING_CON_EVENT_EXPIRATION:SMCP_PAIRING_NON_EVENT_EXPIRATION
		);

		if(status)
			continue;

		iter->currentEvent = event;
		event->refCount++;
		DEBUG_PRINTF("Event:%p: retain",event);

#if SMCP_CONF_PAIRING_STATS
		iter->fire_count++;
#endif
	}

bail:
	if(event)
		smcp_event_tracker_release(event);
	return ret;
}

smcp_status_t
smcp_trigger_custom_event_with_node(
	smcp_node_t			node,
	const char*			subpath,
	smcp_content_fetcher_func contentFetcher,
	void* context
) {
	smcp_t const self = (smcp_t)smcp_node_get_root(node);
	char path[SMCP_MAX_PATH_LENGTH + 1];

	path[sizeof(path) - 1] = 0;

	smcp_node_get_path(node, path, sizeof(path));

	if(subpath) {
		if(path[0])
			strlcat(path, "/", sizeof(path));
		strlcat(path, subpath, sizeof(path));
	}

	{   // Remove trailing slashes.
		size_t len = strlen(path);
		while(len && path[len - 1] == '/')
			path[--len] = 0;
	}

	return smcp_trigger_custom_event(
		self,
		path,
		contentFetcher,
		context
	);
}

extern smcp_status_t
smcp_delete_pairing(smcp_pairing_node_t pairing) {
	smcp_node_t parent = (smcp_node_t)pairing->node.node.parent;
	smcp_t const self = (smcp_t)smcp_node_get_root(&pairing->node.node);
	char* name = (char*)pairing->node.node.name;

	DEBUG_PRINTF("%s: %p \"%s\"",__func__,pairing,pairing->node.node.name);

	if(pairing->flags&SMCP_PARING_FLAG_OBSERVE)
		smcp_finish_async_response(&pairing->async_response);

	if(pairing->currentEvent)
		smcp_event_tracker_release(pairing->currentEvent);
	smcp_transaction_end(self,&pairing->transaction);
	smcp_node_delete(&pairing->node.node);
	free(name);
	if(parent && !parent->children) {
		free((char*)parent->name);
		smcp_node_delete(parent);
	}
	return SMCP_STATUS_OK;
}

#pragma mark -
#pragma mark Pairing Node Interface

static smcp_status_t
smcp_pairing_path_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;

#if !SMCP_CONF_OBSERVING_ONLY
	smcp_t const self = smcp_get_current_instance();
	uintptr_t idVal;
	if(	method == COAP_METHOD_POST
		|| method == COAP_METHOD_PUT
	) {
		const char* value = NULL;
		size_t value_len;
#if HAVE_ALLOCA
		char* path = NULL;
		char* uri = NULL;
#else
		static char path[SMCP_MAX_PATH_LENGTH];
		static char uri[SMCP_MAX_URI_LENGTH];
#endif
		if(node == self->root_pairing_node) {
			require(
				COAP_OPTION_URI_PATH==smcp_inbound_next_option((const uint8_t**)&value, &value_len),
				bail
			);
#if HAVE_ALLOCA
			path = alloca(value_len+1);
#endif
			memcpy(path,value,value_len);
			path[value_len] = 0;

		} else if(node->parent == self->root_pairing_node) {
#if HAVE_ALLOCA
			path = (char*)node->name;
#else
			strcpy(path,(char*)node->name);
#endif
		}
		if(node->parent == self->root_pairing_node || node == self->root_pairing_node) {
			require_action(
				COAP_OPTION_URI_PATH==smcp_inbound_next_option((const uint8_t**)&value, &value_len),
				bail,
				ret = SMCP_STATUS_NOT_ALLOWED
			);
#if HAVE_ALLOCA
			uri = alloca(value_len+1);
#endif
			memcpy(uri,value,value_len);
			uri[value_len] = 0;
		}

		require_string(uri!=NULL,bail,"URI must be set by this point");

		ret = smcp_pair_with_uri(
			self,
			path,
			uri,
			SMCP_PARING_FLAG_RELIABILITY_PART,
			&idVal
		);

		smcp_outbound_begin_response(COAP_RESULT_201_CREATED);
		smcp_outbound_add_option(COAP_OPTION_LOCATION_PATH, self->root_pairing_node->name, HEADER_CSTR_LEN);
		smcp_outbound_add_option(COAP_OPTION_LOCATION_PATH, path, HEADER_CSTR_LEN);
		smcp_outbound_add_option(COAP_OPTION_LOCATION_PATH, uri, HEADER_CSTR_LEN);
		smcp_outbound_send();
	} else
#endif // !SMCP_CONF_OBSERVING_ONLY
	ret = smcp_default_request_handler(node, method);

bail:
	return ret;
}

static smcp_status_t
smcp_pairing_node_variable_func(
	smcp_pairing_node_t		pairing,
	uint8_t action,
	uint8_t path,
	char* value
) {
	smcp_status_t ret = 0;
	enum {
#if !SMCP_CONF_OBSERVING_ONLY
		PATH_DEST_URI,
#endif // !SMCP_CONF_OBSERVING_ONLY
		PATH_FLAGS,
#if SMCP_CONF_PAIRING_STATS
		PATH_FIRE_COUNT,
		PATH_SEND_COUNT,
		PATH_ERROR_COUNT,
		PATH_LAST_ERROR,
#endif
#if SMCP_CONF_USE_SEQ
		PATH_SEQ,
		PATH_ACK,
#endif
		PATH_COUNT
	};

	//printf("timer_node_var_func: action=%d path=%d\n",action,path);

	if(path>=PATH_COUNT) {
		ret = SMCP_STATUS_NOT_FOUND;
	} else if(action==SMCP_VAR_GET_KEY) {
		static const char* path_names[] = {
#if !SMCP_CONF_OBSERVING_ONLY
			[PATH_DEST_URI] = "d",
#endif // #if !SMCP_CONF_OBSERVING_ONLY
			[PATH_FLAGS] = "f",
#if SMCP_CONF_PAIRING_STATS
			[PATH_FIRE_COUNT] = "fc",
			[PATH_SEND_COUNT] = "tx",
			[PATH_ERROR_COUNT] = "ec",
			[PATH_LAST_ERROR] = "err",
#endif
#if SMCP_CONF_USE_SEQ
			[PATH_SEQ] = "seq",
			[PATH_ACK] = "ack",
#endif
		};
		strncpy(value,path_names[path],SMCP_VARIABLE_MAX_KEY_LENGTH);
	} else if(action==SMCP_VAR_GET_LF_TITLE) {
		static const char* path_names[] = {
#if !SMCP_CONF_OBSERVING_ONLY
			[PATH_DEST_URI] = "destURI",
#endif
			[PATH_FLAGS] = "flags",
#if SMCP_CONF_PAIRING_STATS
			[PATH_FIRE_COUNT] = "fireCount",
			[PATH_SEND_COUNT] = "sendCount",
			[PATH_ERROR_COUNT] = "errorCount",
			[PATH_LAST_ERROR] = NULL,
#endif
#if SMCP_CONF_USE_SEQ
			[PATH_SEQ] = NULL,
			[PATH_ACK] = NULL,
#endif
		};
		if(path_names[path])
			strcpy(value,path_names[path]);
#if SMCP_CONF_PAIRING_STATS
		else if(path==PATH_LAST_ERROR)
			strcpy(value,(pairing->last_error>0)?coap_code_to_cstr(pairing->last_error):smcp_status_to_cstr(pairing->last_error));
#endif
		else
			return SMCP_STATUS_NOT_ALLOWED;
	} else if(action==SMCP_VAR_GET_VALUE) {
		int v;
		if(path==PATH_FLAGS) {
			v = pairing->flags;
#if !SMCP_CONF_OBSERVING_ONLY
		} else if(path==PATH_DEST_URI) {
			strncpy(value,smcp_pairing_get_uri_cstr(pairing),SMCP_VARIABLE_MAX_VALUE_LENGTH);
			return 0;
#endif
#if SMCP_CONF_USE_SEQ
		} else if(path==PATH_SEQ) {
			v = pairing->seq;
		} else if(path==PATH_ACK) {
			v = pairing->ack;
#endif
#if SMCP_CONF_PAIRING_STATS
		} else if(path==PATH_FIRE_COUNT) {
			v = pairing->fire_count;
		} else if(path==PATH_SEND_COUNT) {
			v = pairing->send_count;
		} else if(path==PATH_ERROR_COUNT) {
			v = pairing->errors;
		} else if(path==PATH_LAST_ERROR) {
			v = pairing->last_error;
#endif
		}
		sprintf(value,"%d",v);
	} else if(action==SMCP_VAR_SET_VALUE) {
		// TODO: Writeme!
		ret = SMCP_STATUS_NOT_ALLOWED;
	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

	return ret;
}

static smcp_status_t
smcp_pairing_node_request_handler(
	smcp_pairing_node_t		pairing,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;

	if(method == COAP_METHOD_DELETE) {
		if(smcp_inbound_next_option(NULL, NULL)!=COAP_OPTION_URI_PATH) {
			ret = smcp_delete_pairing(pairing);
			require_noerr(ret, bail);
			smcp_outbound_begin_response(COAP_RESULT_202_DELETED);
			ret = smcp_outbound_send();
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else {
		ret = smcp_variable_request_handler(&pairing->node, method);
	}

bail:
	return ret;
}

smcp_root_pairing_node_t smcp_pairing_init(
	smcp_node_t parent, const char* name
) {
	smcp_t const self = (smcp_t)smcp_node_get_root(parent);
	if(!name)
		name = SMCP_PAIRING_DEFAULT_ROOT_PATH;
	require((self->root_pairing_node = smcp_node_init(NULL, parent, name)), bail);
	self->root_pairing_node->request_handler = &smcp_pairing_path_request_handler;

bail:
	return self->root_pairing_node;
}

#endif // #if SMCP_ENABLE_PAIRING
