/*
 *  smcp_pairing.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/31/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert_macros.h"

#if !SMCP_DEBUG_TIMERS && !VERBOSE_DEBUG
#undef assert_printf
#define assert_printf(fmt, ...) do { } while(0)
#endif

#include "smcp.h"
#include "smcp_logging.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ll.h"

#if SMCP_USE_BSD_SOCKETS
#include <netdb.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#elif CONTIKI
#include "resolv.h"
#endif

#include "smcp_pairing.h"
#include "smcp_node.h"
#include "smcp_timer.h"
#include "smcp_internal.h"

#include "smcp_variable_node.h"

#include "smcp_helpers.h"
#include "url-helpers.h"

#pragma mark -
#pragma mark Macros

#pragma mark -
#pragma mark Paring

static smcp_status_t
smcp_pairing_node_request_handler(
	smcp_pairing_node_t	pairing,
	smcp_method_t	method
);

smcp_status_t
smcp_daemon_pair_with_sockaddr(
	smcp_daemon_t	self,
	const char*		path,
	const char*		uri,
	SMCP_SOCKET_ARGS,
	int				flags,
	uintptr_t*		idVal
) {
	smcp_status_t ret = SMCP_STATUS_OK;

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
		path_node = smcp_node_init(path_node, self->root_pairing_node, path);
	}

	require_action(path_node, bail, ret = SMCP_STATUS_FAILURE);

	pairing = calloc(1, sizeof(*pairing));

	require_action(pairing, bail, ret = SMCP_STATUS_MALLOC_FAILURE);
	
	smcp_node_init(&pairing->node, path_node, uri);

	pairing->node.request_handler = &smcp_pairing_node_request_handler;

	pairing->flags = flags;

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

#if DEBUG
	pairing->seq = pairing->ack = 0;
#else
	pairing->seq = pairing->ack = SMCP_FUNC_RANDOM_UINT32();
#endif

	assert(pairing->seq == pairing->ack);

bail:
	return ret;
}

smcp_status_t
smcp_daemon_pair_with_uri(
	smcp_daemon_t	self,
	const char*		path,
	const char*		uri,
	int				flags,
	uintptr_t*		idVal
) {
#if SMCP_USE_BSD_SOCKETS
	return smcp_daemon_pair_with_sockaddr(self, path, uri, NULL, 0, flags, idVal);
#elif CONTIKI
	return smcp_daemon_pair_with_sockaddr(self, path, uri, 0, 0, flags, idVal);
#else
	return SMCP_STATUS_NOT_IMPLEMENTED;
#endif
}


smcp_pairing_node_t
smcp_daemon_get_first_pairing_for_path(
	smcp_daemon_t self, const char* path
) {
	smcp_pairing_node_t ret = NULL;
	smcp_node_t path_node = NULL;
	
	while(path[0] == '/' && path[1] != 0) path++;

	path_node = smcp_node_find(
		self->root_pairing_node,
		path,
		strlen(path)
	);

	require(path_node,bail);
	require(path_node->children,bail);

	ret = bt_first(path_node->children);

bail:
	return ret;
}

smcp_pairing_node_t
smcp_daemon_next_pairing(
	smcp_daemon_t self, smcp_pairing_node_t pairing
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
	const smcp_daemon_t self = smcp_get_current_daemon();
	smcp_event_tracker_t event = pairing->currentEvent;

	coap_content_type_t content_type;

	status = smcp_message_begin(self,COAP_METHOD_POST,COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

#if SMCP_USE_BSD_SOCKETS
	if(((struct sockaddr*)&pairing->saddr)->sa_family)
		status = smcp_message_set_destaddr((struct sockaddr*)&pairing->saddr, sizeof(pairing->saddr));
#elif CONTIKI
	if(pairing->toport)
		status = smcp_message_set_destaddr(&pairing->toaddr,pairing->toport);
#endif
	require_noerr(status,bail);

	status = smcp_message_set_uri(smcp_pairing_get_uri_cstr(pairing),0);
	require_noerr(status,bail);

	status = smcp_message_add_header(SMCP_HEADER_ORIGIN, smcp_pairing_get_path_cstr(pairing), COAP_HEADER_CSTR_LEN);
	require_noerr(status,bail);

	char cseq[24];
#if __AVR__
	snprintf_P(
		cseq,
		sizeof(cseq),
		PSTR("%lX POST"),
		(long unsigned int)pairing->seq
	);
#else
	snprintf(cseq,
		sizeof(cseq),
		"%lX POST",
		(long unsigned int)pairing->seq
	);
#endif
	status = smcp_message_add_header(SMCP_HEADER_CSEQ, cseq, COAP_HEADER_CSTR_LEN);
	require_noerr(status,bail);

	if(event->contentFetcher) {
		(*event->contentFetcher)(
			event->contentFetcherContext,
			NULL,
			NULL,
			&content_type
		);
		status = smcp_message_add_header(COAP_HEADER_CONTENT_TYPE, (void*)&content_type, 1);
		require_noerr(status,bail);

		size_t len = 0;
		char* ptr = smcp_message_get_content_ptr(&len);
		event->contentFetcher(
			event->contentFetcherContext,
			ptr,
			&len,
			&content_type
		);
		smcp_message_set_content_len(len);
	}

	status = smcp_message_send();
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

static void
smcp_event_response_handler(
	int statuscode, smcp_pairing_node_t pairing
) {
#if SMCP_CONF_PAIRING_STATS
	// TODO: Trigger events based on these errors...!
	pairing->last_error = statuscode;
	if(statuscode && ((statuscode < 200) || (statuscode >= 300))) {
		// Looks like we failed to live up to this pairing.
		pairing->errors++;
	}
#endif
	// expire the event.
	smcp_event_tracker_t event = pairing->currentEvent;
	DEBUG_PRINTF("Event:%p: smcp_event_response_handler(): statuscode=%d",event,statuscode);
	pairing->currentEvent = NULL;
	smcp_event_tracker_release(event);
}

static smcp_status_t
smcp_retry_event(smcp_pairing_node_t pairing) {
	smcp_status_t status;
	const smcp_daemon_t self = smcp_get_current_daemon();

	status = smcp_message_begin(self,COAP_METHOD_POST,COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	self->is_responding = true;
	self->force_current_outbound_code = true;

#if SMCP_USE_BSD_SOCKETS
	if(((struct sockaddr*)&pairing->saddr)->sa_family)
		status = smcp_message_set_destaddr((struct sockaddr*)&pairing->saddr, sizeof(pairing->saddr));
#elif CONTIKI
	if(pairing->toport)
		status = smcp_message_set_destaddr(&pairing->toaddr,pairing->toport);
#endif
	require_noerr(status,bail);

	status = smcp_message_set_uri(smcp_pairing_get_uri_cstr(pairing),0);
	require_noerr(status,bail);

	status = smcp_message_add_header(
		SMCP_HEADER_ORIGIN,
		smcp_pairing_get_path_cstr(pairing),
		COAP_HEADER_CSTR_LEN
	);

	require_noerr(status,bail);

	char cseq[24];
#if __AVR__
	snprintf_P(
		cseq,
		sizeof(cseq),
		PSTR("%lX POST"),
		(long unsigned int)pairing->seq
	);
#else
	snprintf(cseq,
		sizeof(cseq),
		"%lX POST",
		(long unsigned int)pairing->seq
	);
#endif
	status = smcp_message_add_header(SMCP_HEADER_CSEQ, cseq, COAP_HEADER_CSTR_LEN);
	require_noerr(status,bail);

/*
	status = smcp_daemon_handle_request(
		self,
		COAP_METHOD_GET,
		pairing->path,
		"",
		0
	);
*/
	self->current_inbound_code = COAP_METHOD_GET;
	self->current_inbound_content_len = 0;
	self->current_inbound_content_ptr = NULL;
	self->current_header = NULL;

#warning TODO: Need to inject the path!!!
	
	status = smcp_daemon_handle_request(self);
	require_noerr(status,bail);

#if SMCP_CONF_PAIRING_STATS
	pairing->send_count++;
#endif

bail:
	return status;
}

smcp_status_t
smcp_daemon_trigger_event(
	smcp_daemon_t self,
	const char* path
) {
	smcp_status_t ret = 0;
	smcp_pairing_node_t iter;
	smcp_event_tracker_t event = NULL;

	require_action(self!=NULL,bail,ret=SMCP_STATUS_BAD_ARGUMENT);

	if(!path) path = "";

	// Move past any preceding slashes.
	while(path && path[0] == '/' && path[1] == 0) path++;

	for(iter = smcp_daemon_get_first_pairing_for_path(self, path);
	    iter;
	    iter = smcp_daemon_next_pairing(self, iter)
	) {
		coap_transaction_id_t tid = (coap_transaction_id_t)SMCP_FUNC_RANDOM_UINT32();
		smcp_status_t status;

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

		if(iter->currentEvent) {
			DEBUG_PRINTF("Event:%p: Previous event, %p, is still around!",event,iter->currentEvent);
			smcp_invalidate_transaction(self, iter->last_tid);
		}

		iter->currentEvent = event;

		status = smcp_begin_transaction(
			self,
			tid,
			(iter->flags&SMCP_PARING_FLAG_RELIABILITY_MASK)?30000:10,
			0, // Flags
			(void*)&smcp_retry_event,
			(void*)&smcp_event_response_handler,
			(void*)iter
		);
		if(status)
			continue;

		iter->last_tid = tid;
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
smcp_daemon_trigger_event_with_node(
	smcp_daemon_t		self,
	smcp_node_t			node,
	const char*			subpath
) {
	char path[SMCP_MAX_PATH_LENGTH + 1];

	path[sizeof(path) - 1] = 0;

	smcp_node_get_path(node, path, sizeof(path));

	if(subpath) {
		if(path[0])
			strncat(path, "/", sizeof(path) - 1);
		strncat(path, subpath, sizeof(path) - 1);
	}

	{   // Remove trailing slashes.
		size_t len = strlen(path);
		while(len && path[len - 1] == '/')
			path[--len] = 0;
	}

	return smcp_daemon_trigger_event(
		self,
		path
	);
}


smcp_status_t
smcp_daemon_trigger_custom_event(
	smcp_daemon_t		self,
	const char*			path,
	smcp_content_fetcher_func contentFetcher,
	void* context
) {
	smcp_status_t ret = 0;
	smcp_pairing_node_t iter;
	smcp_event_tracker_t event = NULL;

	if(!path) path = "";

	// Move past any preceding slashes.
	while(path && *path == '/') path++;

	for(iter = smcp_daemon_get_first_pairing_for_path(self, path);
	    iter;
	    iter = smcp_daemon_next_pairing(self, iter)
	) {
		coap_transaction_id_t tid = (coap_transaction_id_t)SMCP_FUNC_RANDOM_UINT32();
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
			smcp_invalidate_transaction(self, iter->last_tid);
		}

		iter->currentEvent = event;

		status = smcp_begin_transaction(
			self,
			tid,
			(iter->flags&SMCP_PARING_FLAG_RELIABILITY_MASK)?30000:10,
			0, // Flags
			(void*)&smcp_retry_custom_event,
			(void*)&smcp_event_response_handler,
			(void*)iter
		);
		if(status)
			continue;

		iter->last_tid = tid;
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
smcp_daemon_trigger_custom_event_with_node(
	smcp_daemon_t		self,
	smcp_node_t			node,
	const char*			subpath,
	smcp_content_fetcher_func contentFetcher,
	void* context
) {
	char path[SMCP_MAX_PATH_LENGTH + 1];

	path[sizeof(path) - 1] = 0;

	smcp_node_get_path(node, path, sizeof(path));

	if(subpath) {
		if(path[0])
			strncat(path, "/", sizeof(path) - 1);
		strncat(path, subpath, sizeof(path) - 1);
	}

	{   // Remove trailing slashes.
		size_t len = strlen(path);
		while(len && path[len - 1] == '/')
			path[--len] = 0;
	}

	return smcp_daemon_trigger_custom_event(
		self,
		path,
		contentFetcher,
		context
	);
}

smcp_status_t
smcp_daemon_refresh_variable(
	smcp_daemon_t self, smcp_variable_node_t node
) {
	smcp_status_t ret = 0;

	require_action(self != NULL, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(node != NULL, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

#if 1
	ret = smcp_daemon_trigger_event_with_node(
		self,
		(smcp_node_t)node,
		NULL
	);
#else
	ret = smcp_daemon_trigger_custom_event_with_node(
		self,
		(smcp_node_t)node,
		NULL,
		(void*)node->get_func,
		node
	);
#endif

bail:
	return ret;
}

smcp_status_t
smcp_daemon_handle_pair(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_daemon_t self = smcp_get_current_daemon();
	smcp_status_t ret = 0;
	uintptr_t idVal;
	char reply[3 + sizeof(uintptr_t) * 2];
	char full_path[SMCP_MAX_PATH_LENGTH + 1];

	full_path[0] = 0;

	require_action(node, bail, ret = SMCP_STATUS_FAILURE);

	const coap_header_item_t *iter = smcp_daemon_get_first_header();

	for(;iter;iter=smcp_daemon_get_next_header(iter)) {
		if(iter->key == COAP_HEADER_URI_PATH) {
			break;
		}
	}

	for(;iter && (iter->key == COAP_HEADER_URI_PATH);iter=smcp_daemon_get_next_header(iter)) {
		strncat(full_path, "/", sizeof(full_path));
		// TODO: This needs to be URL encoded!
		strncat(full_path, iter->value, MIN(sizeof(full_path),iter->value_len));
	}

#if SMCP_USE_BSD_SOCKETS
	ret = smcp_daemon_pair_with_sockaddr(
		self,
		full_path,
		smcp_daemon_get_current_inbound_content_ptr(),
		smcp_daemon_get_current_request_saddr(),
		smcp_daemon_get_current_request_socklen(),
		SMCP_PARING_FLAG_RELIABILITY_PART,
		&idVal
	);
#elif CONTIKI
	ret = smcp_daemon_pair_with_sockaddr(
		self,
		full_path,
		smcp_daemon_get_current_inbound_content_ptr(),
		smcp_daemon_get_current_request_ipaddr(),
		smcp_daemon_get_current_request_ipport(),
		SMCP_PARING_FLAG_RELIABILITY_PART,
		&idVal
	);
#else
	ret = smcp_daemon_pair_with_uri(
		self,
		full_path,
		smcp_daemon_get_current_inbound_content_ptr(),
		SMCP_PARING_FLAG_RELIABILITY_PART,
		&idVal
	);
#endif

	snprintf(reply, sizeof(reply), "%p", (void*)idVal);

	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));

	smcp_message_begin_response(HTTP_TO_COAP_CODE(smcp_convert_status_to_result_code(ret)));

	if(!ret)
		smcp_message_set_content(reply, COAP_HEADER_CSTR_LEN);

	smcp_message_send();

bail:
	return ret;
}

extern smcp_status_t
smcp_daemon_delete_pairing(smcp_daemon_t self, smcp_pairing_node_t pairing) {
	if(pairing->currentEvent) {
		smcp_event_tracker_release(pairing->currentEvent);
		smcp_invalidate_transaction(self, pairing->last_tid);
	}
	smcp_node_t parent = (smcp_node_t)pairing->node.bt_item.parent;
	smcp_node_delete(&pairing->node);
	if(!parent->children) {
		smcp_node_delete(parent);
	}
	return SMCP_STATUS_OK;
}


#pragma mark -
#pragma mark Pairing Node Interface

static smcp_status_t
smcp_pairing_node_request_handler(
	smcp_pairing_node_t		pairing,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;
	smcp_daemon_t self = smcp_get_current_daemon();

	enum {
		PATH_ROOT,
		PATH_DEST_URI,
		PATH_FLAGS,
#if SMCP_CONF_PAIRING_STATS
		PATH_FIRE_COUNT,
		PATH_SEND_COUNT,
		PATH_ERROR_COUNT,
		PATH_LAST_ERROR,
#endif
		PATH_SEQ,
		PATH_ACK,
	} path;

	if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"d"))
		path = PATH_DEST_URI;
	else if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"f"))
		path = PATH_FLAGS;
#if SMCP_CONF_PAIRING_STATS
	else if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"fc"))
		path = PATH_FIRE_COUNT;
	else if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"tx"))
		path = PATH_SEND_COUNT;
	else if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"ec"))
		path = PATH_ERROR_COUNT;
	else if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"err"))
		path = PATH_LAST_ERROR;
#endif
	else if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"seq"))
		path = PATH_SEQ;
	else if(smcp_current_request_header_strequal(COAP_HEADER_URI_PATH,"ack"))
		path = PATH_ACK;
	
	if(path!=PATH_ROOT)
		smcp_current_request_next_header(NULL,NULL);

	coap_header_key_t key;
	uint8_t* value;
	size_t value_len;
	{
		while((key==smcp_current_request_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {
			require_action(key!=COAP_HEADER_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);

			require_action(
				!COAP_HEADER_IS_REQUIRED(key),
				bail,
				ret=SMCP_STATUS_BAD_OPTION
			);
		}
	}

	if(method == COAP_METHOD_GET) {
		if(path==PATH_DEST_URI) {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_message_set_content(smcp_pairing_get_uri_cstr(pairing), COAP_HEADER_CSTR_LEN);
			ret = smcp_message_send();
		} else if(path==PATH_FLAGS) {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_message_set_content_formatted("0x%02X",pairing->flags);
			ret = smcp_message_send();
		} else if(path==PATH_SEQ) {
			ret = SMCP_STATUS_NOT_IMPLEMENTED;
		} else if(path==PATH_ACK) {
			ret = SMCP_STATUS_NOT_IMPLEMENTED;
	#if SMCP_CONF_PAIRING_STATS
		} else if(path==PATH_FIRE_COUNT) {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_message_set_var_content_unsigned_int(pairing->fire_count);
			ret = smcp_message_send();
		} else if(path==PATH_SEND_COUNT) {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_message_set_var_content_unsigned_int(pairing->send_count);
			ret = smcp_message_send();
		} else if(path==PATH_ERROR_COUNT) {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_message_set_var_content_unsigned_int(pairing->errors);
			ret = smcp_message_send();
		} else if(path==PATH_LAST_ERROR) {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_message_set_var_content_int(pairing->last_error);
			ret = smcp_message_send();
	#endif
		} else {
			ret = smcp_default_request_handler(&pairing->node, method);
		}
	} else if(method == COAP_METHOD_POST && method == COAP_METHOD_PUT) {
		if(path==PATH_FLAGS) {
			// TODO: Fix this!
			ret = SMCP_STATUS_NOT_ALLOWED;
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else if(method == COAP_METHOD_DELETE) {
		if(path==PATH_ROOT) {
			ret = smcp_daemon_delete_pairing(self, pairing);
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

bail:
	return ret;
}

smcp_root_pairing_node_t smcp_pairing_init(
	smcp_daemon_t self, smcp_node_t parent, const char* name
) {
	require((self->root_pairing_node = smcp_node_init(NULL, parent, name)), bail);
	
bail:
	return self->root_pairing_node;
}
