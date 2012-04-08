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

static bt_compare_result_t
smcp_pairing_compare_for_insert(
	smcp_pairing_t lhs, smcp_pairing_t rhs
) {
	if(lhs->path == rhs->path)
		return strcmp(lhs->dest_uri, rhs->dest_uri);
	bt_compare_result_t ret = strcmp(lhs->path, rhs->path);
	return (ret == 0) ? strcmp(lhs->dest_uri, rhs->dest_uri) : ret;
}

static bt_compare_result_t
smcp_pairing_compare_cstr(
	smcp_pairing_t lhs, const char* rhs
) {
	if(lhs->path == rhs)
		return 0;
	if(!lhs->path)
		return 1;
	if(!rhs)
		return -1;
	return strcmp(lhs->path, rhs);
}

void
smcp_pairing_finalize(smcp_pairing_t self) {
	if(self->path)
		free((void*)self->path);
	if(self->dest_uri)
		free((void*)self->dest_uri);
	free((void*)self);
}

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

	smcp_pairing_t pairing = NULL;

	require_action(path, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(uri, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	pairing = calloc(1, sizeof(*pairing));

	require(pairing, bail);

	while(path[0] == '/') path++;

	pairing->path = strdup(path);
	pairing->dest_uri = strdup(uri);
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

	bt_insert(
		    (void**)&((smcp_daemon_t)self)->pairings,
		pairing,
		    (bt_compare_func_t)smcp_pairing_compare_for_insert,
		    (bt_delete_func_t)smcp_pairing_finalize,
		NULL
	);

#if 1
	pairing->seq = pairing->ack = SMCP_FUNC_RANDOM_UINT32();
#else
	pairing->seq = pairing->ack = 0;
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


smcp_pairing_t
smcp_daemon_get_first_pairing_for_path(
	smcp_daemon_t self, const char* path
) {
	smcp_pairing_t ret = NULL;
	smcp_pairing_t prev = NULL;

	while(path[0] == '/') path++;

	ret = bt_find((void**)&self->pairings,
		path,
		    (bt_compare_func_t)smcp_pairing_compare_cstr,
		NULL);

	if(ret) {
		for(prev = bt_prev(ret);
		    prev && (0 == strcmp(ret->path, prev->path));
		    ret = prev, prev = bt_prev(ret)) {
		}
	}

	return ret;
}

smcp_pairing_t
smcp_daemon_next_pairing(
	smcp_daemon_t self, smcp_pairing_t pairing
) {
	smcp_pairing_t ret = NULL;

	require(pairing != NULL, bail);

	ret = bt_next((void*)pairing);
	if(ret && (0 != strcmp(pairing->path, ret->path)))
		ret = 0;

bail:
	return ret;
}

static bool
smcp_retry_custom_event(smcp_pairing_t pairing) {
	bool ret = true;
	const smcp_daemon_t self = smcp_get_current_daemon();
	smcp_event_tracker_t event = pairing->currentEvent;

	coap_content_type_t content_type;

	smcp_message_begin(self,COAP_METHOD_POST,COAP_TRANS_TYPE_CONFIRMABLE);

#if SMCP_USE_BSD_SOCKETS
	if(((struct sockaddr*)&pairing->saddr)->sa_family)
		smcp_message_set_destaddr((struct sockaddr*)&pairing->saddr, sizeof(pairing->saddr));
#elif CONTIKI
	if(pairing->toport)
		smcp_message_set_destaddr(&pairing->toaddr,pairing->toport);
#endif

	smcp_message_set_uri(pairing->dest_uri,0);
	smcp_message_add_header(SMCP_HEADER_ORIGIN, pairing->path, COAP_HEADER_CSTR_LEN);

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
	smcp_message_add_header(SMCP_HEADER_CSEQ, cseq, COAP_HEADER_CSTR_LEN);

	if(event->contentFetcher) {
		(*event->contentFetcher)(
			event->contentFetcherContext,
			NULL,
			NULL,
			&content_type
		);
		smcp_message_add_header(COAP_HEADER_CONTENT_TYPE, (void*)&content_type, 1);

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

	smcp_message_send();

#if SMCP_CONF_PAIRING_STATS
	pairing->send_count++;
#endif

	return ret;
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
	int statuscode, char* content, size_t content_length, smcp_pairing_t pairing
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

static bool
smcp_retry_event(smcp_pairing_t pairing) {
	bool ret = true;
	const smcp_daemon_t self = smcp_get_current_daemon();

	smcp_message_begin(self,COAP_METHOD_POST,COAP_TRANS_TYPE_CONFIRMABLE);

	self->is_responding = true;
	self->force_current_outbound_code = true;

#if SMCP_USE_BSD_SOCKETS
	if(((struct sockaddr*)&pairing->saddr)->sa_family)
		smcp_message_set_destaddr((struct sockaddr*)&pairing->saddr, sizeof(pairing->saddr));
#elif CONTIKI
	if(pairing->toport)
		smcp_message_set_destaddr(&pairing->toaddr,pairing->toport);
#endif

	smcp_message_set_uri(pairing->dest_uri,0);
	smcp_message_add_header(SMCP_HEADER_ORIGIN, pairing->path, COAP_HEADER_CSTR_LEN);

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
	smcp_message_add_header(SMCP_HEADER_CSEQ, cseq, COAP_HEADER_CSTR_LEN);

	ret = smcp_daemon_handle_request(self, COAP_METHOD_GET, pairing->path, "", 0);

#if SMCP_CONF_PAIRING_STATS
	pairing->send_count++;
#endif

	return ret;
}

smcp_status_t
smcp_daemon_trigger_event(
	smcp_daemon_t self,
	const char* path
) {
	smcp_status_t ret = 0;
	smcp_pairing_t iter;
	smcp_event_tracker_t event = NULL;

	require_action(self!=NULL,bail,ret=SMCP_STATUS_BAD_ARGUMENT);

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
	smcp_pairing_t iter;
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
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_daemon_t self = smcp_get_current_daemon();
	smcp_status_t ret = 0;
	uintptr_t idVal;
	char reply[3 + sizeof(uintptr_t) * 2];
	char full_path[SMCP_MAX_PATH_LENGTH + 1];

	full_path[sizeof(full_path) - 1] = 0;

	require_action(node, bail, ret = SMCP_STATUS_FAILURE);

	smcp_node_get_path(node, full_path, sizeof(full_path));
	if(path && path[0]) {
		if(path[0])
			strncat(full_path, "/", sizeof(full_path) - 1);
		strncat(full_path, path, sizeof(full_path) - 1);
	}
#if SMCP_USE_BSD_SOCKETS
	ret = smcp_daemon_pair_with_sockaddr(
		self,
		full_path,
		content,
		smcp_daemon_get_current_request_saddr(),
		smcp_daemon_get_current_request_socklen(),
		SMCP_PARING_FLAG_RELIABILITY_PART,
		&idVal
	);
#elif CONTIKI
	ret = smcp_daemon_pair_with_sockaddr(
		self,
		full_path,
		content,
		smcp_daemon_get_current_request_ipaddr(),
		smcp_daemon_get_current_request_ipport(),
		SMCP_PARING_FLAG_RELIABILITY_PART,
		&idVal
	);
#else
	ret = smcp_daemon_pair_with_uri(
		self,
		full_path,
		content,
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
smcp_daemon_delete_pairing(
	smcp_daemon_t self, smcp_pairing_t pairing
) {
	if(pairing->currentEvent) {
		smcp_event_tracker_release(pairing->currentEvent);
		smcp_invalidate_transaction(self, pairing->last_tid);
	}
	return bt_remove(
		    (void**)&((smcp_daemon_t)self)->pairings,
		pairing,
		    (bt_compare_func_t)smcp_pairing_compare_for_insert,
		    (bt_delete_func_t)smcp_pairing_finalize,
		NULL
	) ? SMCP_STATUS_OK : SMCP_STATUS_NOT_FOUND;
}


#pragma mark -
#pragma mark Pairing Node Interface

static smcp_status_t
smcp_pairing_node_list(smcp_pairing_t first_pairing) {
	smcp_status_t ret = 0;
	size_t content_break_threshold = 160;
	uint16_t start_index = 0, i = 0;

	// TODO: Rewrite using the constrained API so we don't use so much stack!
	char replyContent[160*2];

	memset(replyContent, 0, sizeof(replyContent));

	smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));

	smcp_pairing_t
	    pairing_iter = first_pairing ? first_pairing : bt_first(
		smcp_get_current_daemon()->pairings),
	    pairing_prev = NULL;

	{
		const coap_header_item_t *iter =
		    smcp_daemon_get_current_request_headers();
		const coap_header_item_t *end = iter +
		    smcp_daemon_get_current_request_header_count();
		for(; iter != end; ++iter) {
			if((iter->key == COAP_HEADER_CONTINUATION_RESPONSE) &&
			        (iter->value_len == sizeof(start_index))) {
				memcpy(&start_index, iter->value, sizeof(start_index));
				start_index = ntohs(start_index);
			} else if(iter->key == COAP_HEADER_SIZE_REQUEST) {
				uint8_t i;
				content_break_threshold = 0;
				for(i = 0; i < iter->value_len; i++)
					content_break_threshold =
					    (content_break_threshold << 8) + iter->value[i];
				if(content_break_threshold >= sizeof(replyContent)) {
					DEBUG_PRINTF(
							"Requested size (%d) is too large, trimming to %d.",
						(int)content_break_threshold, (int)(sizeof(replyContent) - 1));
					content_break_threshold = sizeof(replyContent) - 1;
				}
			}
		}
	}

	if(content_break_threshold >= sizeof(replyContent) - 1)
		// Trim the content break threshold to something we support.
		content_break_threshold = sizeof(replyContent) - 2;


	for(i = 0;
	    pairing_iter && (i < start_index);
	    i++, pairing_iter = bt_next(pairing_iter)) {
	}

	i = 0;

	while(pairing_iter) {
		const char* name;
		size_t escapedLen;

		if(first_pairing)
			name = pairing_iter->dest_uri;
		else
			name = pairing_iter->path;

		if(!name)
			break;

		if(pairing_prev &&
		        ((strlen(name) + 4) >
		            (content_break_threshold - strlen(replyContent) -
		            2))) {
			start_index++;
			break;
		}

		replyContent[i++] = '<';
		escapedLen = -i;
		i += url_encode_cstr(replyContent + i,
			name,
			sizeof(replyContent) - i - 2);
		escapedLen += i;
		replyContent[i++] = '>';

		if(first_pairing) {
			if(escapedLen > (2 + sizeof(void*) * 2)) {
				i += snprintf(replyContent + i,
					sizeof(replyContent) - i,
					";sh=\"%p\"",
					pairing_iter);
			}
		}
		strncpy(replyContent + i, ";ct=40", sizeof(replyContent) - i);
		i += 6;

		pairing_prev = pairing_iter;
		pairing_iter = bt_next(pairing_iter);
		start_index++;
		if(first_pairing) {
			if(pairing_iter &&
			        (0 != strcmp(first_pairing->path, pairing_iter->path)))
				pairing_iter = NULL;
		} else {
			if(pairing_iter) {
				while(pairing_iter &&
				        (0 ==
				        strcmp(pairing_prev->path, pairing_iter->path))) {
					pairing_prev = pairing_iter;
					pairing_iter = bt_next(pairing_iter);
					start_index++;
				}
			}
		}

		if(pairing_iter)
			replyContent[i++] = ',';
	}

	// If there are more nodes, indicate as such in the headers.
	if(pairing_iter) {
		smcp_message_set_code(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT));
		start_index = htons(start_index);
		smcp_message_add_header(
			COAP_HEADER_CONTINUATION_REQUEST,
			(void*)&start_index,
			sizeof(start_index)
		);
	}

	coap_content_type_t content_type =
	    COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;

	smcp_message_add_header(
		COAP_HEADER_CONTENT_TYPE,
		    (const void*)&content_type,
		1
	);
	smcp_message_set_content(replyContent,i);
	smcp_message_send();
bail:
	return ret;
}

static smcp_status_t
smcp_pairing_node_request_handler(
	smcp_node_t		node,
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_status_t ret = 0;
	smcp_daemon_t self = smcp_get_current_daemon();

	if(!path || (path[0] == 0)) {
		if(method == COAP_METHOD_GET) {
			ret = smcp_pairing_node_list(NULL);
		} else {
			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_METHOD_NOT_ALLOWED));
			smcp_message_send();
		}
	} else {
		char* name = strsep((char**)&path, "/");
		smcp_pairing_t pairing;
		url_decode_cstr_inplace(name);

		pairing = smcp_daemon_get_first_pairing_for_path(self, name);

		if(!path || (path[0] == 0)) {
			require_action(pairing != NULL,
				bail,
				ret = SMCP_STATUS_NOT_FOUND);
			if(method == COAP_METHOD_GET) {
				ret = smcp_pairing_node_list(pairing);

#if 0
            } else if((method==COAP_METHOD_PUT) || (method==COAP_METHOD_POST)) {
                require_action(content_length,bail,ret=SMCP_STATUS_UNSUPPORTED_URI);
                ret = smcp_daemon_pair_with_uri(
					self,
					name,
					content,
					SMCP_PARING_FLAG_RELIABILITY_PART,
					NULL
				);
                if((ret==SMCP_STATUS_OK)) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CREATED));
					smcp_message_send();
				}
#endif

			} else {
				smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_METHOD_NOT_ALLOWED));
				smcp_message_send();
			}
		} else {
			char* uri = strsep((char**)&path, "/");
			if(isdigit(uri[0])) {
				smcp_pairing_t target = (smcp_pairing_t)strtol(uri,
					NULL,
					0);
				// Verify that this really is a valid pointer...!
				while(pairing && (pairing != target)) {
					pairing = smcp_daemon_next_pairing(self, pairing);
				}
			} else {
				url_decode_cstr_inplace(uri);
				while(pairing && (0 != strcmp(uri, pairing->dest_uri))) {
					pairing = smcp_daemon_next_pairing(self, pairing);
				}
			}


			if(method == COAP_METHOD_GET) {
				require_action(pairing != NULL,
					bail,
					ret = SMCP_STATUS_NOT_FOUND);
				if(!path) {
					const char rcontent[] = (
						"<d>;n=\"Dest URI\","
						"<f>;n=\"Flags\","
#if SMCP_CONF_PAIRING_STATS
					    "<fc>;n=\"Fire Count\","
						"<tx>;n=\"Send Count\","
						"<ec>;n=\"Error Count\","
						"<err>;n=\"Last Error\","
#endif
					    "<seq>,"
						"<ack>"
					);
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_content_type(COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);
					smcp_message_set_content(rcontent, COAP_HEADER_CSTR_LEN);
					ret = smcp_message_send();
				} else if(strequal_const(path, "d")) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_content(pairing->dest_uri, COAP_HEADER_CSTR_LEN);
					ret = smcp_message_send();
				} else if(strequal_const(path, "f")) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_content_formatted("0x%02X",pairing->flags);
					ret = smcp_message_send();
				} else if(strequal_const(path, "seq")) {
					ret = SMCP_STATUS_NOT_IMPLEMENTED;
				} else if(strequal_const(path, "ack")) {
					ret = SMCP_STATUS_NOT_IMPLEMENTED;
#if SMCP_CONF_PAIRING_STATS
				} else if(strequal_const(path, "fc")) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_var_content_unsigned_int(pairing->fire_count);
					ret = smcp_message_send();
				} else if(strequal_const(path, "tx")) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_var_content_unsigned_int(pairing->send_count);
					ret = smcp_message_send();
				} else if(strequal_const(path, "ec")) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_var_content_unsigned_int(pairing->errors);
					ret = smcp_message_send();
				} else if(strequal_const(path, "err")) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_var_content_int(pairing->last_error);
					ret = smcp_message_send();
#endif
				} else {
					ret = SMCP_STATUS_NOT_FOUND;
				}
			} else if((method == COAP_METHOD_PUT) ||
			        (method == COAP_METHOD_POST)) {
				require_action(path != NULL,
					bail,
					ret = SMCP_STATUS_FAILURE);
				if(!pairing &&
				        ((ret =
				                smcp_daemon_pair_with_uri(self, name, uri,
								0,
								NULL)) == SMCP_STATUS_OK)) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CREATED));
					smcp_message_send();
				}
			} else if((method == COAP_METHOD_DELETE) && pairing) {
				ret = smcp_daemon_delete_pairing(self, pairing);
			} else {
				smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_METHOD_NOT_ALLOWED));
				smcp_message_send();
			}
		}
	}

bail:
	return ret;
}

smcp_pairing_node_t smcp_pairing_node_init(
	smcp_pairing_node_t self, smcp_node_t parent, const char* name
) {
	require(self = smcp_node_init((smcp_node_t)self, parent, name), bail);

	self->request_handler = &smcp_pairing_node_request_handler;

bail:
	return self;
}
