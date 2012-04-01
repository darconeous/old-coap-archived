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
#elif __CONTIKI__
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


/*
   static bt_compare_result_t
   smcp_pairing_compare(smcp_pairing_t lhs,smcp_pairing_t rhs) {
    if(lhs->path==rhs->path)
        return strcmp(lhs->dest_uri,rhs->dest_uri);
    bt_compare_result_t ret = strcmp(lhs->path,rhs->path);
    return (ret==0)?strcmp(lhs->dest_uri,rhs->dest_uri):ret;
   }
 */
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
smcp_daemon_pair_with_uri(
	smcp_daemon_t	self,
	const char*		path,
	const char*		uri,
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
	pairing->expiration = SMCP_PAIRING_EXPIRATION_INFINITE;

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

	if(pairing->seq != pairing->ack)
		abort();

bail:
	return ret;
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

bail:
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
smcp_retry_event(smcp_pairing_t pairing) {
	bool ret = true;
	const smcp_daemon_t self = smcp_get_current_daemon();
	smcp_event_tracker_t event = pairing->currentEvent;

	coap_content_type_t content_type;

	smcp_message_begin(self,COAP_METHOD_POST,COAP_TRANS_TYPE_CONFIRMABLE);

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

	return ret;
}

static void
smcp_event_tracker_release(smcp_event_tracker_t event) {
	if(0==--event->refCount) {
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

	// expire the event.
	smcp_event_tracker_t event = pairing->currentEvent;
	pairing->currentEvent = NULL;
	smcp_event_tracker_release(event);
}

smcp_status_t
smcp_daemon_trigger_event(
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
		}
		smcp_invalidate_transaction(self, iter->last_tid);

		if(iter->currentEvent)
			smcp_event_tracker_release(iter->currentEvent);

		iter->currentEvent = event;

		status = smcp_begin_transaction(
			self,
			tid,
			10000,
			0, // Flags
			(void*)&smcp_retry_event,
			(void*)&smcp_event_response_handler,
			(void*)iter
		);
		if(status)
			continue;

		iter->last_tid = tid;
		event->refCount++;

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

	return smcp_daemon_trigger_event(
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

	ret = smcp_daemon_trigger_event_with_node(
		self,
		(smcp_node_t)node,
		NULL,
		(void*)node->get_func,
		node
	);

bail:
	return ret;
}

#if 0

smcp_status_t
smcp_daemon_refresh_variable(
	smcp_daemon_t self, smcp_variable_node_t node
) {
	smcp_status_t ret = 0;
	char *content = NULL;
	size_t content_length = 0;
	coap_content_type_t content_type = COAP_CONTENT_TYPE_TEXT_PLAIN;

	require_action(self != NULL, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(node != NULL, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);

	if(node->get_func) {
		char tmp_content[SMCP_MAX_CONTENT_LENGTH]; // TODO: This is really hard on the stack! Investigate alternatives.
		content_length = sizeof(tmp_content);
		ret =
		    (*node->get_func)(node, tmp_content, &content_length,
			&content_type);
		require(ret == 0, bail);
		if(content_length) {
			content = (char*)malloc(content_length);
			memcpy(content, tmp_content, content_length);
		}
	}

	ret = smcp_daemon_trigger_event_with_node(
		self,
		    (smcp_node_t)node,
		NULL,
		content,
		content_length,
		content_type
	    );

bail:
	if(content)
		free(content);

	return ret;
}


smcp_status_t
smcp_daemon_trigger_event(
	smcp_daemon_t		self,
	const char*			path,
	const char*			content,
	size_t				content_length,
	coap_content_type_t content_type
) {
	smcp_status_t ret = 0;
	smcp_pairing_t iter;
	coap_transaction_id_t tid =
	    (coap_transaction_id_t)SMCP_FUNC_RANDOM_UINT32();
	char cseq[24];

	if(!path) path = "";

	// Move past any preceding slashes.
	while(path && *path == '/') path++;

	memset(cseq, 0, sizeof(cseq));

	for(iter = smcp_daemon_get_first_pairing_for_path(self, path);
	    iter;
	    iter = smcp_daemon_next_pairing(self, iter)
	) {
		smcp_status_t status;
		smcp_pairing_seq_t seq = smcp_pairing_get_next_seq(iter);

		smcp_message_begin(self,COAP_METHOD_POST,COAP_TRANS_TYPE_CONFIRMABLE);
		smcp_message_set_tid(tid);
		smcp_message_add_header(COAP_HEADER_CONTENT_TYPE, (void*)&content_type, 1);
		smcp_message_add_header(SMCP_HEADER_ORIGIN, path, COAP_HEADER_CSTR_LEN);

#if __AVR__
		snprintf_P(
			cseq,
			sizeof(cseq),
			PSTR("%lX POST"),
			(long unsigned int)seq
		);
#else
		snprintf(cseq,
			sizeof(cseq),
			"%lX POST",
			(long unsigned int)seq
		);
#endif

		smcp_message_add_header(SMCP_HEADER_CSEQ, cseq, COAP_HEADER_CSTR_LEN);
		smcp_message_set_uri(iter->dest_uri,0);
		smcp_message_set_content(content,content_length);

		DEBUG_PRINTF(CSTR(
				"%p: sending stuff for pairing \"%p\"..."), self, iter);

		status = smcp_message_send();

		check_string(status == SMCP_STATUS_OK, smcp_status_to_cstr(status));
#if SMCP_CONF_PAIRING_STATS
		if(status) {
			iter->errors++;
			iter->last_error = status;
		}
		iter->fire_count++;
#endif

		// TODO: Handle retransmits for reliable pairings!
	}

bail:
	return ret;
}

smcp_status_t
smcp_daemon_trigger_event_with_node(
	smcp_daemon_t		self,
	smcp_node_t			node,
	const char*			subpath,
	const char*			content,
	size_t				content_length,
	coap_content_type_t content_type
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

	return smcp_daemon_trigger_event(self,
		path,
		content,
		content_length,
		content_type);
}

#endif


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
	ret = smcp_daemon_pair_with_uri(
		self,
		full_path,
		content,
		0,
		&idVal
	    );

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
	size_t content_break_threshold = 60;
	uint16_t start_index = 0, i = 0;
	char replyContent[160];

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
					DEBUG_PRINTF(CSTR(
							"Requested size (%d) is too large, trimming to %d."),
						content_break_threshold, sizeof(replyContent) - 1);
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
		i += url_encode_cstr(replyContent + i,
			name,
			sizeof(replyContent) - i - 2);
		replyContent[i++] = '>';

		if(first_pairing) {
			if(strlen(name) > (2 + sizeof(void*) * 2)) {
				i += snprintf(replyContent + i,
					sizeof(replyContent) - i,
					";sh=\"%p\"",
					pairing_iter);
			}
		} else {
			strncpy(replyContent + i, ";ct=40", sizeof(replyContent) - i);
			i += 6;
		}

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
	smcp_message_set_content(replyContent,COAP_HEADER_CSTR_LEN);
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
			}
/*
            } else if((method==COAP_METHOD_PUT) || (method==COAP_METHOD_POST)) {
                require_action(content_length,bail,ret=SMCP_STATUS_UNSUPPORTED_URI);
                ret = smcp_daemon_pair_with_uri(self,name,content,0,NULL);
                if((ret==SMCP_STATUS_OK)) {
                    smcp_daemon_send_response( HTTP_RESULT_CODE_CREATED, NULL, NULL, 0);
                }
 */
			else {
				smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_METHOD_NOT_ALLOWED));
				smcp_message_send();
			}
		} else {
			char* uri = strsep((char**)&path, "/");
			if(isdigit(uri[0])) {
				smcp_pairing_t target = (smcp_pairing_t)strtol(uri,
					NULL,
					0);
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
					const char rcontent[] = "<d>,<f>,"
#if SMCP_CONF_PAIRING_STATS
					    "<fc>,<ec>,<err>,"
#endif
					    "<seq>,<ack>";
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					coap_content_type_t ct =
					    COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;

					smcp_message_add_header(COAP_HEADER_CONTENT_TYPE, (char*)&ct, 1);
					smcp_message_set_content(rcontent, COAP_HEADER_CSTR_LEN);
					smcp_message_send();
				} else if(strequal_const(path, "d")) {
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					smcp_message_set_content(pairing->dest_uri, COAP_HEADER_CSTR_LEN);
					smcp_message_send();
				} else if(strequal_const(path, "f")) {
					char *rcontent;
					size_t len=0;
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					rcontent = smcp_message_get_content_ptr(&len);
					len = snprintf(rcontent,
						len,
						"0x%02X",
						pairing->flags
					);
					smcp_message_set_content_len(len);
					smcp_message_send();
				} else if(strequal_const(path, "seq")) {
				} else if(strequal_const(path, "ack")) {
#if SMCP_CONF_PAIRING_STATS
				} else if(strequal_const(path, "fc")) {
					char *rcontent;
					size_t len=0;
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					rcontent = smcp_message_get_content_ptr(&len);
					len = snprintf(rcontent,
						len,
						"%u",
						pairing->fire_count
					);
					smcp_message_set_content_len(len);
					smcp_message_send();
				} else if(strequal_const(path, "ec")) {
					char *rcontent;
					size_t len=0;
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					rcontent = smcp_message_get_content_ptr(&len);
					len = snprintf(rcontent,
						len,
						"%u",
						pairing->errors
					);
					smcp_message_set_content_len(len);
					smcp_message_send();
				} else if(strequal_const(path, "err")) {
					char *rcontent;
					size_t len=0;
					smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
					rcontent = smcp_message_get_content_ptr(&len);
					len = snprintf(rcontent,
						len,
						"%d",
						pairing->last_error
					);
					smcp_message_set_content_len(len);
					smcp_message_send();
#endif
				} else {
					ret = SMCP_STATUS_NOT_FOUND;
				}
			} else if((method == COAP_METHOD_PUT) ||
			        (method == COAP_METHOD_POST)) {
				require_action(path != NULL,
					bail,
					ret = SMCP_STATUS_NOT_IMPLEMENTED);
				if(!pairing &&
				        ((ret =
				                smcp_daemon_pair_with_uri(self, name, uri,
								0,
								NULL)) == SMCP_STATUS_OK)) {
					smcp_daemon_send_response(HTTP_RESULT_CODE_CREATED,
						NULL,
						NULL,
						0);
				}
			} else if(method == COAP_METHOD_DELETE) {
				require_action(path != NULL,
					bail,
					ret = SMCP_STATUS_NOT_IMPLEMENTED);
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
