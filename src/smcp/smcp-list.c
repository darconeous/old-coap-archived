/*	@file smcp-list.c
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

/*	TODO: This function should be re-written using the new design patterns.
*/

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert_macros.h"

#if HAS_ALLOCA
#include <alloca.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "smcp_internal.h"
#include "smcp_helpers.h"
#include "smcp_logging.h"
#include "smcp.h"
#include "ll.h"
#include "url-helpers.h"

smcp_status_t
smcp_daemon_handle_list(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;
#if HAS_ALLOCA
	char* next_node = NULL;
#else
	char next_node[128];
#endif
	char replyContent[SMCP_MAX_PATH_LENGTH + 32 + 1];
	size_t content_break_threshold = 120;
	size_t content_offset = 0;
	const char* prefix = NULL;
	coap_option_key_t key;
	const uint8_t* value;
	size_t value_len;
	memset(replyContent, 0, sizeof(replyContent));
	next_node[0] = 0;
	if(!node->parent) {
		if(smcp_inbound_option_strequal(COAP_HEADER_URI_PATH,".well-known")) {
			smcp_inbound_next_header(NULL, NULL);
			if(smcp_inbound_option_strequal(COAP_HEADER_URI_PATH,"core")) {
				smcp_inbound_next_header(NULL, NULL);
				prefix = "/";
			} else {
				ret = SMCP_STATUS_NOT_ALLOWED;
				goto bail;
			}
		}
	}

	{
		while((key=smcp_inbound_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {
			require_action(key!=COAP_HEADER_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);
			if(key == COAP_HEADER_URI_QUERY) {
				// Skip URI query components for now.
			} else
			if(key == COAP_HEADER_CONTINUATION_RESPONSE) {
#if HAS_ALLOCA
				next_node = alloca(value_len + 1);
#endif
				memcpy(next_node, value, value_len);
				next_node[value_len] = 0;
			} else if(key == COAP_HEADER_SIZE_REQUEST) {
				uint8_t i;
				content_break_threshold = 0;
				for(i = 0; i < value_len; i++)
					content_break_threshold =
						(content_break_threshold << 8) + value[i];
				if(content_break_threshold >= sizeof(replyContent)) {
					DEBUG_PRINTF(
						"Requested size (%d) is too large, trimming to %d.",
						(int)content_break_threshold,
						(int)sizeof(replyContent) - 1
					);
					content_break_threshold = sizeof(replyContent) - 1;
				}
			} else {
				if(COAP_HEADER_IS_REQUIRED(key)) {
					ret=SMCP_STATUS_BAD_OPTION;
					assert_printf("Unrecognized option %d, \"%s\"",
						key,
						coap_option_key_to_cstr(key, false)
					);
					goto bail;
				}
			}
		}
	}

	if((content_break_threshold == 0) || (content_offset && !next_node)) {
		// We don't support content offsets right now.
		// TODO: Think about the implications of content offsets.
		smcp_outbound_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE));
		smcp_outbound_send();
		goto bail;
	}

	// Node should always be set by the time we get here.
	require_action(node, bail, ret = SMCP_STATUS_BAD_ARGUMENT);

	smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);

	if(next_node && next_node[0]) {
		smcp_node_t next;
		node = smcp_node_find_with_path(node, next_node);
		smcp_outbound_set_code(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT));
		check_string(node, "Unable to find next node!");
		next = bt_next(node);
		if(node && !next && node->parent)
			next = bt_first(((smcp_node_t)node->parent)->children);
		node = next;
	} else {
		if(((smcp_node_t)node)->children)
			node = bt_first(((smcp_node_t)node)->children);
		else
			node = NULL;
	}
	next_node[0] = 0;

	while(node) {
		smcp_node_t next;
		const char* node_name = node->name;

		if(!node_name)
			break;

		if(next_node[0]) {
			if(((int)strlen(node_name) + 4) >
			        (int)((int)content_break_threshold -
			            (int)strlen(replyContent) - 2))
				break;
		} else {
			if((strlen(node_name) + 4) >
			        (sizeof(replyContent) - strlen(replyContent) - 3))
				break;
		}

		strlcat(replyContent, "<", sizeof(replyContent));

		if(prefix)
			strlcat(replyContent, prefix, sizeof(replyContent));

		{
			size_t len = strlen(replyContent);
			if(sizeof(replyContent)-1>len)
				url_encode_cstr(replyContent+len, node_name, sizeof(replyContent) - len);
		}

		strlcat(replyContent, ">", sizeof(replyContent));

		if(node->children)
			strlcat(replyContent, ";ct=40", sizeof(replyContent));
		next = bt_next(node);

		//next_node = (char*)node->name;
		strncpy(next_node,node->name,sizeof(next_node));
		node = next;
#if SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
		strlcat(replyContent, ",\n" + (!node), sizeof(replyContent));
#else
		strlcat(replyContent, "," + (!node), sizeof(replyContent));
#endif
	}

	smcp_outbound_set_content_type(COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);

	// If there are more nodes, indicate as such in the headers.
	if(node && next_node[0]) {
		smcp_outbound_set_code(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT));
		smcp_outbound_add_option(
			COAP_HEADER_CONTINUATION_REQUEST,
			next_node,
			strlen(next_node)
		);
	}

	smcp_outbound_append_content(replyContent, COAP_HEADER_CSTR_LEN);

	smcp_outbound_send();

bail:
	return ret;
}
