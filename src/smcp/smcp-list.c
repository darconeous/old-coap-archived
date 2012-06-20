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
#define VERBOSE_DEBUG 1
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

#include "smcp-internal.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"
#include "smcp.h"
#include "ll.h"
#include "url-helpers.h"

smcp_status_t
smcp_handle_list(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;
	char* replyContent;
	size_t content_break_threshold = 256;
	const char* prefix = NULL;

	// The path "/.well-known/core" is a special case. If we get here,
	// we know that it isn't being handled explicitly, so we just
	// show the root listing as a reasonable default.
	if(!node->parent) {
		if(smcp_inbound_option_strequal_const(COAP_HEADER_URI_PATH,".well-known")) {
			smcp_inbound_next_option(NULL, NULL);
			if(smcp_inbound_option_strequal_const(COAP_HEADER_URI_PATH,"core")) {
				smcp_inbound_next_option(NULL, NULL);
				prefix = "/";
			} else {
				ret = SMCP_STATUS_NOT_ALLOWED;
				goto bail;
			}
		}
	}

	// Check over the headers to make sure they are sane.
	{
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_HEADER_INVALID) {
			require_action(key!=COAP_HEADER_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);
			if(key == COAP_HEADER_URI_QUERY) {
				// Skip URI query components for now.
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

	// Node should always be set by the time we get here.
	require_action(node, bail, ret = SMCP_STATUS_BAD_ARGUMENT);

#if VERBOSE_DEBUG
	{
		smcp_node_t iter = bt_first(((smcp_node_t)node)->children);
		for(;iter;iter = bt_next(iter)) {
			DEBUG_PRINTF("CHILD: \"%s\"",iter->name);
		}
	}
#endif

	if(((smcp_node_t)node)->children)
		node = bt_first(((smcp_node_t)node)->children);
	else
		node = NULL;

	smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	smcp_outbound_set_content_type(COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);

	replyContent = smcp_outbound_get_content_ptr(&content_break_threshold);
	replyContent[0] = 0;

	while(node) {
		smcp_node_t next;
		const char* node_name = node->name;

		if(!node_name)
			break;

		if((strlen(node_name) + 4) >
				(content_break_threshold - strlen(replyContent) - 3))
			break;

		strlcat(replyContent, "<", content_break_threshold);

		if(prefix)
			strlcat(replyContent, prefix, content_break_threshold);

		{
			size_t len = strlen(replyContent);
			if(content_break_threshold-1>len)
				url_encode_cstr(replyContent+len, node_name, content_break_threshold - len);
		}

		strlcat(replyContent, ">", content_break_threshold);

		if(node->children)
			strlcat(replyContent, ";ct=40", content_break_threshold);

		next = bt_next(node);

		node = next;
#if SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
		strlcat(replyContent, ",\n" + (!node), content_break_threshold);
#else
		strlcat(replyContent, "," + (!node), content_break_threshold);
#endif
	}

	ret = smcp_outbound_set_content_len(strlen(replyContent));
	require_noerr(ret,bail);

	ret = smcp_outbound_send();

bail:
	return ret;
}
