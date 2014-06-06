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
**	SEC-TODO: This function is abusing strlcat()!
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
#include "smcp-node-router.h"

#if SMCP_CONF_NODE_ROUTER

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "smcp-internal.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"
#include "url-helpers.h"

smcp_status_t
smcp_handle_list(
	smcp_t self,
	smcp_node_t		node
) {
	smcp_status_t ret = 0;
	char* replyContent;
	coap_size_t content_break_threshold = 256;
	const char* prefix = node->name;

	// The path "/.well-known/core" is a special case. If we get here,
	// we know that it isn't being handled explicitly, so we just
	// show the root listing as a reasonable default.
	if(!node->parent) {
		if(smcp_inbound_option_strequal_const(self, COAP_OPTION_URI_PATH,".well-known")) {
			smcp_inbound_next_option(self, NULL, NULL);
			if(smcp_inbound_option_strequal_const(self, COAP_OPTION_URI_PATH,"core")) {
				smcp_inbound_next_option(self, NULL, NULL);
				prefix = "";
			} else {
				ret = SMCP_STATUS_NOT_ALLOWED;
				goto bail;
			}
		}
	}

	if(smcp_inbound_option_strequal_const(self, COAP_OPTION_URI_PATH,"")) {
		// Handle trailing '/'.
		smcp_inbound_next_option(self, NULL, NULL);
		if(prefix[0]) prefix = NULL;
	}

	// Check over the headers to make sure they are sane.
	{
		coap_option_key_t key;
		const uint8_t* value;
		coap_size_t value_len;
		while((key=smcp_inbound_next_option(self, &value, &value_len))!=COAP_OPTION_INVALID) {
			require_action(key!=COAP_OPTION_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);
			if(key == COAP_OPTION_URI_QUERY) {
				// Skip URI query components for now.
//			} else if(key == COAP_OPTION_SIZE_REQUEST) {
//				uint8_t i;
//				content_break_threshold = 0;
//				for(i = 0; i < value_len; i++)
//					content_break_threshold =
//						(content_break_threshold << 8) + value[i];
//				if(content_break_threshold >= sizeof(replyContent)) {
//					DEBUG_PRINTF(
//						"Requested size (%d) is too large, trimming to %d.",
//						(int)content_break_threshold,
//						(int)sizeof(replyContent) - 1
//					);
//					content_break_threshold = sizeof(replyContent) - 1;
//				}
			} else {
				if(COAP_OPTION_IS_CRITICAL(key)) {
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

	if(((smcp_node_t)node)->children)
#if SMCP_NODE_ROUTER_USE_BTREE
		node = bt_first(((smcp_node_t)node)->children);
#else
		node = ((smcp_node_t)node)->children;
#endif
	else
		node = NULL;

	ret = smcp_outbound_begin_response(self, COAP_RESULT_205_CONTENT);
	require_noerr(ret, bail);

	ret = smcp_outbound_add_option_uint(self, COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);
	require_noerr(ret, bail);

	replyContent = smcp_outbound_get_content_ptr(self, &content_break_threshold);
	require(NULL != replyContent, bail);

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

		if(prefix) {
			size_t len = strlen(replyContent);
			if(content_break_threshold-1>len)
				url_encode_cstr(replyContent+len, prefix, content_break_threshold - len);
			strlcat(replyContent, "/", content_break_threshold);
		}

		{
			size_t len = strlen(replyContent);
			if(content_break_threshold-1>len)
				url_encode_cstr(replyContent+len, node_name, content_break_threshold - len);
		}

		if(node->children)
			strlcat(replyContent, "/", content_break_threshold);

		strlcat(replyContent, ">", content_break_threshold);

		if(node->children || node->has_link_content)
			strlcat(replyContent, ";ct=40", content_break_threshold);

		if(node->is_observable)
			strlcat(replyContent, ";obs", content_break_threshold);

#if SMCP_NODE_ROUTER_USE_BTREE
		next = bt_next((void*)node);
#else
		next = ll_next((void*)node);
#endif

		node = next;
#if SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
		strlcat(replyContent, &",\n"[!node], content_break_threshold);
#else
		strlcat(replyContent, &","[!node], content_break_threshold);
#endif
	}

	ret = smcp_outbound_set_content_len(self, strlen(replyContent));
	require_noerr(ret,bail);

	ret = smcp_outbound_send(self);

bail:
	return ret;
}

#endif // #if SMCP_CONF_NODE_ROUTER
