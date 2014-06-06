/*	@file smcp_variable_node.c
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

#include "assert-macros.h"

#include "smcp-opts.h"
#include "smcp.h"
#include "smcp-helpers.h"
#include "smcp-variable_node.h"
#include "smcp-logging.h"
#include "fasthash.h"
#include "smcp-node-router.h"

#include "url-helpers.h"
#include <stdlib.h>

#define BAD_KEY_INDEX		(255)

smcp_status_t
smcp_variable_node_request_handler(
	smcp_t self,
	smcp_variable_node_t		node
) {
	// TODO: Make this function use less stack space!

	smcp_method_t method = smcp_inbound_get_code(self);
	smcp_status_t ret = SMCP_STATUS_NOT_FOUND;
	SMCP_NON_RECURSIVE coap_content_type_t content_type;
	SMCP_NON_RECURSIVE char* content_ptr;
	SMCP_NON_RECURSIVE coap_size_t content_len;
	SMCP_NON_RECURSIVE char buffer[SMCP_VARIABLE_MAX_VALUE_LENGTH+1];
	SMCP_NON_RECURSIVE coap_content_type_t reply_content_type;
	uint8_t key_index = BAD_KEY_INDEX;
	coap_size_t value_len;
	bool needs_prefix = true;
	char* prefix_name = "";

	content_type = smcp_inbound_get_content_type(self);
	content_ptr = (char*)smcp_inbound_get_content_ptr(self);
	content_len = smcp_inbound_get_content_len(self);

	reply_content_type = SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;

	require(node, bail);

	// Look up the key index.
	if(smcp_inbound_peek_option(self,NULL,&value_len)==COAP_OPTION_URI_PATH) {
		if(!value_len) {
			needs_prefix = false;
			smcp_inbound_next_option(self,NULL,NULL);
		} else for(key_index=0;key_index<BAD_KEY_INDEX;key_index++) {
			ret = node->func(node,SMCP_VAR_GET_KEY,key_index,buffer);
			require_action(ret==0,bail,ret=SMCP_STATUS_NOT_FOUND);
			if(smcp_inbound_option_strequal(self, COAP_OPTION_URI_PATH, buffer)) {
				smcp_inbound_next_option(self,NULL,NULL);
				break;
			}
		}
	}

	{
		coap_option_key_t key;
		const uint8_t* value;
		while((key=smcp_inbound_next_option(self, &value, &value_len))!=COAP_OPTION_INVALID) {
			require_action(key!=COAP_OPTION_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);
			if(key==COAP_OPTION_URI_QUERY) {
				if(	method == COAP_METHOD_POST
					&& value_len>=2
					&& strhasprefix_const((const char*)value,"v=")
				) {
					DEBUG_PRINTF("variable-node: value is in the query.");
					content_type = COAP_CONTENT_TYPE_TEXT_PLAIN;
					content_ptr = (char*)value+2;
					content_len = value_len-2;
				}
//			} else if(key==COAP_OPTION_ETAG) {
//			} else if(key==COAP_OPTION_IF_MATCH) {
//			} else if(key==COAP_OPTION_IF_NONE_MATCH) {
			} else if(key==COAP_OPTION_ACCEPT) {
				reply_content_type = 0;
				if(value_len==1)
					reply_content_type = value[0];
				else {
					// Unsupported type.
				}
			} else if(COAP_OPTION_IS_CRITICAL(key)) {
				ret=SMCP_STATUS_BAD_OPTION;
				assert_printf("Unrecognized option %d, \"%s\"",
					key,
					coap_option_key_to_cstr(key, false)
				);
				goto bail;
			}
		}
	}

	// TODO: Implement me!
	if(method == COAP_METHOD_PUT)
		method = COAP_METHOD_POST;

	if(method == COAP_METHOD_POST) {
		require_action(!smcp_inbound_is_dupe(self),bail,ret=0);

		require_action(
			key_index!=BAD_KEY_INDEX,
			bail,
			ret=SMCP_STATUS_NOT_ALLOWED
		);
		if(content_type==SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED) {
			char* key = NULL;
			char* value = NULL;
			content_len = 0;
			while(
				url_form_next_value(
					(char**)&content_ptr,
					&key,
					&value
				)
				&& key
				&& value
			) {
				if(strequal_const(key, "v")) {
					content_ptr = value;
					content_len = strlen(value);
					break;
				}
			}
		}

		// Make sure our content is zero terminated.
		((char*)content_ptr)[content_len] = 0;

		ret = node->func(node,SMCP_VAR_SET_VALUE,key_index,(char*)content_ptr);
		require_noerr(ret,bail);

		ret = smcp_outbound_begin_response(self, COAP_RESULT_204_CHANGED);
		require_noerr(ret,bail);

		ret = smcp_outbound_send(self);
		require_noerr(ret,bail);
	} else if(method == COAP_METHOD_GET) {

		if(key_index==BAD_KEY_INDEX) {
			char* content_end_ptr;

			ret = smcp_outbound_begin_response(self, COAP_RESULT_205_CONTENT);
			require_noerr(ret,bail);

			smcp_outbound_add_option_uint(self, COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);

			ret = smcp_observable_update(self, &node->observable, SMCP_OBSERVABLE_BROADCAST_KEY);
			check_string(ret==0,smcp_status_to_cstr(ret));

			content_ptr = smcp_outbound_get_content_ptr(self, &content_len);
			content_end_ptr = content_ptr+content_len;

			for(key_index=0;key_index<BAD_KEY_INDEX;key_index++) {
				ret = node->func(node,SMCP_VAR_GET_KEY,key_index,buffer);
				if(ret) break;

				if(content_ptr+2>=content_end_ptr) {
					// No more room for content.
					break;
				}

				*content_ptr++ = '<';
				if(needs_prefix) {
					content_ptr += url_encode_cstr(content_ptr, prefix_name, (content_end_ptr-content_ptr)-1);
					content_ptr = stpncpy(content_ptr,"/",MIN(1,(content_end_ptr-content_ptr)-1));
				}
				content_ptr += url_encode_cstr(content_ptr, buffer, (content_end_ptr-content_ptr)-1);
				*content_ptr++ = '>';

				ret = node->func(node,SMCP_VAR_GET_VALUE,key_index,buffer);

				if(content_ptr+4>=content_end_ptr) {
					// No more room for content.
					break;
				}

				if(!ret) {
					strcpy(content_ptr,";v=");
					content_ptr += 3;
					content_ptr += quoted_cstr(content_ptr, buffer, (content_end_ptr-content_ptr)-1);
				}

				ret = node->func(node,SMCP_VAR_GET_LF_TITLE,key_index,buffer);

				if(content_ptr+8>=content_end_ptr) {
					// No more room for content.
					break;
				}

				if(!ret) {
					strcpy(content_ptr,";title=");
					content_ptr += 7;
					content_ptr += quoted_cstr(content_ptr, buffer, (content_end_ptr-content_ptr)-1);
				}

				// Observation flag
				if(0==node->func(node,SMCP_VAR_GET_OBSERVABLE,key_index,NULL)) {
					content_ptr = stpncpy(content_ptr,";obs",MIN(4,(content_end_ptr-content_ptr)-1));
				}

				*content_ptr++ = ',';
			}
			ret = smcp_outbound_set_content_len(self, content_len-(content_end_ptr-content_ptr));
			require_noerr(ret,bail);

			ret = smcp_outbound_send(self);
		} else {
			coap_size_t replyContentLength = 0;
			char *replyContent;

			ret = smcp_outbound_begin_response(self, COAP_RESULT_205_CONTENT);
			require_noerr(ret,bail);

			if(0==node->func(node,SMCP_VAR_GET_OBSERVABLE,key_index,buffer)) {
				ret = smcp_observable_update(self, &node->observable, key_index);
				check_string(ret==0,smcp_status_to_cstr(ret));
			}

			if(reply_content_type == SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED) {
				uint32_t etag;

				if(0==node->func(node,SMCP_VAR_GET_MAX_AGE,key_index,buffer)) {
#if HAVE_STRTOL
					uint32_t max_age = strtol(buffer,NULL,0)&0xFFFFFF;
#else
					uint32_t max_age = atoi(buffer)&0xFFFFFF;
#endif
					smcp_outbound_add_option_uint(self, COAP_OPTION_MAX_AGE, max_age);
				}

				ret = node->func(node,SMCP_VAR_GET_VALUE,key_index,buffer);
				require_noerr(ret,bail);

				fasthash_start(0);
				fasthash_feed((const uint8_t*)buffer,strlen(buffer));
				etag = fasthash_finish_uint32();

				smcp_outbound_add_option_uint(self, COAP_OPTION_CONTENT_TYPE, SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);

				smcp_outbound_add_option_uint(self, COAP_OPTION_ETAG, etag);

				replyContent = smcp_outbound_get_content_ptr(self, &replyContentLength);

				*replyContent++ = 'v';
				*replyContent++ = '=';
				replyContentLength -= 2;
				replyContentLength = url_encode_cstr(
					replyContent,
					buffer,
					replyContentLength
				);
				ret = smcp_outbound_set_content_len(self, replyContentLength+2);
			} else {
				ret = node->func(node,SMCP_VAR_GET_VALUE,key_index,buffer);
				require_noerr(ret,bail);

				ret = smcp_outbound_append_content(self, buffer, SMCP_CSTR_LEN);
			}

			require_noerr(ret,bail);

			ret = smcp_outbound_send(self);
		}
	} else {
		ret = smcp_default_request_handler(
			self,
			(void*)node
		);
		check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));
	}

bail:
	check_string(ret == SMCP_STATUS_OK, smcp_status_to_cstr(ret));
	return ret;
}

