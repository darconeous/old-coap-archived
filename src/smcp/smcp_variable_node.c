
#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert_macros.h"
#include "smcp_node.h"
#include "smcp_variable_node.h"
#include <stdlib.h>

void
smcp_variable_node_dealloc(smcp_variable_node_t x) {
	free(x);
}

smcp_variable_node_t
smcp_variable_node_alloc() {
	smcp_variable_node_t ret =
	    (smcp_variable_node_t)calloc(sizeof(struct smcp_variable_node_s),
		1);

	ret->node.finalize = (void (*)(smcp_node_t)) &
	    smcp_variable_node_dealloc;
	return ret;
}


smcp_status_t
smcp_variable_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_FOUND;
	coap_content_type_t content_type = smcp_inbound_get_content_type();
	const char* content_ptr = smcp_inbound_get_content_ptr();
	size_t content_len = smcp_inbound_get_content_len();
	require(node, bail);

	{
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		while((key=smcp_inbound_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {
			require_action(key!=COAP_HEADER_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);
			if(key==COAP_HEADER_URI_QUERY) {
				if(	method == COAP_METHOD_POST
					&& value_len>=2
					&& strhasprefix_const((const char*)value,"v=")
				) {
					content_type = COAP_CONTENT_TYPE_TEXT_PLAIN;
					content_ptr = (const char*)value+2;
					content_len = value_len-2;
				}
				continue;
			}
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

	// TODO: Implement me!
	if(method == COAP_METHOD_PUT)
		method = COAP_METHOD_POST;

	if(method == COAP_METHOD_POST) {
		require_action(((smcp_variable_node_t)node)->post_func!=NULL,bail,ret=SMCP_STATUS_NOT_ALLOWED);
		ret = (*((smcp_variable_node_t)node)->post_func)(
			((smcp_variable_node_t)node),
			content_ptr,
			content_len,
			content_type
		);
		require_noerr(ret,bail);

		ret = smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
		require_noerr(ret,bail);

		ret = smcp_outbound_send();
		require_noerr(ret,bail);
	} else if(method == COAP_METHOD_GET) {
		require_action(((smcp_variable_node_t)node)->get_func!=NULL,bail,ret=SMCP_STATUS_NOT_ALLOWED);
		{
			size_t replyContentLength = 0;
			char *replyContent;
			coap_content_type_t replyContentType;

			ret = (*((smcp_variable_node_t)node)->get_func)(
				(smcp_variable_node_t)node,
				NULL,
				&replyContentLength,
				&replyContentType
			);
			require_noerr(ret,bail);

			ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
			require_noerr(ret,bail);

			smcp_outbound_set_content_type(replyContentType);

			replyContent = smcp_outbound_get_content_ptr(&replyContentLength);

			ret = (*((smcp_variable_node_t)node)->get_func)(
				(smcp_variable_node_t)node,
				replyContent,
				&replyContentLength,
				&replyContentType
			);
			require_noerr(ret,bail);

			ret = smcp_outbound_set_content_len(replyContentLength);
			require_noerr(ret,bail);

			ret = smcp_outbound_send();
		}
	} else {
		ret = smcp_default_request_handler(
			node,
			method
		);
	}

bail:
	return ret;
}

smcp_variable_node_t
smcp_node_init_variable(
	smcp_variable_node_t self, smcp_node_t node, const char* name
) {
	smcp_variable_node_t ret = NULL;

	require(node, bail);

	require(self || (self = smcp_variable_node_alloc()), bail);

	ret = (smcp_variable_node_t)self;

	smcp_node_init(&ret->node, node, name);

	ret->node.request_handler = &smcp_variable_request_handler;

bail:
	return ret;
}
