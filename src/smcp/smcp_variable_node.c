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
	coap_content_type_t content_type = smcp_daemon_get_current_inbound_content_type();

	require(node, bail);

	{
		coap_header_key_t key;
		uint8_t* value;
		size_t value_len;
		while((key==smcp_current_request_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {
			require_action(key!=COAP_HEADER_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);

			require_action(
				!COAP_HEADER_IS_REQUIRED(key),
				bail,
				ret=SMCP_STATUS_BAD_OPTION
			);
		}
	}

	// TODO: Implement me!
	if(method == COAP_METHOD_PUT)
		method = COAP_METHOD_POST;

	if(method == COAP_METHOD_POST) {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
		if(((smcp_variable_node_t)node)->post_func) {
			ret = (*((smcp_variable_node_t)node)->post_func)(
				((smcp_variable_node_t)node),
				smcp_daemon_get_current_inbound_content_ptr(),
				smcp_daemon_get_current_inbound_content_len(),
				content_type
			);
			require_noerr(ret,bail);
		}
	} else if(method == COAP_METHOD_GET) {
		if(((smcp_variable_node_t)node)->get_func) {
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

			smcp_message_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_OK));
			smcp_message_set_content_type(replyContentType);
			replyContent = smcp_message_get_content_ptr(&replyContentLength);
			ret = (*((smcp_variable_node_t)node)->get_func)(
				(smcp_variable_node_t)node,
				replyContent,
				&replyContentLength,
				&replyContentType
			);
			smcp_message_set_content_len(replyContentLength);
			smcp_message_send();
		} else {
			ret = SMCP_STATUS_NOT_IMPLEMENTED;
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
