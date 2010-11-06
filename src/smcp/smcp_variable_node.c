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
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_status_t ret = SMCP_STATUS_NOT_FOUND;

	require(node, bail);

	if(path && path[0] != 0) {
		ret = SMCP_STATUS_NOT_FOUND;
		goto bail;
	}


	if(method == COAP_METHOD_PUT)
		// TODO: Implement me!
		method = COAP_METHOD_POST;

	if(method == COAP_METHOD_POST) {
		coap_content_type_t content_type = COAP_CONTENT_TYPE_TEXT_PLAIN;

		const coap_header_item_t *next_header =
		    smcp_daemon_get_current_request_headers();
		for(;
		    smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header)) {
			if(smcp_header_item_key_equal(next_header,
					COAP_HEADER_CONTENT_TYPE))
				content_type = *(unsigned char*)smcp_header_item_get_value(
					next_header);
		}
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
		if(((smcp_variable_node_t)node)->post_func) {
			ret = (*((smcp_variable_node_t)node)->post_func)(
				    ((smcp_variable_node_t)node),
				    (char*)content,
				content_length,
				content_type
			    );
		}
	} else if(method == COAP_METHOD_GET) {
		char replyContent[SMCP_MAX_CONTENT_LENGTH];
		size_t replyContentLength = sizeof(replyContent);
		coap_content_type_t replyContentType =
		    COAP_CONTENT_TYPE_TEXT_PLAIN;
		coap_header_item_t replyHeaders[2] = {};

		ret = SMCP_STATUS_NOT_IMPLEMENTED;
		if(((smcp_variable_node_t)node)->get_func) {
			ret = (*((smcp_variable_node_t)node)->get_func)(
				    (smcp_variable_node_t)node,
				replyContent,
				&replyContentLength,
				&replyContentType
			    );
		}

		if(ret == SMCP_STATUS_OK) {
			util_add_header(replyHeaders, 1, COAP_HEADER_CONTENT_TYPE,
				    (const void*)&replyContentType, 1);
			smcp_daemon_send_response(COAP_RESULT_CODE_OK,
				replyHeaders,
				replyContent,
				replyContentLength);
		}
	} else {
		ret = smcp_default_request_handler(node,
			method,
			path,
			content,
			content_length);
		//ret = SMCP_STATUS_NOT_IMPLEMENTED;
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
