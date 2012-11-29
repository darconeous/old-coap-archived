/*	@file plugtest-server.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Plugtest Server Object
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

#include <smcp/assert_macros.h>
#include <stdlib.h>

#include <smcp/smcp.h>
#include "plugtest-server.h"


smcp_status_t
plugtest_test_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	char* content = NULL;
	size_t max_len = 0;

	if(method==COAP_METHOD_GET) {
		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	} else if(method==COAP_METHOD_POST) {
		ret = smcp_outbound_begin_response(COAP_RESULT_201_CREATED);
	} else if(method==COAP_METHOD_PUT) {
		ret = smcp_outbound_begin_response(COAP_RESULT_203_VALID);
	} else if(method==COAP_METHOD_DELETE) {
		ret = smcp_outbound_begin_response(COAP_RESULT_202_DELETED);
	}

	if(ret) goto bail;

	smcp_outbound_set_content_type(0);

	content = smcp_outbound_get_content_ptr(&max_len);
	if(!content) {
		ret = SMCP_STATUS_FAILURE;
		goto bail;
	}

	ret = smcp_outbound_set_content_len(
		snprintf(content,max_len,"Plugtest! Method = %d\n",method)
	);
	if(ret) goto bail;

	ret = smcp_outbound_send();

bail:
	return ret;
}

smcp_status_t
plugtest_query_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}




smcp_status_t
plugtest_separate_async_resend_response(void* context) {
	smcp_status_t ret = 0;
	struct smcp_async_response_s* async_response = (void*)context;

	printf("Resending async response. . .\n");

	ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(ret,bail);

	ret = smcp_outbound_set_content_type(COAP_CONTENT_TYPE_TEXT_PLAIN);
	require_noerr(ret,bail);

	ret = smcp_outbound_set_async_response(async_response);
	require_noerr(ret,bail);

	ret = smcp_outbound_set_content_formatted("This was an asynchronous response!");
	require_noerr(ret,bail);

	ret = smcp_outbound_send();
	require_noerr(ret,bail);

bail:
	return ret;
}

smcp_status_t
plugtest_separate_async_ack_handler(int statuscode, void* context) {
	struct smcp_async_response_s* async_response = (void*)context;

	printf("Finished sending async response.\n");

	smcp_finish_async_response(async_response);
	free(async_response);

	return SMCP_STATUS_OK;
}

smcp_status_t
plugtest_separate_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	struct smcp_async_response_s* async_response = NULL;
	smcp_transaction_t transaction = NULL;
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	if(method==COAP_METHOD_GET) {
		printf("This request needs an async response.\n");

		if(smcp_inbound_is_dupe()) {
			ret = SMCP_STATUS_DUPE;
			goto bail;
		}

		async_response = calloc(sizeof(struct smcp_async_response_s),1);
		if(!async_response) {
			ret = SMCP_STATUS_MALLOC_FAILURE;
			goto bail;
		}

		ret = smcp_start_async_response(async_response,0);
		if(ret) { goto bail; }

		transaction = smcp_transaction_init(
			NULL,
			SMCP_TRANSACTION_DELAY_START,
			&plugtest_separate_async_resend_response,
			&plugtest_separate_async_ack_handler,
			(void*)async_response
		);
		if(!transaction) {
			ret = SMCP_STATUS_MALLOC_FAILURE;
			goto bail;
		}

		async_response = NULL;

		ret = smcp_transaction_begin(
			smcp_get_current_instance(),
			transaction,
			30*MSEC_PER_SEC
		);
		if(ret) {
			smcp_transaction_end(smcp_get_current_instance(),transaction);
			goto bail;
		}
	}

bail:
	if(async_response)
		free(async_response);
	return ret;
}

smcp_status_t
plugtest_large_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}

smcp_status_t
plugtest_large_update_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}

smcp_status_t
plugtest_large_create_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}

smcp_status_t
plugtest_obs_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	if(method==COAP_METHOD_GET) {
		char* content = NULL;
		size_t max_len = 0;

		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

		smcp_outbound_set_content_type(0);

		ret = smcp_pair_inbound_observe_update();
		if(ret) goto bail;

		// Kind of a silly way to set the max-age to '10'.
		ret = smcp_outbound_add_option(COAP_HEADER_MAX_AGE,"\x0a",1);
		if(ret) goto bail;

		content = smcp_outbound_get_content_ptr(&max_len);
		if(!content) {
			ret = SMCP_STATUS_FAILURE;
			goto bail;
		}

		ret = smcp_outbound_set_content_len(
			snprintf(content,max_len,"%d",time(NULL))
		);
		if(ret) goto bail;

		ret = smcp_outbound_send();
	}
bail:
	return ret;
}

void
plugtest_obs_timer_callback(smcp_t smcp, void* context) {
	struct plugtest_server_s *self = (void*)context;

	smcp_invalidate_timer(smcp,&self->obs_timer);
	smcp_schedule_timer(smcp,&self->obs_timer,5 * MSEC_PER_SEC);

	smcp_trigger_event_with_node(smcp,&self->obs,NULL);
}

smcp_status_t
plugtest_server_init(struct plugtest_server_s *self,smcp_node_t root) {

	bzero(self,sizeof(*self));

	smcp_node_init(&self->test,root,"test");
	self->test.request_handler = &plugtest_test_handler;

	smcp_node_init(&self->seg1,root,"seg1");
	smcp_node_init(&self->seg2,&self->seg1,"seg2");
	smcp_node_init(&self->seg3,&self->seg2,"seg3");
	self->seg3.request_handler = &plugtest_test_handler;

	smcp_node_init(&self->separate,root,"separate");
	self->separate.request_handler = &plugtest_separate_handler;

/*
	smcp_node_init(&self->query,root,"query");
	self->query.request_handler = &plugtest_query_handler;

	smcp_node_init(&self->large,root,"large");
	self->large.request_handler = &plugtest_large_handler;

	smcp_node_init(&self->large_update,root,"large_update");
	self->large_update.request_handler = &plugtest_large_update_handler;

	smcp_node_init(&self->large_create,root,"large_create");
	self->large_create.request_handler = &plugtest_large_create_handler;
*/

	smcp_node_init(&self->obs,root,"obs");
	self->obs.request_handler = &plugtest_obs_handler;

	smcp_timer_init(&self->obs_timer,&plugtest_obs_timer_callback,NULL,(void*)self);

	// Starts the timer
	plugtest_obs_timer_callback((smcp_t)smcp_node_get_root(root),(void*)self);

	return SMCP_STATUS_OK;
}
