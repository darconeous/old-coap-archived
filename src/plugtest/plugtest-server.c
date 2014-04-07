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

#include <smcp/assert-macros.h>
#include <stdlib.h>

#include <smcp/smcp.h>
#include "plugtest-server.h"

#if CONTIKI && !defined(time)
#define time(x)		clock_seconds()
#endif

#define PLUGTEST_OBS_KEY			(42)

smcp_status_t
plugtest_test_handler(smcp_node_t node)
{
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	char* content = NULL;
	coap_size_t max_len = 0;
	smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	} else if(method==COAP_METHOD_POST) {
		ret = smcp_outbound_begin_response(COAP_RESULT_201_CREATED);
	} else if(method==COAP_METHOD_PUT) {
		ret = smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
	} else if(method==COAP_METHOD_DELETE) {
		ret = smcp_outbound_begin_response(COAP_RESULT_202_DELETED);
	}

	if(ret) goto bail;

	smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);

	content = smcp_outbound_get_content_ptr(&max_len);
	if(!content) {
		ret = SMCP_STATUS_FAILURE;
		goto bail;
	}

	smcp_inbound_get_path(content, SMCP_GET_PATH_LEADING_SLASH|SMCP_GET_PATH_INCLUDE_QUERY);
	strlcat(content,"\nPlugtest!\nMethod = ",max_len);
	strlcat(content,coap_code_to_cstr(method),max_len);
	strlcat(content,"\n",max_len);

	{
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;
		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
			strlcat(content,coap_option_key_to_cstr(key,1),max_len);
			strlcat(content,": ",max_len);
			if(coap_option_value_is_string(key)) {
				size_t argh = strlen(content)+value_len;
				strlcat(content,(char*)value,MIN(max_len,argh+1));
				content[argh] = 0;
			} else {
				strlcat(content,"<binary>",max_len);
			}
			strlcat(content,"\n",max_len);
		}
	}

	smcp_outbound_set_content_len(strlen(content));

	ret = smcp_outbound_send();

bail:
	return ret;
}

smcp_status_t
plugtest_separate_async_resend_response(void* context)
{
	smcp_status_t ret = 0;
	struct smcp_async_response_s* async_response = (void*)context;

#if !SMCP_AVOID_PRINTF
	printf("Resending async response. . . %p\n",async_response);
#endif

	ret = smcp_outbound_begin_async_response(COAP_RESULT_205_CONTENT,async_response);
	require_noerr(ret,bail);

	ret = smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
	require_noerr(ret,bail);

	ret = smcp_outbound_append_content("This was an asynchronous response!",SMCP_CSTR_LEN);
	require_noerr(ret,bail);

	ret = smcp_outbound_send();
	require_noerr(ret,bail);

bail:
	return ret;
}

smcp_status_t
plugtest_separate_async_ack_handler(int statuscode, void* context) {
	struct smcp_async_response_s* async_response = (void*)context;

#if !SMCP_AVOID_PRINTF
	printf("Finished sending async response. code=%d async_response=%p\n",statuscode,async_response);
#endif
	if(statuscode == SMCP_STATUS_TRANSACTION_INVALIDATED) {
		smcp_finish_async_response(async_response);
		free(async_response);
	}

	return SMCP_STATUS_OK;
}

smcp_status_t
plugtest_separate_handler(
	smcp_node_t		node
) {
	struct smcp_async_response_s* async_response = NULL;
	smcp_transaction_t transaction = NULL;
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		if(smcp_inbound_is_dupe()) {
			smcp_outbound_begin_response(COAP_CODE_EMPTY);
			smcp_outbound_send();
			ret = SMCP_STATUS_OK;
			goto bail;
		}

		async_response = calloc(sizeof(struct smcp_async_response_s),1);
		if(!async_response) {
			ret = SMCP_STATUS_MALLOC_FAILURE;
			goto bail;
		}

#if !SMCP_AVOID_PRINTF
		printf("This request needs an async response. %p\n",async_response);
#endif

		transaction = smcp_transaction_init(
			NULL,
			SMCP_TRANSACTION_DELAY_START|SMCP_TRANSACTION_ALWAYS_INVALIDATE,
			&plugtest_separate_async_resend_response,
			&plugtest_separate_async_ack_handler,
			(void*)async_response
		);
		if(!transaction) {
			free(async_response);
			// TODO: Consider dropping instead...?
			ret = SMCP_STATUS_MALLOC_FAILURE;
			goto bail;
		}

		ret = smcp_transaction_begin(
			smcp_get_current_instance(),
			transaction,
			(smcp_inbound_get_packet()->tt==COAP_TRANS_TYPE_CONFIRMABLE)?COAP_MAX_TRANSMIT_WAIT*MSEC_PER_SEC:1
		);
		if(SMCP_STATUS_OK != ret) {
			smcp_transaction_end(smcp_get_current_instance(),transaction);
			goto bail;
		}

		ret = smcp_start_async_response(async_response,0);
		if(ret) { goto bail; }

		async_response = NULL;
	}

bail:
	return ret;
}

void
plugtest_obs_timer_callback(smcp_t smcp, void* context) {
	struct plugtest_server_s *self = (void*)context;

	smcp_invalidate_timer(smcp,&self->obs_timer);
	smcp_schedule_timer(smcp,&self->obs_timer,5 * MSEC_PER_SEC);

	smcp_observable_trigger(&self->observable,PLUGTEST_OBS_KEY,0);
}

smcp_status_t
plugtest_obs_handler(
	struct plugtest_server_s *self
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		char* content = NULL;
		coap_size_t max_len = 0;

		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		require_noerr(ret, bail);

		ret = smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
		require_noerr(ret, bail);

		if(!smcp_timer_is_scheduled(smcp_get_current_instance(), &self->obs_timer))
			plugtest_obs_timer_callback(smcp_get_current_instance(),self);

		ret = smcp_observable_update(&self->observable,PLUGTEST_OBS_KEY);
		check_noerr(ret);

		ret = smcp_outbound_add_option_uint(COAP_OPTION_MAX_AGE,10);
		require_noerr(ret, bail);

		content = smcp_outbound_get_content_ptr(&max_len);
		require_action(content!=NULL, bail, ret = SMCP_STATUS_FAILURE);

		require_action(max_len>11, bail, ret = SMCP_STATUS_MESSAGE_TOO_BIG);

		ret = smcp_outbound_set_content_len(
			strlen(uint32_to_dec_cstr(content, (uint32_t)time(NULL)))
		);
		require_noerr(ret, bail);

		ret = smcp_outbound_send();
		require_noerr(ret, bail);
	}
bail:
	return ret;
}

smcp_status_t
plugtest_large_handler(
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	char* content = NULL;
	coap_size_t max_len = 0;
	smcp_method_t method = smcp_inbound_get_code();
	uint32_t block_option = 0x03;
	uint32_t block_start = 0;
	uint32_t block_stop = 0;
	uint32_t resource_length = 2000;

	if(method==COAP_METHOD_GET) {
		ret = 0;
	}

	require_noerr(ret,bail);

	{
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;
		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
			if(key == COAP_OPTION_BLOCK2) {
				uint8_t i;
				block_option = 0;
				for(i = 0; i < value_len; i++)
					block_option = (block_option << 8) + value[i];
			}
		}
	}

	ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(ret,bail);

	ret = smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
	require_noerr(ret,bail);

	ret = smcp_outbound_add_option_uint(COAP_OPTION_MAX_AGE,60*60);
	require_noerr(ret,bail);

	max_len = smcp_outbound_get_space_remaining()-2;

	// Here we are making sure our data will fit,
	// and adjusting our block-option size accordingly.
	do {
		struct coap_block_info_s block_info;
		coap_decode_block(&block_info, block_option);
		block_start = block_info.block_offset;
		block_stop = block_info.block_offset + block_info.block_size;

		if(max_len<(block_stop-block_start) && block_option!=0 && !block_info.block_offset) {
			block_option--;
			block_stop = 0;
			continue;
		}
	} while(0==block_stop);

	require_action(block_start<resource_length,bail,ret=SMCP_STATUS_INVALID_ARGUMENT);

	if(block_stop>=resource_length)
		block_option &= ~(1<<3);
	else
		block_option |= (1<<3);

	ret = smcp_outbound_add_option_uint(COAP_OPTION_BLOCK2,block_option);
	require_noerr(ret,bail);

	content = smcp_outbound_get_content_ptr(&max_len);

	require_action(NULL!=content, bail, ret = SMCP_STATUS_FAILURE);
	require_action(max_len>(block_stop-block_start), bail, ret = SMCP_STATUS_MESSAGE_TOO_BIG);

	{
		uint32_t i;
		for(i=block_start;i<block_stop;i++) {
			if(!((i+1)%64))
				content[i-block_start] = '\n';
			else
				content[i-block_start] = '0'+(i%10);
		}
	}

	ret = smcp_outbound_set_content_len(MIN(block_stop-block_start,resource_length-block_start));
	if(ret) goto bail;

	ret = smcp_outbound_send();

bail:
	return ret;
}

/*
// Not yet implemented.

smcp_status_t
plugtest_large_update_handler(
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}

smcp_status_t
plugtest_large_create_handler(
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}
*/

smcp_status_t
plugtest_server_init(struct plugtest_server_s *self,smcp_node_t root) {

	memset(self,0,sizeof(*self));

	smcp_node_init(&self->test,root,"test");
	self->test.request_handler = (smcp_callback_func)&plugtest_test_handler;

	smcp_node_init(&self->seg1,root,"seg1");
	smcp_node_init(&self->seg2,&self->seg1,"seg2");
	smcp_node_init(&self->seg3,&self->seg2,"seg3");
	self->seg3.request_handler = (smcp_callback_func)&plugtest_test_handler;

	smcp_node_init(&self->separate,root,"separate");
	self->separate.request_handler = (smcp_callback_func)&plugtest_separate_handler;

	smcp_node_init(&self->query,root,"query");
	self->query.request_handler = (smcp_callback_func)&plugtest_test_handler;

	smcp_node_init(&self->large,root,"large");
	self->large.request_handler = (smcp_callback_func)&plugtest_large_handler;

/*
	// Not yet implemented.
	smcp_node_init(&self->large_update,root,"large_update");
	self->large_update.request_handler = &plugtest_large_update_handler;

	smcp_node_init(&self->large_create,root,"large_create");
	self->large_create.request_handler = &plugtest_large_create_handler;
*/

	smcp_node_init(&self->obs,root,"obs");
	self->obs.request_handler = (smcp_callback_func)&plugtest_obs_handler;
	self->obs.context = (void*)self;
	self->obs.is_observable = true;

	smcp_timer_init(&self->obs_timer,&plugtest_obs_timer_callback,NULL,(void*)self);

	return SMCP_STATUS_OK;
}
