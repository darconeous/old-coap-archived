/*	@file smcp_curl_proxy.c
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

#include "assert_macros.h"
#include "smcp.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"
#include "smcp-internal.h"
#include "coap.h"
#include "smcp-curl_proxy.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct smcp_curl_request_s {
	CURL* curl;
	struct smcp_async_response_s async_response;
	struct smcp_transaction_s async_transaction;
	smcp_curl_proxy_node_t proxy_node;
	char* content;
	size_t content_len;
	char* output_content;
	size_t output_content_len;
} *smcp_curl_request_t;

void
smcp_curl_request_release(smcp_curl_request_t x) {
	if(x->curl)
		curl_easy_cleanup(x->curl);
	free(x);
}

smcp_curl_request_t
smcp_curl_request_create(void) {
	smcp_curl_request_t ret = calloc(1,sizeof(*ret));
	ret->curl = curl_easy_init();
	if(!ret->curl) {
		smcp_curl_request_release(ret);
		ret = NULL;
	}
	return ret;
}

static smcp_status_t
resend_async_response(void* context) {
	smcp_status_t ret = 0;
	smcp_curl_request_t request = (smcp_curl_request_t)context;
	struct smcp_async_response_s* async_response = &request->async_response;

	size_t len = request->content_len;
	if(len>512) {
		len = 512;
	}

	{
		long code;
		curl_easy_getinfo(request->curl, CURLINFO_RESPONSE_CODE,&code);
		code = http_to_coap_code(code);

		ret = smcp_outbound_begin_response(code);
		require_noerr(ret,bail);
	}

	{
		const char* content_type_string;
		curl_easy_getinfo(request->curl, CURLINFO_CONTENT_TYPE,&content_type_string);
		coap_content_type_t content_type = coap_content_type_from_cstr(content_type_string);
		if(content_type!=COAP_CONTENT_TYPE_UNKNOWN) {
			ret = smcp_outbound_set_content_type(content_type);
			check_noerr(ret);
		} else {
			DEBUG_PRINTF("Unrecognised content-type: %s",content_type_string);
		}
	}

	ret = smcp_outbound_set_async_response(async_response);
	require_noerr(ret,bail);

	ret = smcp_outbound_append_content(request->content, len);
	require_noerr(ret,bail);

	ret = smcp_outbound_send();
	require_noerr(ret,bail);

	if(ret) {
		assert_printf(
			"smcp_outbound_send() returned error %d(%s).\n",
			ret,
			smcp_status_to_cstr(ret)
		);
		goto bail;
	}

bail:
	return ret;
}

static smcp_status_t
async_response_ack_handler(int statuscode, void* context) {
	smcp_curl_request_t request = (smcp_curl_request_t)context;
	struct smcp_async_response_s* async_response = &request->async_response;

	smcp_finish_async_response(async_response);
	smcp_curl_request_release(request);
	return SMCP_STATUS_OK;
}

static size_t
ReadMemoryCallback(void *ptr, size_t size, size_t nmemb, void *userp)
{
	smcp_curl_request_t request = (smcp_curl_request_t)userp;
	size_t len = MIN(size*nmemb,request->output_content_len);
	memcpy(ptr,request->output_content,len);
	return len;
}

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	smcp_curl_request_t request = (smcp_curl_request_t)userp;

	assert_printf("CuRL WriteMemoryCallback()",0);

	require_action(realsize>=0,bail,realsize=0);

	// At the moment limit to one call.
	require_action(request->content==NULL,bail,realsize=0);

	request->content = realloc(request->content, request->content_len + realsize + 1);

	require_action(request->content!=NULL,bail,realsize=0);

	memcpy(&(request->content[request->content_len]), contents, realsize);
	request->content_len += realsize;
	request->content[request->content_len] = 0;

	smcp_transaction_init(
		&request->async_transaction,
		0, // Flags
		(void*)&resend_async_response,
		(void*)&async_response_ack_handler,
		(void*)request
	);

	smcp_transaction_begin(
		(smcp_t)smcp_node_get_root(&request->proxy_node->node),
		&request->async_transaction,
		10*1000	// Retry for thirty seconds.
	);

bail:
	return realsize;
}

static smcp_status_t
smcp_curl_proxy_node_request_handler(
	smcp_curl_proxy_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	smcp_curl_request_t request = NULL;
	struct curl_slist *headerlist=NULL;

	//require_action(method<=COAP_METHOD_DELETE,bail,ret = SMCP_STATUS_NOT_ALLOWED);

	//require_action(COAP_HEADER_URI_PATH!=smcp_inbound_peek_option(NULL,NULL),bail,ret=SMCP_STATUS_NOT_FOUND);

	smcp_inbound_reset_next_option();

	request = smcp_curl_request_create();
	request->proxy_node = node;

	require_action(request!=NULL,bail,ret = SMCP_STATUS_MALLOC_FAILURE);

	switch(method) {
		case COAP_METHOD_GET: curl_easy_setopt(request->curl, CURLOPT_CUSTOMREQUEST, "GET"); break;
		case COAP_METHOD_PUT: curl_easy_setopt(request->curl, CURLOPT_PUT, 1L); break;
		case COAP_METHOD_POST: curl_easy_setopt(request->curl, CURLOPT_POST, 1L); break;
		case COAP_METHOD_DELETE: curl_easy_setopt(request->curl, CURLOPT_CUSTOMREQUEST, "DELETE"); break;
		default:
			ret = SMCP_STATUS_NOT_ALLOWED;
			break;
	}

	{
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_HEADER_INVALID) {
			if(key==COAP_HEADER_PROXY_URI) {
				char uri[value_len+1];
				memcpy(uri,value,value_len);
				uri[value_len] = 0;
				curl_easy_setopt(request->curl, CURLOPT_URL, uri);
				assert_printf("CuRL URL: \"%s\"",uri);
				ret = 0;
			} else if(key==COAP_HEADER_URI_HOST) {
			} else if(key==COAP_HEADER_URI_PORT) {
			} else if(key==COAP_HEADER_URI_PATH) {
			} else if(key==COAP_HEADER_URI_QUERY) {
			} else if(key==COAP_HEADER_TOKEN) {
			} else if(key==COAP_HEADER_CONTENT_TYPE || key==COAP_HEADER_ACCEPT) {
				const char* option_name = coap_option_key_to_cstr(key, false);
				const char* value_string = coap_content_type_to_cstr(value[1]);
				char header[strlen(option_name)+strlen(value_string)+3];
				strcpy(header,option_name);
				strcat(header,": ");
				strcat(header,value_string);
				headerlist = curl_slist_append(headerlist, header);
				assert_printf("CuRL HEADER: \"%s\"",header);
			} else {
				if(coap_option_value_is_string(key)) {
					const char* option_name = coap_option_key_to_cstr(key, false);
					char header[strlen(option_name)+value_len+3];
					strcpy(header,option_name);
					strcat(header,": ");
					strncat(header,(const char*)value,value_len);
					assert_printf("CuRL HEADER: \"%s\"",header);
					headerlist = curl_slist_append(headerlist, header);
				}
			}
		}
	}

	require_noerr(ret,bail);

	if(smcp_inbound_get_content_len()) {
		size_t len = smcp_inbound_get_content_len();
		request->output_content = calloc(1,len+1);
		request->output_content_len = len;
		memcpy(request->output_content,smcp_inbound_get_content_ptr(),len);
		curl_easy_setopt(request->curl, CURLOPT_READFUNCTION, ReadMemoryCallback);
		curl_easy_setopt(request->curl, CURLOPT_READDATA, (void *)request);
	}

	curl_easy_setopt(request->curl, CURLOPT_USERAGENT, "smcp-curl-proxy/1.0");
	curl_easy_setopt(request->curl, CURLOPT_HTTPHEADER, headerlist),headerlist=NULL;
	curl_easy_setopt(request->curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(request->curl, CURLOPT_WRITEDATA, (void *)request);

	ret = smcp_start_async_response(&request->async_response,0);
	require_noerr(ret,bail);

	if(node->curl_multi_handle)
		curl_multi_add_handle(node->curl_multi_handle, request->curl);
	else
		curl_easy_perform(request->curl);

bail:
	if(headerlist)
		curl_slist_free_all(headerlist);

	if(ret && request)
		smcp_curl_request_release(request);

	return ret;
}

void
smcp_curl_proxy_node_dealloc(smcp_curl_proxy_node_t x) {
	free(x);
}

smcp_curl_proxy_node_t
smcp_smcp_curl_proxy_node_alloc() {
	smcp_curl_proxy_node_t ret =
	    (smcp_curl_proxy_node_t)calloc(sizeof(struct smcp_curl_proxy_node_s), 1);

	ret->node.finalize = (void (*)(smcp_node_t)) &smcp_curl_proxy_node_dealloc;
	return ret;
}

smcp_curl_proxy_node_t
smcp_curl_proxy_node_init(
	smcp_curl_proxy_node_t	self,
	smcp_node_t			parent,
	const char*			name
) {
	require(self || (self = smcp_smcp_curl_proxy_node_alloc()), bail);

	require(smcp_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	curl_global_init(CURL_GLOBAL_ALL);
	self->curl_multi_handle = curl_multi_init();
	((smcp_node_t)&self->node)->request_handler = (void*)&smcp_curl_proxy_node_request_handler;

	// Now set the proxy path
	char path[64];
	if(0==smcp_node_get_path(&self->node,path,sizeof(path))) {
		smcp_set_proxy_url((smcp_t)smcp_node_get_root(&self->node), path);
	}

bail:
	return self;
}

smcp_status_t
smcp_curl_proxy_node_update_fdset(
	smcp_curl_proxy_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *max_fd,
	cms_t *timeout
) {
	int fd = *max_fd;
	long cms_timeout = *timeout;

	curl_multi_fdset(
		self->curl_multi_handle,
		read_fd_set,
		write_fd_set,
		error_fd_set,
		&fd
	);

	*max_fd = MAX(*max_fd,fd);

	curl_multi_timeout(
		self->curl_multi_handle,
		&cms_timeout
	);

	if(cms_timeout!=-1) {
		*timeout = MIN(*timeout,cms_timeout);
	}

	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_curl_proxy_node_process(smcp_curl_proxy_node_t self) {
	int running_curl_handles;
	curl_multi_perform(self->curl_multi_handle, &running_curl_handles);
	return SMCP_STATUS_OK;
}

