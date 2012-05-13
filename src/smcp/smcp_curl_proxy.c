
#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 1
#endif

#include "assert_macros.h"
#include "smcp.h"
#include "smcp_helpers.h"
#include "smcp_logging.h"
#include "coap.h"
#include "smcp_curl_proxy.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct smcp_curl_request_s {
	CURL* curl;
	coap_transaction_id_t tid;
	struct smcp_async_response_s async_response;
	char* content;
	size_t content_len;
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
	ret->tid = SMCP_FUNC_RANDOM_UINT32();
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

	ret = smcp_message_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(ret,bail);

	ret = smcp_message_set_content_type(COAP_CONTENT_TYPE_TEXT_PLAIN);
	require_noerr(ret,bail);

	ret = smcp_message_set_async_response(async_response);
	require_noerr(ret,bail);

	ret = smcp_message_set_content(request->content, len);
	require_noerr(ret,bail);

	ret = smcp_message_send();
	require_noerr(ret,bail);

	if(ret) {
		assert_printf(
			"smcp_message_send() returned error %d(%s).\n",
			ret,
			smcp_status_to_cstr(ret)
		);
		goto bail;
	}

bail:
	return ret;
}

static void
async_response_ack_handler(int statuscode, void* context) {
	smcp_curl_request_t request = (smcp_curl_request_t)context;
	struct smcp_async_response_s* async_response = &request->async_response;

	smcp_finish_async_response(async_response);
	smcp_curl_request_release(request);
}


static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	smcp_curl_request_t request = (smcp_curl_request_t)userp;

	require_action(realsize>0,bail,realsize=0);

	// At the moment limit to one call.
	require_action(request->content==NULL,bail,realsize=0);

	request->content = realloc(request->content, request->content_len + realsize + 1);

	require_action(request->content!=NULL,bail,realsize=0);

	memcpy(&(request->content[request->content_len]), contents, realsize);
	request->content_len += realsize;
	request->content[request->content_len] = 0;
	
	smcp_begin_transaction(
		smcp_get_current_daemon(),
		request->tid,
		10*1000,	// Retry for thirty seconds.
		0, // Flags
		(void*)&resend_async_response,
		(void*)&async_response_ack_handler,
		(void*)request
	);

bail:
	return realsize;
}

static smcp_status_t
smcp_curl_proxy_node_request_handler(
	smcp_curl_proxy_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;
	smcp_curl_request_t request = NULL;
	struct curl_slist *headerlist=NULL;
 	
	require_action(method<=COAP_METHOD_DELETE,bail,ret = SMCP_STATUS_NOT_ALLOWED);

	smcp_current_request_reset_next_header();
	
	request = smcp_curl_request_create();
	
	require_action(request!=NULL,bail,ret = SMCP_STATUS_MALLOC_FAILURE);

	{
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		while((key=smcp_current_request_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {
			if(key==COAP_HEADER_PROXY_URI) {
				char uri[value_len+1];
				memcpy(uri,value,value_len);
				uri[value_len] = 0;
				curl_easy_setopt(request->curl, CURLOPT_URL, uri);
			} else if(key==COAP_HEADER_URI_HOST) {
			} else if(key==COAP_HEADER_URI_PORT) {
			} else if(key==COAP_HEADER_URI_PATH) {
			} else if(key==COAP_HEADER_URI_QUERY) {
			} else if(key==COAP_HEADER_TOKEN) {
			} else {
/*
				const char* option_name = coap_option_key_to_cstr(key, false);
				char header[strlen(option_name)+value_len+3];
				strcpy(header,option_name);
				strcat(header,": ");
				strncat(header,(const char*)value,value_len);
				headerlist = curl_slist_append(headerlist, header);
*/
			}
		}
	}

	curl_easy_setopt(request->curl, CURLOPT_HTTPHEADER, headerlist);
	curl_easy_setopt(request->curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(request->curl, CURLOPT_WRITEDATA, (void *)request);
	curl_easy_setopt(request->curl, CURLOPT_USERAGENT, "smcp-curl-proxy/1.0");
 
	ret = smcp_start_async_response(&request->async_response);
	require_noerr(ret,bail);

#if 0
	curl_multi_add_handle(node->curl_multi_handle, request->curl);
#else
	curl_easy_perform(request->curl);
#endif

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
	if(x->curl_multi_handle)
		curl_multi_cleanup(x->curl_multi_handle);
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
	smcp_daemon_t		smcp,
	smcp_node_t			parent,
	const char*			name
) {
	require(self || (self = smcp_smcp_curl_proxy_node_alloc()), bail);

	require(smcp_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	((smcp_node_t)&self->node)->request_handler = &smcp_curl_proxy_node_request_handler;

	curl_global_init(CURL_GLOBAL_ALL);

	self->curl_multi_handle = curl_multi_init();

bail:
	return self;
}
