/*
 *  cmd_test.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include <smcp/assert_macros.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include <signal.h>

#include <smcp/smcp.h>
#include <smcp/smcp-node.h>
#include <smcp/smcp-timer_node.h>
#include <smcp/smcp-variable_node.h>
#include <smcp/smcp-pairing.h>
#include "help.h"
#include "smcpctl.h"
#include "cmd_test.h"
#if HAS_LIBCURL
#include <smcp/smcp-curl_proxy.h>
#endif

static smcp_status_t
action_func(
	smcp_variable_node_t	node,
	char*					content,
	size_t					content_length,
	coap_content_type_t		content_type
) {
	fprintf(stdout,
		" *** Received Action! content_length=%d\n",
		    (int)content_length);

	coap_dump_header(
		stdout,
		"   * ",
		smcp_inbound_get_packet(),
		0
	);

	if(content_length)
		fprintf(stdout, "   * content=\"%s\"\n", content);

	return SMCP_STATUS_OK;
}

smcp_status_t
loadavg_get_func(
	smcp_variable_node_t	node,
	char*					content,
	size_t*					content_length,
	coap_content_type_t*	content_type
) {
	int ret = 0;
	double loadavg[3] = { };

	if(content_type)
		*content_type = SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;

	if(!content_type || !content || !content_length)
		goto bail; // Just an event saying that they are finished.

	require_action(node!=NULL, bail, ret = -1);
	require_action(content!=NULL, bail, ret = -1);
	require_action(content_length!=0, bail, ret = -1);

	require_action(0 <
		getloadavg(loadavg,
			sizeof(loadavg) / sizeof(*loadavg)), bail, ret = -1);

	require_action((size_t)snprintf(content, *content_length, "v=%0.2f",
			loadavg[0]) <= *content_length, bail, ret = -1);

	fprintf(
		stderr,
		" *** Queried for load average (max_content_length=%d, content=\"%s\", loadavg=%0.2f) \n",
		    (int)*content_length,
		content,
		loadavg[0]);

	*content_length = strlen(content);


bail:
	return ret;
}

static void
list_response_handler(
	int			statuscode,
	void*		context
) {
//	smcp_daemon_t self = smcp_get_current_daemon();
	const char* content = smcp_inbound_get_content_ptr();
	size_t content_length = smcp_inbound_get_content_len();
	printf(" *** GOT LIST RESPONSE!!! ***\n");
	printf("   * RESULT CODE = %d (%s)\n", statuscode,
		(statuscode>0)?coap_code_to_cstr(statuscode):smcp_status_to_cstr(statuscode));

	if(content) {
		char contentBuffer[SMCP_MAX_CONTENT_LENGTH + 1] = {};
		memcpy(contentBuffer, content, content_length);

		printf("   * CONTENT = \"%s\"\n", contentBuffer);
	}
}

smcp_status_t
sliced_post_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	return SMCP_STATUS_OK;
}

static struct smcp_async_response_s async_response;

smcp_status_t
resend_async_response(void* context) {
	smcp_status_t ret = 0;
	struct smcp_async_response_s* async_response = (void*)context;

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

static void
async_response_ack_handler(int statuscode, void* context) {
	struct smcp_async_response_s* async_response = (void*)context;

	printf(" *** Finished sending async response.\n");
	printf("   * RESULT CODE = %d (%s)\n", statuscode,
		(statuscode>0)?coap_code_to_cstr(statuscode):smcp_status_to_cstr(statuscode));

	smcp_finish_async_response(async_response);
}

smcp_status_t
async_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_OK;
	if(method==COAP_METHOD_GET) {
		ret = smcp_start_async_response(&async_response);
		if(ret==SMCP_STATUS_DUPE) {
			printf("  ** Dupe, already preparing async response.\n");
		} else if(!ret) {
			printf(" *** Request requires an async response...!\n");
		}
		require_noerr(ret, bail);

		ret = smcp_begin_transaction(
			smcp_get_current_daemon(),
			smcp_get_next_tid(smcp_get_current_daemon(),NULL),
			30*1000,	// Retry for thirty seconds.
			SMCP_TRANSACTION_DELAY_START, // Flags
			(void*)&resend_async_response,
			(void*)&async_response_ack_handler,
			(void*)&async_response
		);
	} else {
		ret = SMCP_STATUS_NOT_ALLOWED;
	}

bail:
	return ret;
}

int
tool_cmd_test(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	if((2 == argc) && (0 == strcmp(argv[1], "--help"))) {
		printf("Help not yet implemented for this command.\n");
		return ERRORCODE_HELP;
	}

	smcp_daemon_t smcp_daemon;
	smcp_daemon_t smcp_daemon2;

	struct smcp_node_s device_node = {};
	struct smcp_timer_node_s timer_node = {};
	struct smcp_variable_node_s var_node = {};
	struct smcp_variable_node_s action_node = {};
	struct smcp_node_s sliced_post_node = {};
	struct smcp_node_s async_response_node = {};

	smcp_daemon2 = smcp_daemon_create(12345);
	if(smcp_daemon_get_port(smcp) == SMCP_DEFAULT_PORT)
		smcp_daemon = smcp;
	else
		smcp_daemon = smcp_daemon_create(SMCP_DEFAULT_PORT);

#if HAS_LIBCURL
	struct smcp_curl_proxy_node_s proxy_node = {};
	curl_global_init(CURL_GLOBAL_ALL);

	CURLM* curl_multi_handle = curl_multi_init();
	smcp_curl_proxy_node_init(
		&proxy_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"proxy",
		curl_multi_handle
	);
#endif

	smcp_pairing_init(
		smcp_daemon,
		smcp_daemon_get_root_node(smcp_daemon),
		SMCP_PAIRING_DEFAULT_ROOT_PATH
	);

	smcp_pairing_init(
		smcp_daemon2,
		smcp_daemon_get_root_node(smcp_daemon2),
		SMCP_PAIRING_DEFAULT_ROOT_PATH
	);

	smcp_node_init(
		(smcp_node_t)&device_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"device"
	);

	smcp_timer_node_init(&timer_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"timer"
	);

	smcp_node_init((smcp_node_t)&sliced_post_node,
		&device_node,
		"sliced_post"
	);
	sliced_post_node.request_handler = &sliced_post_request_handler;

	smcp_node_init((smcp_node_t)&async_response_node,
		&device_node,
		"async_response"
	);
	async_response_node.request_handler = &async_request_handler;


	smcp_node_init_variable(
		&var_node,
		(smcp_node_t)&device_node,
		"loadavg"
	);
	var_node.get_func = loadavg_get_func;

	smcp_node_init_variable(
		&action_node,
		smcp_daemon_get_root_node(smcp_daemon2),
		"action"
	);
	action_node.post_func = action_func;

#if 1
	{
		char url[256];
		snprintf(url,
			sizeof(url),
			"smcp://127.0.0.1:%d/action",
			smcp_daemon_get_port(smcp_daemon2));
		smcp_daemon_pair_with_uri(smcp_daemon,
			"device/loadavg",
			url,
			0,
			NULL);
		printf("EVENT_NODE PAIRED WITH %s\n", url);
	}

	{
		char url[256];
		snprintf(url,
			sizeof(url),
			"smcp://[::1]:%d/device/loadavg",
			smcp_daemon_get_port(smcp_daemon));
		smcp_daemon_pair_with_uri(smcp_daemon2, "action", url, 0, NULL);
		printf("ACTION_NODE PAIRED WITH %s\n", url);
	}
#endif

	// Just adding some random nodes so we can browse thru them with another process...
	{
		smcp_node_t subdevice = smcp_node_init(NULL,
			smcp_daemon_get_root_node(smcp_daemon),
			"lots_of_devices");
		unsigned char i = 0;
#if 1
		for(i = i * 97 + 101; i; i = i * 97 + 101) {
#else
		for(i = 0; i != 255; i++) {
#endif
			char *name = NULL;
			asprintf(&name, "subdevice_%d", i); // Will leak, but we don't care.
			smcp_node_init(NULL, (smcp_node_t)subdevice, name);
		}
		{
			unsigned int i = bt_rebalance(
				    (void**)&((smcp_node_t)subdevice)->children);
			printf("Balance operation took %u rotations\n", i);
		}
		{
			unsigned int i = bt_rebalance(
				    (void**)&((smcp_node_t)subdevice)->children);
			printf("Second balance operation took %u rotations\n", i);
		}
		{
			unsigned int i = bt_rebalance(
				    (void**)&((smcp_node_t)subdevice)->children);
			printf("Third balance operation took %u rotations\n", i);
		}
		{
			unsigned int i = bt_rebalance(
				    (void**)&((smcp_node_t)subdevice)->children);
			printf("Fourth balance operation took %u rotations\n", i);
		}
	}

	{
		coap_transaction_id_t tid = smcp_get_next_tid(smcp_daemon2,NULL);

		char url[256];

#if 0
		snprintf(url,
			sizeof(url),
			"smcp://["SMCP_IPV 6_MULTICAST_ADDRESS "]:%d/device/",
			smcp_daemon_get_port(smcp_daemon));
#else
		snprintf(url,
			sizeof(url),
			"smcp://[::1]:%d/device/",
			smcp_daemon_get_port(smcp_daemon));
#endif

		smcp_begin_transaction(
			smcp_daemon2,
			tid,
			5 * MSEC_PER_SEC,
			0, // Flags
			NULL,
			&list_response_handler,
			NULL
		);

		smcp_outbound_begin(smcp_daemon2,COAP_METHOD_GET,COAP_TRANS_TYPE_CONFIRMABLE);
			smcp_outbound_set_tid(tid);
			smcp_outbound_set_uri(url, 0);
		smcp_outbound_send();

		fprintf(stderr, " *** Sent LIST request...\n");
	}

	int i;
	for(i = 0; i < 3000000; i++) {
#if 0
		if((i - 1) % 250 == 0) {
			fprintf(stderr, " *** Forcing variable refresh...\n");
			smcp_daemon_refresh_variable(smcp_daemon, &var_node);
		}
#endif
		smcp_daemon_process(smcp_daemon, 10);
		smcp_daemon_process(smcp_daemon2, 10);
#if HAS_LIBCURL
		int runningHandles;
		if(curl_multi_handle)
			curl_multi_perform(curl_multi_handle, &runningHandles);
#endif
	}

bail:
#if HAS_LIBCURL
	curl_multi_cleanup(curl_multi_handle);
#endif

	return 0;
}
