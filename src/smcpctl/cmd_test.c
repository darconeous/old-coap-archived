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

smcp_status_t device_func(
	smcp_variable_node_t node,
	uint8_t action,
	uint8_t i,
	char* value
) {
	smcp_status_t ret = 0;
	if(action==SMCP_VAR_GET_KEY) {
		switch(i) {
			case 0:
				strcpy(value,"loadavg");
				break;
			case 1:
				strcpy(value,"clock");
				break;
			case 2:
				strcpy(value,"action");
				break;
			default:
				ret = SMCP_STATUS_NOT_FOUND;
				break;
		}
	} else if(action==SMCP_VAR_GET_MAX_AGE && i==0) {
	} else if(action==SMCP_VAR_GET_VALUE) {
		switch(i) {
			case 0:
				{
					double loadavg[3] = { };
					require_action(
						0 < getloadavg(loadavg, sizeof(loadavg) / sizeof(*loadavg)),
						bail,
						ret = SMCP_STATUS_FAILURE
					);

					smcp_outbound_add_option(COAP_HEADER_MAX_AGE,"\x0F", 1);

					require_action(
						(size_t)snprintf(
							value,
							SMCP_VARIABLE_MAX_VALUE_LENGTH,
							"%0.2f",
							loadavg[0]
						) <= SMCP_VARIABLE_MAX_VALUE_LENGTH,
						bail,
						ret = SMCP_STATUS_FAILURE
					);
				}
				break;
			case 1:
				require_action(
					(size_t)snprintf(
						value,
						SMCP_VARIABLE_MAX_VALUE_LENGTH,
						"%d",
						(int)clock()
					) <= SMCP_VARIABLE_MAX_VALUE_LENGTH,
					bail,
					ret = SMCP_STATUS_FAILURE
				);
				break;
			case 2:
				ret = SMCP_STATUS_NOT_ALLOWED;
				break;

			default:
				ret = SMCP_STATUS_NOT_FOUND;
				break;
		}
	} else if(action==SMCP_VAR_SET_VALUE) {
		switch(i) {
			case 0:
				ret = SMCP_STATUS_NOT_ALLOWED;
				break;
			case 1:
				ret = SMCP_STATUS_NOT_ALLOWED;
				break;
			case 2:
				fprintf(stdout," *** Received Action!\n");

				coap_dump_header(
					stdout,
					"   * ",
					smcp_inbound_get_packet(),
					0
				);
				break;

			default:
				ret = SMCP_STATUS_NOT_FOUND;
				break;
		}
	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

bail:
	return ret;
}


static void
list_response_handler(
	int			statuscode,
	void*		context
) {
//	smcp_t const self = smcp_get_current_instance();
	const char* content = smcp_inbound_get_content_ptr();
	printf(" *** GOT LIST RESPONSE!!! ***\n");
	printf("   * RESULT CODE = %d (%s)\n", statuscode,
		(statuscode>0)?coap_code_to_cstr(statuscode):smcp_status_to_cstr(statuscode));

	if(content) {
		printf("   * CONTENT = \"%s\"\n", content);
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
		ret = smcp_start_async_response(&async_response,0);
		if(ret==SMCP_STATUS_DUPE) {
			printf("  ** Dupe, already preparing async response.\n");
		} else if(!ret) {
			printf(" *** Request requires an async response...!\n");
		}
		require_noerr(ret, bail);

		ret = smcp_begin_transaction(
			smcp_get_current_instance(),
			smcp_get_next_tid(smcp_get_current_instance(),NULL),
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
	smcp_t smcp_instance, int argc, char* argv[]
) {
	if((2 == argc) && (0 == strcmp(argv[1], "--help"))) {
		printf("Help not yet implemented for this command.\n");
		return ERRORCODE_HELP;
	}

	smcp_t smcp;
	smcp_t smcp2;

	struct smcp_timer_node_s timer_node = {};
	struct smcp_variable_node_s device_node = {};
	struct smcp_node_s async_response_node = {};

	smcp2 = smcp_create(12345);
	if(smcp_get_port(smcp_instance) == SMCP_DEFAULT_PORT)
		smcp = smcp_instance;
	else
		smcp = smcp_create(SMCP_DEFAULT_PORT);

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

#if HAS_LIBCURL
	struct smcp_curl_proxy_node_s proxy_node = {};
	curl_global_init(CURL_GLOBAL_ALL);

	CURLM* curl_multi_handle = curl_multi_init();
	smcp_curl_proxy_node_init(
		&proxy_node,
		smcp_get_root_node(smcp),
		"proxy",
		curl_multi_handle
	);
#endif

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	smcp_pairing_init(
		smcp_get_root_node(smcp),
		SMCP_PAIRING_DEFAULT_ROOT_PATH
	);

	smcp_pairing_init(
		smcp_get_root_node(smcp2),
		SMCP_PAIRING_DEFAULT_ROOT_PATH
	);

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	smcp_node_init_variable(
		&device_node,
		smcp_get_root_node(smcp),
		"device"
	);
	device_node.func = device_func;

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	smcp_node_init_variable(
		NULL,
		smcp_get_root_node(smcp2),
		"device"
	)->func = device_func;

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	smcp_timer_node_init(
		&timer_node,
		smcp_get_root_node(smcp),
		"timer"
	);

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	smcp_node_init((smcp_node_t)&async_response_node,
		smcp_get_root_node(smcp),
		"async_response"
	);
	async_response_node.request_handler = &async_request_handler;

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

#if 1
	{
		char url[256];
		snprintf(url,
			sizeof(url),
			"smcp://127.0.0.1:%d/device/action",
			smcp_get_port(smcp2));
		smcp_pair_with_uri(smcp,
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
			smcp_get_port(smcp));
		smcp_pair_with_uri(smcp2, "device/action", url, 0, NULL);
		printf("ACTION_NODE PAIRED WITH %s\n", url);
	}
#endif

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	// Just adding some random nodes so we can browse thru them with another process...
	{
		smcp_node_t subdevice = smcp_node_init(NULL,
			smcp_get_root_node(smcp),
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
//		{
//			unsigned int i = bt_rebalance(
//				    (void**)&((smcp_node_t)subdevice)->children);
//			printf("Balance operation took %u rotations\n", i);
//		}
//		{
//			unsigned int i = bt_rebalance(
//				    (void**)&((smcp_node_t)subdevice)->children);
//			printf("Second balance operation took %u rotations\n", i);
//		}
//		{
//			unsigned int i = bt_rebalance(
//				    (void**)&((smcp_node_t)subdevice)->children);
//			printf("Third balance operation took %u rotations\n", i);
//		}
//		{
//			unsigned int i = bt_rebalance(
//				    (void**)&((smcp_node_t)subdevice)->children);
//			printf("Fourth balance operation took %u rotations\n", i);
//		}
	}

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	{
		coap_transaction_id_t tid = smcp_get_next_tid(smcp2,NULL);

		char url[256];

#if 0
		snprintf(url,
			sizeof(url),
			"smcp://["SMCP_IPV 6_MULTICAST_ADDRESS "]:%d/device/",
			smcp_get_port(smcp));
#else
		snprintf(url,
			sizeof(url),
			"smcp://[::1]:%d/device/",
			smcp_get_port(smcp));
#endif

		smcp_begin_transaction(
			smcp2,
			tid,
			5 * MSEC_PER_SEC,
			0, // Flags
			NULL,
			&list_response_handler,
			NULL
		);

		smcp_outbound_begin(smcp2,COAP_METHOD_GET,COAP_TRANS_TYPE_CONFIRMABLE);
			smcp_outbound_set_tid(tid);
			smcp_outbound_set_uri(url, 0);
		smcp_outbound_send();

		fprintf(stderr, " *** Sent LIST request...\n");
	}

	//printf(__FILE__":%d: root node child count = %d\n",__LINE__,(int)bt_count(&smcp_get_root_node(smcp)->children));

	int i;
	for(i = 0; 1/*i < 3000000*/; i++) {
#if 1
		if((i - 1) % 250 == 0) {
			fprintf(stderr, " *** Forcing variable refresh...\n");
			smcp_trigger_event_with_node(smcp, &device_node.node, "loadavg");
		}
#endif
		smcp_process(smcp, 10);
		smcp_process(smcp2, 10);
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
