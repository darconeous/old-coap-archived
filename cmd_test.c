/*
 *  cmd_test.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include "assert_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"

#include "smcp.h"
#include "smcp_node.h"

#include "cmd_test.h"

smcp_status_t
action_func(
	smcp_action_node_t	node,
	const char*			headers[],
	const char*			content,
	size_t				content_length,
	const char*			content_type,
	struct sockaddr*	saddr,
	socklen_t			socklen,
	void*				context
) {
	fprintf(stderr,
		" *** Received Action! content_length = %d ",
		    (int)content_length);
	fprintf(stderr, "content = \"%s\"\n", content);

	return 0;
}

smcp_status_t
loadavg_get_func(
	smcp_variable_node_t	node,
	const char*				headers[],
	char*					content,
	size_t*					content_length,
	const char**			content_type,
	struct sockaddr*		saddr,
	socklen_t				socklen,
	void*					context
) {
	int ret = 0;
	double loadavg[3] = { };

	require_action(node, bail, ret = -1);
	require_action(content, bail, ret = -1);
	require_action(content_length, bail, ret = -1);

	getloadavg(loadavg, sizeof(loadavg) / sizeof(*loadavg));

	snprintf(content, *content_length, "v=%0.2f", loadavg[0]);
	*content_length = strlen(content);
	*content_type = SMCP_CONTENT_TYPE_FORM;

bail:
	return ret;
}

smcp_variable_node_t create_load_average_variable_node(
	smcp_device_node_t parent, const char* name
) {
	smcp_variable_node_t ret = NULL;
	smcp_event_node_t changed_event = NULL;

	ret = smcp_node_add_variable((void*)parent, name);

	changed_event = smcp_node_add_event((void*)ret, "changed");
	ret->get_func = loadavg_get_func;

	return ret;
}


static void
list_response_handler(
	smcp_daemon_t		self,
	const char*			version,
	int					statuscode,
	const char*			headers[],
	const char*			content,
	size_t				content_length,
	struct sockaddr*	saddr,
	socklen_t			socklen,
	void*				context
) {
	printf(" *** GOT LIST RESPONSE!!! ***\n");
	printf(" *** STATUS  CODE = %d\n", statuscode);

	if(content) {
		char contentBuffer[500] = "";
		memcpy(contentBuffer, content, content_length);

		printf(" *** CONTENT = \"%s\"\n", contentBuffer);
	}
}

static bool
util_add_header(
	const char* headerList[],
	int			maxHeaders,
	const char* name,
	const char* value
) {
	for(; maxHeaders && headerList[0]; maxHeaders--, headerList += 2) ;
	if(maxHeaders) {
		headerList[0] = name;
		headerList[1] = value;
		headerList[2] = NULL;
		return true;
	}
	return false;
}

int
tool_cmd_test(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	smcp_daemon_t smcp_daemon;
	smcp_daemon_t smcp_daemon2;

	smcp_device_node_t device_node;
	smcp_action_node_t action_node;
	smcp_variable_node_t var_node;

	smcp_daemon2 = smcp_daemon_create(12345);
	if(smcp_daemon_get_port(smcp) == SMCP_DEFAULT_PORT)
		smcp_daemon = smcp;
	else
		smcp_daemon = smcp_daemon_create(SMCP_DEFAULT_PORT);

	device_node =
	    smcp_node_add_subdevice(smcp_daemon_get_root_node(
			smcp_daemon), "device");

//	smcp_node_add_event((smcp_node_t)device_node, "event");
//	smcp_node_add_subdevice(smcp_daemon_get_root_node(smcp_daemon), "device3");
//	smcp_node_add_subdevice(smcp_daemon_get_root_node(smcp_daemon), "device4");

	var_node = create_load_average_variable_node(device_node, "loadavg");

	action_node =
	    smcp_node_add_action(smcp_daemon_get_root_node(
			smcp_daemon2), "action");
	action_node->post_func = action_func;

	{
		char url[256];
		snprintf(url,
			sizeof(url),
			"smcp://127.0.0.1:%d/?action",
			smcp_daemon_get_port(smcp_daemon2));
		smcp_node_pair_with_uri((smcp_node_t)smcp_node_find_with_path((
				    smcp_node_t)var_node, "!changed"), url, 0);
		printf("EVENT_NODE PAIRED WITH %s\n", url);
	}
	{
		char url[256];
		snprintf(url,
			sizeof(url),
			"smcp://127.0.0.1:%d/device/loadavg!changed",
			smcp_daemon_get_port(smcp_daemon));
		smcp_node_pair_with_uri((smcp_node_t)action_node, url, 0);
		printf("ACTION_NODE PAIRED WITH %s\n", url);
	}

	{
		const char* headers[SMCP_MAX_HEADERS * 2 + 1] = { NULL };
		char idValue[30];
		snprintf(idValue, sizeof(idValue), "%08x", SMCP_FUNC_RANDOM_UINT32());

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

		util_add_header(headers, SMCP_MAX_HEADERS, SMCP_HEADER_ID, idValue);

		smcp_daemon_add_response_handler(
			smcp_daemon2,
			idValue,
			5000,
			0, // Flags
			&list_response_handler,
			NULL
		);

		smcp_daemon_send_request_to_url(
			smcp_daemon2,
			SMCP_METHOD_LIST,
			url,
			"SMCP/0.1",
			headers,
			NULL,
			0
		);
		fprintf(stderr, " *** Sent LIST request...\n");
	}

	int i;
	for(i = 0; i < 30000; i++) {
		if(i % 50 == 0) {
			fprintf(stderr, " *** Forcing variable refresh...\n");
			smcp_daemon_refresh_variable(smcp_daemon, var_node);
		}
		smcp_daemon_process(smcp_daemon, 50);
		smcp_daemon_process(smcp_daemon2, 50);
	}


	return 0;
}
