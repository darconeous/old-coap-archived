/*
 *  cmd_list.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include <AssertMacros.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "smcp.h"
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include "cmd_list.h"

static arg_list_item_t option_list[] = {
	{ 'h', "help", NULL, "Print Help" },
	{ 0 }
};

static bool listIsDone;

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
	if(statuscode != SMCP_RESULT_CODE_OK)
		printf("*** RESULT CODE = %d\n", statuscode);
	if(content) {
		char contentBuffer[500] = "";
		memcpy(contentBuffer, content, content_length);

		printf("%s\n", contentBuffer);

		for(i = 0; headers[i]; i += 2) {
			if(0 == strcmp(headers[i], SMCP_HEADER_MORE)) {
				// More to fetch!
			}
		}
	}

	listIsDone = true;
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
tool_cmd_list(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	int ret = -1;

	listIsDone = false;
	const char* headers[SMCP_MAX_HEADERS * 2 + 1] = { NULL };
	char idValue[30];
	snprintf(idValue, sizeof(idValue), "%08x", arc4random());

	util_add_header(headers, SMCP_MAX_HEADERS, SMCP_HEADER_ID, idValue);
	//util_add_header(headers,SMCP_MAX_HEADERS,SMCP_HEADER_NEXT,"device2/");

	require_noerr(smcp_daemon_add_response_handler(
			smcp,
			idValue,
			5000,
			0, // Flags
			&list_response_handler,
			NULL
		), bail);

	require_noerr(smcp_daemon_send_request_to_url(
			smcp,
			SMCP_METHOD_LIST,
			argv[1],
			"SMCP/0.1",
			headers,
			NULL,
			0
		), bail);

	while(!listIsDone)
		smcp_daemon_process(smcp, 50);

	ret = 0;
bail:
	return 0;
}
