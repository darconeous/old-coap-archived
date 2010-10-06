/*
 *  cmd_pair.c
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
#include "smcp.h"
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include "cmd_pair.h"

/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 0 }
   };
 */

static bool pairIsDone;

bool send_pair_request(
	smcp_daemon_t smcp, const char* url, const char* content);

static void
pair_response_handler(
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
	if((statuscode < 200) || (statuscode >= 300))
		printf("*** RESULT CODE = %d\n", statuscode);
	if(content && (statuscode != SMCP_RESULT_CODE_ACK) &&
	    content_length) {
		char contentBuffer[500];

		content_length =
		    ((content_length > sizeof(contentBuffer) -
		        2) ? sizeof(contentBuffer) - 2 : content_length);
		memcpy(contentBuffer, content, content_length);
		contentBuffer[content_length] = 0;

		if(content_length && (contentBuffer[content_length - 1] == '\n'))
			contentBuffer[--content_length] = 0;

		printf("%s\n", contentBuffer);
	}

	pairIsDone = true;
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

bool
send_pair_request(
	smcp_daemon_t smcp, const char* url, const char* url2
) {
	bool ret = false;
	const char* headers[SMCP_MAX_HEADERS * 2 + 1] = { NULL };
	static char idValue[30];

	pairIsDone = false;

	snprintf(idValue, sizeof(idValue), "%08x", SMCP_FUNC_RANDOM_UINT32());

	util_add_header(headers, SMCP_MAX_HEADERS, SMCP_HEADER_ID, idValue);

	require_noerr(smcp_daemon_add_response_handler(
			smcp,
			idValue,
			5000,
			0, // Flags
			&pair_response_handler,
			    (void*)url
		), bail);

	require_noerr(smcp_daemon_send_request_to_url(
			smcp,
			SMCP_METHOD_PAIR,
			url,
			"SMCP/0.1",
			headers,
			url2,
			strlen(url2)
		), bail);

	ret = true;

bail:
	return ret;
}

int
tool_cmd_pair(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	int ret = -1;

	if(argc == 3) {
		require(send_pair_request(smcp, argv[1], argv[2]), bail);
	} else {
		fprintf(stderr, "Bad args.\b");
		goto bail;
	}

	while(!pairIsDone)
		smcp_daemon_process(smcp, 50);

	pairIsDone = 0;

	require(send_pair_request(smcp, argv[2], argv[1]), bail);

	while(!pairIsDone)
		smcp_daemon_process(smcp, 50);

	ret = 0;
bail:
	return 0;
}
