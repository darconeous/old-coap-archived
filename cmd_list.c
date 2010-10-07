/*
 *  cmd_list.c
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
#include "cmd_list.h"

/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 0 }
   };
 */

static bool listIsDone;

bool send_list_request(
	smcp_daemon_t smcp, const char* url, const char* next);

static void
list_response_handler(
	smcp_daemon_t		self,
	int					statuscode,
	smcp_header_item_t	headers[],
	const char*			content,
	size_t				content_length,
	struct sockaddr*	saddr,
	socklen_t			socklen,
	void*				context
) {
	int i;

	if(statuscode != SMCP_RESULT_CODE_OK)
		printf("*** RESULT CODE = %d\n", statuscode);
	if(content && content_length) {
		char contentBuffer[500];

		content_length =
		    ((content_length > sizeof(contentBuffer) -
		        2) ? sizeof(contentBuffer) - 2 : content_length);
		memcpy(contentBuffer, content, content_length);
		contentBuffer[content_length] = 0;

		if(content_length && (contentBuffer[content_length - 1] == '\n'))
			contentBuffer[--content_length] = 0;

		printf("%s\n", contentBuffer);

		for(i = 0; headers[i]; i += 2) {
			if(0 == strcmp(headers[i], SMCP_HEADER_MORE)) {
				const char* next = headers[i + 1];
				if(next[0] == 0) {
					// In this case we need to use
					// the last item in the list.
					next = contentBuffer + content_length - 1;
					while((next != contentBuffer) && next[-1] != '\n') {
						next--;
					}
				}
				if(send_list_request(self, (const char*)context, next))
					return;
			}
		}
	}

	listIsDone = true;
}

static bool
util_add_header(
	smcp_header_item_t	headerList[],
	int					maxHeaders,
	const char*			name,
	const char*			value
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
send_list_request(
	smcp_daemon_t smcp, const char* url, const char* next
) {
	bool ret = false;
	const char* headers[SMCP_MAX_HEADERS * 2 + 1] = { NULL };
	smcp_transaction_id_t tid = SMCP_FUNC_RANDOM_UINT32();

	//static char tid_str[30];

	//snprintf(tid_str,sizeof(tid_str),"%d",tid);

	//util_add_header(headers,SMCP_MAX_HEADERS,SMCP_HEADER_ID,tid_str);

	listIsDone = false;

	if(next)
		util_add_header(headers, SMCP_MAX_HEADERS, SMCP_HEADER_NEXT, next);

	require_noerr(smcp_daemon_add_response_handler(
			smcp,
			tid,
			5000,
			0, // Flags
			&list_response_handler,
			    (void*)url
		), bail);

	require_noerr(smcp_daemon_send_request_to_url(
			smcp,
			tid,
			SMCP_METHOD_LIST,
			url,
			headers,
			NULL,
			0
		), bail);

	ret = true;

bail:
	return ret;
}

int
tool_cmd_list(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	int ret = -1;

	if(argc != 2) {
		fprintf(stderr, "Bad args.\b");
		goto bail;
	}

	require(send_list_request(smcp, argv[1], NULL), bail);

	while(!listIsDone)
		smcp_daemon_process(smcp, 50);

	ret = 0;
bail:
	return 0;
}
