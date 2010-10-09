/*
 *  cmd_post.c
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
#include "cmd_post.h"
#include "url-helpers.h"

/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 0 }
   };
 */

static bool postIsDone;

bool send_post_request(
	smcp_daemon_t	smcp,
	const char*		url,
	const char*		content,
	int				content_len);

static void
post_response_handler(
	smcp_daemon_t		self,
	int					statuscode,
	smcp_header_item_t	headers[],
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

	postIsDone = true;
}


bool
send_post_request(
	smcp_daemon_t	smcp,
	const char*		url,
	const char*		content,
	int				content_len
) {
	bool ret = false;
	smcp_header_item_t headers[SMCP_MAX_HEADERS * 2 + 1] = {  };
	smcp_transaction_id_t tid = SMCP_FUNC_RANDOM_UINT32();

	//static char tid_str[30];

	//snprintf(tid_str,sizeof(tid_str),"%d",tid);

	//util_add_header(headers,SMCP_MAX_HEADERS,SMCP_HEADER_ID,tid_str);

	postIsDone = false;

	require_noerr(smcp_daemon_add_response_handler(
			smcp,
			tid,
			5000,
			0, // Flags
			&post_response_handler,
			    (void*)url
		), bail);

	require_noerr(smcp_daemon_send_request_to_url(
			smcp,
			tid,
			SMCP_METHOD_POST,
			url,
			headers,
			content,
			content_len
		), bail);

	ret = true;

bail:
	return ret;
}

int
tool_cmd_post(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	int ret = -1;

	char url[1000];

	if(getenv("SMCP_CURRENT_PATH")) {
		strncpy(url, getenv("SMCP_CURRENT_PATH"), sizeof(url));
		if(argc >= 2)
			url_change(url, argv[1]);
	} else {
		if(argc >= 2) {
			strncpy(url, argv[1], sizeof(url));
		} else {
			fprintf(stderr, "Bad args.\n");
			goto bail;
		}
	}

	if(argc >= 3)
		require(send_post_request(smcp, url, argv[2], strlen(
					argv[2])), bail);
	else
		require(send_post_request(smcp, url, NULL, 0), bail);

	while(!postIsDone)
		smcp_daemon_process(smcp, 50);

	ret = 0;
bail:
	return 0;
}
