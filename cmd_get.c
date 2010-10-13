/*
 *  cmd_get.c
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
#include "cmd_get.h"
#include "url-helpers.h"

/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 0 }
   };
 */

typedef void (*sig_t)(int);

static bool getIsDone;
static sig_t previous_sigint_handler;
static coap_transaction_id_t tid;

static void
signal_interrupt(int sig) {
	fprintf(stderr, "Interrupt\n");
	getIsDone = 1;
	signal(SIGINT, previous_sigint_handler);
}

bool send_get_request(
	smcp_daemon_t smcp, const char* url);

static void
get_response_handler(
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length,
	struct sockaddr*	saddr,
	socklen_t			socklen,
	void*				context
) {
	if(statuscode != SMCP_RESULT_CODE_OK) {
		fprintf(stderr,
			" *** RESULT CODE = %d (%s)\n",
			statuscode,
			smcp_code_to_cstr(statuscode));
	}
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
	}

	getIsDone = true;
}

bool
send_get_request(
	smcp_daemon_t smcp, const char* url
) {
	bool ret = false;
	coap_header_item_t headers[SMCP_MAX_HEADERS * 2 + 1] = {  };

	//static char tid_str[30];

	tid = SMCP_FUNC_RANDOM_UINT32();

	//snprintf(tid_str,sizeof(tid_str),"%d",tid);

	//util_add_header(headers,SMCP_MAX_HEADERS,SMCP_HEADER_ID,tid_str);

	getIsDone = false;

	require_noerr(smcp_daemon_add_response_handler(
			smcp,
			tid,
			5000,
			0, // Flags
			&get_response_handler,
			    (void*)url
		), bail);

	require_noerr(smcp_daemon_send_request_to_url(
			smcp,
			tid,
			SMCP_METHOD_GET,
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
tool_cmd_get(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	int ret = -1;

	previous_sigint_handler = signal(SIGINT, &signal_interrupt);

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

	require(send_get_request(smcp, url), bail);

	while(!getIsDone)
		smcp_daemon_process(smcp, -1);

	ret = 0;
bail:
	smcp_invalidate_response_handler(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return 0;
}
