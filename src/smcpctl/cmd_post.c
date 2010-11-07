/*
 *  cmd_post.c
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
#include <smcp/smcp.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include "cmd_post.h"
#include <smcp/url-helpers.h>
#include <signal.h>
#include "smcpctl.h"

static arg_list_item_t option_list[] = {
	{ 'h', "help",				  NULL, "Print Help" },
//	{ 'c', "content-file",NULL,"Use content from the specified input source" },
	{ 0,   "outbound-slice-size", NULL, "writeme"	 },
	{ 0,   "content-type",		  NULL, "writeme"	 },
	{ 0 }
};

static int gRet;
static sig_t previous_sigint_handler;
static coap_transaction_id_t tid;
static coap_content_type_t content_type;
static int outbound_slice_size;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

bool send_post_request(
	smcp_daemon_t	smcp,
	const char*		url,
	const char*		content,
	int				content_len);

static void
post_response_handler(
	int			statuscode,
	const char* content,
	size_t		content_length,
	void*		context
) {
//	smcp_daemon_t self = smcp_get_current_daemon();
	if((statuscode >= 100) && show_headers) {
		fprintf(stdout, "\n");
		coap_dump_headers(stdout,
			NULL,
			statuscode,
			smcp_daemon_get_current_request_headers(),
			smcp_daemon_get_current_request_header_count());
	}
	if((statuscode != COAP_RESULT_CODE_OK) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED))
		fprintf(stderr, "post: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : coap_code_to_cstr(statuscode));
	if(content && (statuscode != COAP_RESULT_CODE_NO_CONTENT) &&
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

	if(gRet == ERRORCODE_INPROGRESS)
		gRet = 0;
}


bool
send_post_request(
	smcp_daemon_t	smcp,
	const char*		url,
	const char*		content,
	int				content_len
) {
	bool ret = false;
	coap_header_item_t headers[SMCP_MAX_HEADERS + 1] = {  };

	tid = SMCP_FUNC_RANDOM_UINT32();

	gRet = ERRORCODE_INPROGRESS;

	if(content_type) {
		util_add_header(headers,
			SMCP_MAX_HEADERS,
			COAP_HEADER_CONTENT_TYPE,
			    (void*)&content_type,
			1);
	}

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
			COAP_METHOD_POST,
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
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	int i;
	char url[1000];
	url[0] = 0;
	char content[10000];
	content[0] = 0;
	content_type = 0;

	outbound_slice_size = 100;

	BEGIN_LONG_ARGUMENTS(gRet)
//		HANDLE_LONG_ARGUMENT("include") get_show_headers = true;
//		HANDLE_LONG_ARGUMENT("follow") redirect_count = 10;
//		HANDLE_LONG_ARGUMENT("no-follow") redirect_count = 0;
	HANDLE_LONG_ARGUMENT("outbound-slice-size") outbound_slice_size =
	    strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("content-type") content_type =
	    coap_content_type_from_cstr(argv[++i]);
	HANDLE_LONG_ARGUMENT("help") {
		print_arg_list_help(option_list,
			argv[0],
			"[args] <uri> <POST-Data>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(gRet)
//		HANDLE_SHORT_ARGUMENT('i') get_show_headers = true;
//		HANDLE_SHORT_ARGUMENT('f') redirect_count = 10;

	HANDLE_SHORT_ARGUMENT2('h', '?') {
		print_arg_list_help(option_list,
			argv[0],
			"[args] <uri> <POST-Data>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	HANDLE_OTHER_ARGUMENT() {
		if(url[0] == 0) {
			if(getenv("SMCP_CURRENT_PATH")) {
				strncpy(url, getenv("SMCP_CURRENT_PATH"), sizeof(url));
				url_change(url, argv[i]);
			} else {
				strncpy(url, argv[i], sizeof(url));
			}
		} else {
			if(content[0] == 0) {
				strncpy(content, argv[i], sizeof(content));
			} else {
				strncat(content, " ", sizeof(content));
				strncat(content, argv[i], sizeof(content));
			}
		}
	}
	END_ARGUMENTS

	if((url[0] == 0) && getenv("SMCP_CURRENT_PATH"))
		strncpy(url, getenv("SMCP_CURRENT_PATH"), sizeof(url));

	if(url[0] == 0) {
		fprintf(stderr, "Missing path argument.\n");
		gRet = ERRORCODE_BADARG;
		goto bail;
	}


	gRet = ERRORCODE_INPROGRESS;

	require(send_post_request(smcp, url, content, strlen(content)), bail);

	while(ERRORCODE_INPROGRESS == gRet)
		smcp_daemon_process(smcp, -1);

bail:
	smcp_invalidate_response_handler(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
