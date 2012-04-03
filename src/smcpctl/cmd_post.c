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
static int outbound_slice_size;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

struct post_request_s {
	char* url;
	char* content;
	size_t content_len;
	coap_content_type_t content_type;
};


static void
post_response_handler(
	int			statuscode,
	const char* content,
	size_t		content_length,
	struct post_request_s *request
) {
	if((statuscode >= 100) && show_headers) {
		fprintf(stdout, "\n");
		coap_dump_headers(stdout,
			NULL,
			statuscode,
			smcp_daemon_get_current_request_headers(),
			smcp_daemon_get_current_request_header_count());
	}
	if((statuscode != HTTP_RESULT_CODE_OK) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED))
		fprintf(stderr, "post: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : http_code_to_cstr(statuscode));
	if(content && (statuscode != HTTP_RESULT_CODE_NO_CONTENT) &&
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
	free(request->content);
	free(request->url);
	free(request);
}


bool
resend_post_request(struct post_request_s *request) {
	bool ret = false;
	smcp_status_t status = 0;

	smcp_message_begin(smcp_get_current_daemon(),COAP_METHOD_POST, COAP_TRANS_TYPE_CONFIRMABLE);
	smcp_message_set_uri(request->url, 0);

	if(request->content_type) {
		smcp_message_add_header(
			COAP_HEADER_CONTENT_TYPE,
			(void*)&request->content_type,
			1
		);
	}

	smcp_message_set_content(request->content, request->content_len);

	status = smcp_message_send();

	if(status) {
		check(!status);
		fprintf(stderr,
			"smcp_message_send() returned error %d(%s).\n",
			status,
			smcp_status_to_cstr(status));
		goto bail;
	}

	ret = true;
bail:
	return ret;
}


static coap_transaction_id_t
send_post_request(
	smcp_daemon_t	smcp,
	const char*		url,
	const char*		content,
	int				content_len,
	coap_content_type_t content_type
) {
	struct post_request_s *request;
	coap_transaction_id_t tid;
	bool ret = false;

	request = calloc(1,sizeof(*request));
	require(request!=NULL,bail);
	request->url = strdup(url);
	request->content = calloc(1,sizeof(content_len));
	memcpy(request->content,content,content_len);
	request->content_len = content_len;
	request->content_type = content_type;

	tid = SMCP_FUNC_RANDOM_UINT32();

	gRet = ERRORCODE_INPROGRESS;

	require_noerr(smcp_begin_transaction(
			smcp,
			tid,
			5000,
			0, // Flags
			(void*)&resend_post_request,
			(void*)&post_response_handler,
			(void*)request
		), bail);

	ret = true;

bail:
	if(!ret)
		tid = 0;
	return tid;
}

int
tool_cmd_post(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	coap_transaction_id_t tid;
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	coap_content_type_t content_type = 0;
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

	tid = send_post_request(smcp, url, content, strlen(content),content_type);

	while(ERRORCODE_INPROGRESS == gRet)
		smcp_daemon_process(smcp, -1);

bail:
	smcp_invalidate_transaction(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
