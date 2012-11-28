/*
 *  cmd_post.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

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
	{ 'i', "include",	 NULL,	 "include headers in output" },
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
	coap_code_t method;
};


static void
post_response_handler(
	int			statuscode,
	struct post_request_s *request
) {
	char* content = (char*)smcp_inbound_get_content_ptr();
	size_t content_length = smcp_inbound_get_content_len();
	if((statuscode >= COAP_RESULT_100) && show_headers) {
		fprintf(stdout, "\n");
		coap_dump_header(
			stdout,
			NULL,
			smcp_inbound_get_packet(),
			0
		);
	}
	if((statuscode != COAP_RESULT_204_CHANGED) &&
	        (statuscode != SMCP_STATUS_TRANSACTION_INVALIDATED))
		fprintf(stderr, "post: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : coap_code_to_cstr(statuscode));

	if(content && content_length) {
		printf("%s", content);
		// Only print a newline if the content doesn't already print one.
		if((content[content_length - 1] != '\n'))
			printf("\n");
	}

	if(gRet == ERRORCODE_INPROGRESS)
		gRet = 0;
	free(request->content);
	free(request->url);
	free(request);
}


smcp_status_t
resend_post_request(struct post_request_s *request) {
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(),request->method, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status, bail);

	status = smcp_outbound_set_content_type(request->content_type);
	require_noerr(status, bail);

	status = smcp_outbound_set_uri(request->url, 0);
	require_noerr(status, bail);

	status = smcp_outbound_append_content(request->content, request->content_len);
	require_noerr(status, bail);

	status = smcp_outbound_send();
	require_noerr(status, bail);

	if(status) {
		check(!status);
		fprintf(stderr,
			"smcp_outbound_send() returned error %d(%s).\n",
			status,
			smcp_status_to_cstr(status));
		goto bail;
	}

bail:
	return status;
}


static coap_transaction_id_t
send_post_request(
	smcp_t	smcp,
	const char*		url,
	coap_code_t		method,
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
	request->content = calloc(1,content_len);
	memcpy(request->content,content,content_len);
	request->content_len = content_len;
	request->content_type = content_type;
	request->method = method;

	tid = smcp_get_next_tid(smcp,NULL);

	gRet = ERRORCODE_INPROGRESS;

	require_noerr(smcp_begin_transaction(
			smcp,
			tid,
			30*1000,	// Retry for thirty seconds.
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
	smcp_t smcp, int argc, char* argv[]
) {
	coap_transaction_id_t tid=0;
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	coap_content_type_t content_type = 0;
	coap_code_t method = COAP_METHOD_POST;
	int i;
	char url[1000];
	url[0] = 0;
	char content[10000];
	content[0] = 0;
	content_type = 0;
	if(strequal_const(argv[0],"put")) {
		method = COAP_METHOD_PUT;
	}
	outbound_slice_size = 100;

	BEGIN_LONG_ARGUMENTS(gRet)
		HANDLE_LONG_ARGUMENT("include") show_headers = true;
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
		HANDLE_SHORT_ARGUMENT('i') show_headers = true;
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
				strlcat(content, " ", sizeof(content));
				strlcat(content, argv[i], sizeof(content));
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

	tid = send_post_request(smcp, url, method,content, strlen(content),content_type);

	while(ERRORCODE_INPROGRESS == gRet)
		smcp_process(smcp, -1);

bail:
	smcp_invalidate_transaction(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
