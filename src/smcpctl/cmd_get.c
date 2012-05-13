/*
 *  cmd_get.c
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
#include "cmd_get.h"
#include <smcp/url-helpers.h>
#include <signal.h>
#include "smcpctl.h"
#include <sys/sysctl.h>

static arg_list_item_t option_list[] = {
	{ 'h', "help",	  NULL, "Print Help"				},
	{ 'i', "include", NULL, "include headers in output" },
	{ 'f', "follow",  NULL, "follow redirects"			},
	{ 0 }
};

typedef void (*sig_t)(int);

static int gRet;
static sig_t previous_sigint_handler;
static coap_transaction_id_t tid;
static bool get_show_headers;
static uint16_t size_request;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

bool send_get_request(
	smcp_daemon_t smcp, const char* url, const char* next, size_t nextlen);

static int retries = 0;
static const char *url_data;
static char next_data[128];
static size_t next_len = ((size_t)(-1));
static int redirect_count;



static void
get_response_handler(int statuscode, void* context) {
	smcp_daemon_t self = smcp_get_current_daemon();
	char* content = smcp_daemon_get_current_inbound_content_ptr();
	size_t content_length = smcp_daemon_get_current_inbound_content_len(); 

	if((statuscode >= COAP_RESULT_100) && get_show_headers) {
		if(next_len != ((size_t)(-1)))
			fprintf(stdout, "\n\n");
		coap_dump_header(
			stdout,
			NULL,
			smcp_current_request_get_packet(),
			0
		);
	}

	if(((statuscode < COAP_RESULT_200) ||
	            (statuscode >= COAP_RESULT_400)) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED) &&
	        (statuscode != HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT)))
		fprintf(stderr, "get: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : coap_code_to_cstr(statuscode));

	if(content && content_length) {
		coap_content_type_t content_type = smcp_daemon_get_current_inbound_content_type();
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		const uint8_t* next_value = NULL;
		size_t next_len;
		while((key=smcp_current_request_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {

			if(key == COAP_HEADER_CONTINUATION_REQUEST) {
				next_value = value;
				next_len = value_len;
			}
		}

		fwrite(content, content_length, 1, stdout);
		if(next_value) {
			require(send_get_request(self, (const char*)context,
					next_value, next_len), bail);
			fflush(stdout);
			return;
		} else {
			if((content[content_length - 1] != '\n'))
				printf("\n");
		}
	}

bail:
	if(gRet == ERRORCODE_INPROGRESS)
		gRet = 0;
	return;
}

smcp_status_t
resend_get_request(void* context) {
	smcp_status_t status = 0;

	status = smcp_message_begin(smcp_get_current_daemon(),COAP_METHOD_GET, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	status = smcp_message_set_uri(url_data, 0);
	require_noerr(status,bail);

	if(next_len != ((size_t)(-1))) {
		status = smcp_message_add_header(
			COAP_HEADER_CONTINUATION_RESPONSE,
			next_data,
			next_len
		);
		require_noerr(status,bail);
	}

	if(size_request) {
		status = smcp_message_add_header(
			COAP_HEADER_SIZE_REQUEST,
			(void*)&size_request,
			sizeof(size_request)
		);
		require_noerr(status,bail);
	}

	status = smcp_message_send();

	if(status) {
		check_noerr(status);
		fprintf(stderr,
			"smcp_message_send() returned error %d(%s).\n",
			status,
			smcp_status_to_cstr(status));
		goto bail;
	}

bail:
	return status;
}

bool
send_get_request(
	smcp_daemon_t smcp, const char* url, const char* next, size_t nextlen
) {
	bool ret = false;
	smcp_status_t status = 0;

	tid = SMCP_FUNC_RANDOM_UINT32();
	gRet = ERRORCODE_INPROGRESS;

	retries = 0;
	url_data = url;
	if(next) {
		memcpy(next_data, next, nextlen);
		next_len = nextlen;
	} else {
		next_len = ((size_t)(-1));
	}

	status = smcp_begin_transaction(
		smcp,
		tid,
		30*1000,	// Retry for thirty seconds.
		0, // Flags
		(void*)&resend_get_request,
		(void*)&get_response_handler,
		(void*)url_data
	);

	if(status) {
		check(!status);
		fprintf(stderr,
			"smcp_begin_transaction() returned %d(%s).\n",
			status,
			smcp_status_to_cstr(status));
		goto bail;
	}

	ret = true;

bail:
	return ret;
}


int
tool_cmd_get(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	gRet = ERRORCODE_INPROGRESS;
	int i;
	char url[1000] = "";

	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	get_show_headers = false;
	next_len = ((size_t)(-1));
	get_show_headers = false;
	redirect_count = 0;
	size_request = 0;

	BEGIN_LONG_ARGUMENTS(gRet)
	HANDLE_LONG_ARGUMENT("include") get_show_headers = true;
	HANDLE_LONG_ARGUMENT("follow") redirect_count = 10;
	HANDLE_LONG_ARGUMENT("no-follow") redirect_count = 0;
	HANDLE_LONG_ARGUMENT("slice-size") size_request =
	    htons(strtol(argv[++i], NULL, 0));

	HANDLE_LONG_ARGUMENT("help") {
		print_arg_list_help(option_list, argv[0], "[args] <uri>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(gRet)
	HANDLE_SHORT_ARGUMENT('i') get_show_headers = true;
	HANDLE_SHORT_ARGUMENT('f') redirect_count = 10;

	HANDLE_SHORT_ARGUMENT2('h', '?') {
		print_arg_list_help(option_list, argv[0], "[args] <uri>");
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
			fprintf(stderr, "Unexpected extra argument: \"%s\"\n", argv[i]);
			gRet = ERRORCODE_BADARG;
			goto bail;
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

	require(send_get_request(smcp, url, NULL, 0), bail);

	while(gRet == ERRORCODE_INPROGRESS)
		smcp_daemon_process(smcp, 50);

bail:
	smcp_invalidate_transaction(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
