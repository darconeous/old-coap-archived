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
get_response_handler(
	int statuscode, char* content, size_t content_length, void* context
) {
	smcp_daemon_t self = smcp_get_current_daemon();

	if((statuscode >= 100) && get_show_headers) {
		if(next_len != ((size_t)(-1)))
			fprintf(stdout, "\n\n");
		coap_dump_headers(stdout,
			NULL,
			http_to_coap_code(statuscode),
			smcp_daemon_get_current_request_headers(),
			smcp_daemon_get_current_request_header_count());
	}

	if((statuscode >= 300) && (statuscode < 400) && redirect_count) {
		// Redirect.
		char location[256] = "";
		const coap_header_item_t *iter =
		    smcp_daemon_get_current_request_headers();
		const coap_header_item_t *end = iter +
		    smcp_daemon_get_current_request_header_count();
		for(; iter != end; ++iter) {
			if(iter->key == COAP_HEADER_LOCATION) {
				memcpy(location, iter->value, iter->value_len);
				location[iter->value_len] = 0;
			}
		}
		if(location[0] && (0 != strcmp(location, (const char*)context))) {
			static char redirect_url[SMCP_MAX_URI_LENGTH + 1];
			strncpy(redirect_url,
				    (const char*)context,
				SMCP_MAX_URI_LENGTH);
			url_change(redirect_url, location);
			retries = 0;
			require(send_get_request(self, redirect_url, 0, 0), bail);
			fflush(stdout);
			redirect_count--;
			return;
		}
	}

	if(((statuscode < 200) ||
	            (statuscode >= 300)) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED) &&
	        (statuscode != HTTP_RESULT_CODE_PARTIAL_CONTENT))
		fprintf(stderr, "get: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : http_code_to_cstr(statuscode));

	if(content && content_length) {
		coap_content_type_t content_type = 0;
		const coap_header_item_t *next = NULL;
		const coap_header_item_t *iter =
		    smcp_daemon_get_current_request_headers();
		const coap_header_item_t *end = iter +
		    smcp_daemon_get_current_request_header_count();
		for(; iter != end; ++iter) {
			if(iter->key == COAP_HEADER_CONTENT_TYPE)
				content_type = (unsigned char)iter->value[0];
			else if(iter->key == COAP_HEADER_CONTINUATION_REQUEST)
				next = iter;
		}

		fwrite(content, content_length, 1, stdout);
		if(next) {
			require(send_get_request(self, (const char*)context,
					next->value, next->value_len), bail);
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

bool
resend_get_request(void* context) {
	bool ret = false;
	smcp_status_t status = 0;

	smcp_message_begin(smcp_get_current_daemon(),COAP_METHOD_GET, COAP_TRANS_TYPE_CONFIRMABLE);
	smcp_message_set_uri(url_data, 0);

	if(next_len != ((size_t)(-1))) {
		smcp_message_add_header(
			COAP_HEADER_CONTINUATION_RESPONSE,
			next_data,
			next_len);
	}

	if(size_request) {
		smcp_message_add_header(
			COAP_HEADER_SIZE_REQUEST,
			    (void*)&size_request,
			sizeof(size_request));
	}

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
