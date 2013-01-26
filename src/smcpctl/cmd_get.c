/*
 *  cmd_get.c
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
#include "cmd_get.h"
#include <smcp/url-helpers.h>
#include <signal.h>
#include "smcpctl.h"
#include <sys/sysctl.h>
#include <smcp/smcp-internal.h>

static arg_list_item_t option_list[] = {
	{ 'h', "help",	  NULL, "Print Help"				},
	{ 'i', "include", NULL, "include headers in output" },
	{ 'f', "follow",  NULL, "follow redirects"			},
	{ 'O', "observe",  NULL, "Observe changes"			},
	{ 'k', "keep-alive",  NULL, "Send keep-alive packets" },
	{ 0, "size-request", NULL, "writeme" },
	{ 0  , "timeout",  "seconds", "Change timeout period (Default: 30 Seconds)" },
	{ 'a', "accept", "mime-type/coap-number", "hint to the server the content-type you want" },
	{ 0, "ignore-first", NULL, "writeme" },
	{ 0, "observe-once", NULL, "writeme" },
	{ 0 }
};

typedef void (*sig_t)(int);

static int gRet;
static sig_t previous_sigint_handler;
static coap_msg_id_t tid;
static bool get_show_headers, get_observe, get_keep_alive;
static uint16_t size_request;
static cms_t get_timeout;
static bool observe_ignore_first;
static bool observe_once;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

bool send_get_request(
	smcp_t smcp, const char* url, const char* next, size_t nextlen);

static int retries = 0;
static const char *url_data;
static char next_data[128];
static size_t next_len = ((size_t)(-1));
static int redirect_count;
static coap_msg_id_t tokenid;
static int last_observe_value = -1;
static int last_block = -1;
static coap_content_type_t request_accept_type = -1;

static struct smcp_transaction_s transaction;

static smcp_status_t
get_response_handler(int statuscode, void* context) {
//	smcp_t const self = smcp_get_current_instance();
	const char* content = smcp_inbound_get_content_ptr();
	size_t content_length = smcp_inbound_get_content_len();

	if(statuscode>=0) {
		if(content_length>(smcp_inbound_get_packet_length()-4)) {
			fprintf(stderr, "INTERNAL ERROR: CONTENT_LENGTH LARGER THAN PACKET_LENGTH-4! (content_length=%lu, packet_length=%lu)\n",content_length,smcp_inbound_get_packet_length());
			gRet = ERRORCODE_UNKNOWN;
			goto bail;
		}

		if((statuscode >= 0) && get_show_headers) {
			if(next_len != ((size_t)(-1)))
				fprintf(stdout, "\n\n");
			coap_dump_header(
				stdout,
				NULL,
				smcp_inbound_get_packet(),
				smcp_inbound_get_packet_length()
			);
		}

		if(!coap_verify_packet((void*)smcp_inbound_get_packet(), smcp_inbound_get_packet_length())) {
			fprintf(stderr, "INTERNAL ERROR: CALLBACK GIVEN INVALID PACKET!\n");
			gRet = ERRORCODE_UNKNOWN;
			goto bail;
		}
	}

	if(statuscode == SMCP_STATUS_TRANSACTION_INVALIDATED) {
		gRet = 0;
	}

	if(observe_ignore_first) {
		observe_ignore_first = false;
		goto bail;
	}

	if(	((statuscode < COAP_RESULT_200) ||(statuscode >= COAP_RESULT_400))
		&& (statuscode != SMCP_STATUS_TRANSACTION_INVALIDATED)
		&& (statuscode != HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT))
	) {
		if(get_observe && statuscode == SMCP_STATUS_TIMEOUT) {
			gRet = 0;
		} else {
			gRet = (statuscode == SMCP_STATUS_TIMEOUT)?ERRORCODE_TIMEOUT:ERRORCODE_COAP_ERROR;
			fprintf(stderr, "get: Result code = %d (%s)\n", statuscode,
					(statuscode < 0) ? smcp_status_to_cstr(
					statuscode) : coap_code_to_cstr(statuscode));
		}
	}

	if((statuscode>0) && content && content_length) {
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		bool last_block = true;
		int32_t observe_value = -1;

		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {

			if(key == COAP_OPTION_BLOCK2) {
				last_block = !(value[value_len-1]&(1<<3));
			} else if(key == COAP_OPTION_OBSERVE) {
				if(value_len)
					observe_value = value[0];
				else observe_value = 0;
			}

		}

		fwrite(content, content_length, 1, stdout);

		if(last_block) {
			// Only print a newline if the content doesn't already print one.
			if(content_length && (content[content_length - 1] != '\n'))
				printf("\n");
		}

		fflush(stdout);

		last_observe_value = observe_value;
	}

	if(observe_once) {
		gRet = 0;
		goto bail;
	}

bail:
//	if(!get_observe && gRet == ERRORCODE_INPROGRESS)
//		gRet = 0;
	return SMCP_STATUS_OK;
}

smcp_status_t
resend_get_request(void* context) {
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(),COAP_METHOD_GET, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(url_data, 0);
	require_noerr(status,bail);

	if(request_accept_type!=COAP_CONTENT_TYPE_UNKNOWN) {
		status = smcp_outbound_add_option_uint(COAP_OPTION_ACCEPT, request_accept_type);
		require_noerr(status,bail);
	}

//	if(next_len != ((size_t)(-1))) {
//		status = smcp_outbound_add_option(
//			block_key,
//			next_data,
//			next_len
//		);
//		require_noerr(status,bail);
//	}

	status = smcp_outbound_send();

	if(status) {
		check_noerr(status);
		fprintf(stderr,
			"smcp_outbound_send() returned error %d(%s).\n",
			status,
			smcp_status_to_cstr(status));
		goto bail;
	}

bail:
	return status;
}

bool
send_get_request(
	smcp_t smcp, const char* url, const char* next, size_t nextlen
) {
	bool ret = false;
	smcp_status_t status = 0;
	int flags = SMCP_TRANSACTION_ALWAYS_INVALIDATE;
	gRet = ERRORCODE_INPROGRESS;

	retries = 0;
	url_data = url;

	if(get_observe)
		flags |= SMCP_TRANSACTION_OBSERVE;
	if(get_keep_alive)
		flags |= SMCP_TRANSACTION_KEEPALIVE;

	smcp_transaction_end(smcp,&transaction);
	smcp_transaction_init(
		&transaction,
		flags, // Flags
		(void*)&resend_get_request,
		(void*)&get_response_handler,
		(void*)url_data
	);
	status = smcp_transaction_begin(smcp, &transaction, get_timeout);

	if(status) {
		check(!status);
		fprintf(stderr,
			"smcp_begin_transaction_old() returned %d(%s).\n",
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
	smcp_t smcp, int argc, char* argv[]
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
	get_observe = false;
	get_keep_alive = false;
	get_timeout = 30*1000; // Default timeout is 30 seconds.
	last_observe_value = -1;
	last_block = -1;
	request_accept_type = COAP_CONTENT_TYPE_UNKNOWN;
	observe_once = false;
	observe_ignore_first = false;

	if(strcmp(argv[0],"observe")==0 || strcmp(argv[0],"obs")==0) {
		get_observe = true;
		get_timeout = CMS_DISTANT_FUTURE;
	}

	BEGIN_LONG_ARGUMENTS(gRet)
	HANDLE_LONG_ARGUMENT("include") get_show_headers = true;
	HANDLE_LONG_ARGUMENT("follow") redirect_count = 10;
	HANDLE_LONG_ARGUMENT("no-follow") redirect_count = 0;
	HANDLE_LONG_ARGUMENT("slice-size") size_request = htons(strtol(argv[++i], NULL, 0));
	HANDLE_LONG_ARGUMENT("timeout") get_timeout = 1000*strtof(argv[++i], NULL);
	HANDLE_LONG_ARGUMENT("observe") get_observe = true;
	HANDLE_LONG_ARGUMENT("no-observe") get_observe = false;
	HANDLE_LONG_ARGUMENT("keep-alive") get_keep_alive = true;
	HANDLE_LONG_ARGUMENT("no-keep-alive") get_keep_alive = false;
	HANDLE_LONG_ARGUMENT("once") observe_once = true;
	HANDLE_LONG_ARGUMENT("ignore-first") observe_ignore_first = true;
	HANDLE_LONG_ARGUMENT("accept") {
		i++;
		if(!argv[i]) {
			fprintf(stderr, "Missing argument for \"%s\"\n", argv[i-1]);
			gRet = ERRORCODE_BADARG;
			goto bail;
		}
		request_accept_type = coap_content_type_from_cstr(argv[i]);
	}

	HANDLE_LONG_ARGUMENT("help") {
		print_arg_list_help(option_list, argv[0], "[args] <uri>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(gRet)
	HANDLE_SHORT_ARGUMENT('i') get_show_headers = true;
	HANDLE_SHORT_ARGUMENT('f') redirect_count = 10;
	HANDLE_SHORT_ARGUMENT('O') get_observe = true;
	HANDLE_SHORT_ARGUMENT('a') {
		i++;
		if(!argv[i]) {
			fprintf(stderr, "Missing argument for \"%s\"\n", argv[i-1]);
			gRet = ERRORCODE_BADARG;
			goto bail;
		}
		request_accept_type = coap_content_type_from_cstr(argv[i]);
	}

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

	if(size_request) {
		char block[] = {1};
		require(send_get_request(smcp, url, block, 1), bail);
	} else {
		require(send_get_request(smcp, url, NULL, 0), bail);
	}

	while(gRet == ERRORCODE_INPROGRESS)
		smcp_process(smcp, 50);

bail:
	smcp_transaction_end(smcp,&transaction);
	signal(SIGINT, previous_sigint_handler);
	url_data = NULL;
	return gRet;
}
