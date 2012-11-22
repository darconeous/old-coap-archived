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

static arg_list_item_t option_list[] = {
	{ 'h', "help",	  NULL, "Print Help"				},
	{ 'i', "include", NULL, "include headers in output" },
	{ 'f', "follow",  NULL, "follow redirects"			},
	{ 'O', "observe",  NULL, "Observe changes"			},
	{ 0  , "timeout",  "seconds", "Change timeout period (Default: 30 Seconds)" },
	{ 'a', "accept", "mime-type/coap-number", "hint to the server the content-type you want" },
	{ 0 }
};

typedef void (*sig_t)(int);

static int gRet;
static sig_t previous_sigint_handler;
static coap_transaction_id_t tid;
static bool get_show_headers, get_observe;
static uint16_t size_request;
static cms_t get_timeout;

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
static coap_transaction_id_t tokenid;
static int last_observe_value = -1;
static int last_block = -1;
static int block_key = COAP_HEADER_BLOCK2;
static coap_content_type_t request_accept_type = -1;

static void
get_response_handler(int statuscode, void* context) {
	smcp_t const self = smcp_get_current_instance();
	const char* content = smcp_inbound_get_content_ptr();
	size_t content_length = smcp_inbound_get_content_len();

	if((statuscode >= COAP_RESULT_100) && get_show_headers) {
		if(next_len != ((size_t)(-1)))
			fprintf(stdout, "\n\n");
		coap_dump_header(
			stdout,
			NULL,
			smcp_inbound_get_packet(),
			0
		);
	}

	if(statuscode == SMCP_STATUS_TRANSACTION_INVALIDATED) {
		gRet = 0;
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
		const uint8_t* next_value = NULL;
		size_t next_len;
		bool has_observe_option = false, last_block = true;
		int observe_value = -1;
		int block = -1;

		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_HEADER_INVALID) {

			if(key == COAP_HEADER_OBSERVE) {
				has_observe_option = true;
				if(value_len)
					observe_value = value[0];
				else observe_value = 0;
			}

			if((key == COAP_HEADER_BLOCK2) && value_len) {
				static uint8_t tmp[5];
				next_len = value_len<3?value_len:3;
				memcpy(tmp,value,next_len);
				block_key = key;
				last_block = !(tmp[next_len-1]&(1<<3));

				if(!last_block) {
					if(next_len==1)
						block = (tmp[0]>>4);
					else if(next_len==2)
						block = (tmp[0]<<4)+(tmp[1]>>4);
					else if(next_len==3)
						block = (tmp[1]<<12)+(tmp[1]<<4)+(tmp[2]>>4);

					block++;

					if(next_len==1) {
						tmp[0] = (tmp[0]&0xf)| ((block&0xf)<<4);
					} else if(next_len==2) {
						tmp[0] = ((block>>4)&0xf);
						tmp[1] = (tmp[1]&0xf)| ((block&0xf)<<4);
					} else if(next_len==3) {
						tmp[0] = ((block>>12)&0xf);
						tmp[1] = ((block>>4)&0xf);
						tmp[2] = (tmp[2]&0xf)| ((block&0xf)<<4);
					}

					next_value = tmp;

					block--;
				}
			}
		}

		fwrite(content, content_length, 1, stdout);

		if(!(get_observe && observe_value>=0) && next_value) {
			require(send_get_request(self, (const char*)context,
					(const char*)next_value, next_len), bail);
			fflush(stdout);
			return;
		} else if(last_block) {
			if((content[content_length - 1] != '\n'))
				printf("\n");
		}

		fflush(stdout);

		last_block = block;
		last_observe_value = observe_value;
	}

bail:
	if(!get_observe && gRet == ERRORCODE_INPROGRESS)
		gRet = 0;
	return;
}

smcp_status_t
resend_get_request(void* context) {
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(),COAP_METHOD_GET, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(url_data, 0);
	require_noerr(status,bail);

	status = smcp_outbound_add_option(COAP_HEADER_TOKEN, (void*)&tokenid, sizeof(tokenid));
	require_noerr(status,bail);

	if(request_accept_type!=COAP_CONTENT_TYPE_UNKNOWN) {
		status = smcp_outbound_add_option(COAP_HEADER_ACCEPT, (void*)&request_accept_type, sizeof(request_accept_type));
		require_noerr(status,bail);
	}

	if(next_len != ((size_t)(-1))) {
		status = smcp_outbound_add_option(
			block_key,
			next_data,
			next_len
		);
		require_noerr(status,bail);
	}

//	if(size_request) {
//		status = smcp_outbound_add_option(
//			COAP_HEADER_SIZE_REQUEST,
//			(void*)&size_request,
//			sizeof(size_request)
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

	tid = smcp_get_next_tid(smcp,NULL);
	gRet = ERRORCODE_INPROGRESS;

	if(!next)
		tokenid = tid;

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
		get_timeout,
		get_observe?(SMCP_TRANSACTION_OBSERVE|SMCP_TRANSACTION_ALWAYS_TIMEOUT):0, // Flags
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
	get_timeout = 30*1000; // Default timeout is 30 seconds.
	last_observe_value = -1;
	last_block = -1;
	request_accept_type = COAP_CONTENT_TYPE_UNKNOWN;

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

	require(send_get_request(smcp, url, NULL, 0), bail);

	while(gRet == ERRORCODE_INPROGRESS)
		smcp_process(smcp, 50);

bail:
	smcp_invalidate_transaction(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
