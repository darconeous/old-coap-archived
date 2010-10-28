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
/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 0 }
   };
 */

typedef void (*sig_t)(int);

static int gRet;
static sig_t previous_sigint_handler;
static coap_transaction_id_t tid;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

bool send_get_request(
	smcp_daemon_t smcp, const char* url, const char* next, size_t nextlen);

static int retries = 0;
static char url_data[128];
static char next_data[128];
static size_t next_len = HEADER_CSTR_LEN;
static int smcp_rtt = 120;

static int calc_retransmit_timeout(int retries_) {
	int ret = smcp_rtt;
	int i;

	for(i = 0; i < retries_; i++)
		ret *= 2;

	ret *= (1000 - 150) + (SMCP_FUNC_RANDOM_UINT32() % 300);
	ret /= 1000;

	if(ret > 4000)
		ret = 4000;
//	if(ret!=smcp_rtt)
//		fprintf(stderr,"(retransmit in %dms)\n",ret);
	return ret;
}

bool resend_get_request(smcp_daemon_t smcp);

static void
get_response_handler(
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	char*				content,
	size_t				content_length,
	void*				context
) {
	if(statuscode == SMCP_STATUS_TIMEOUT && (retries++ < 8)) {
		resend_get_request(self);
		return;
	}

	if(((statuscode < 200) ||
	            (statuscode >= 300)) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED) &&
	        (statuscode != SMCP_RESULT_CODE_PARTIAL_CONTENT))
		fprintf(stderr, "get: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : smcp_code_to_cstr(statuscode));

	if(content && content_length) {
		coap_header_item_t *next = NULL;
		coap_header_item_t *next_header;
		coap_content_type_t content_type = 0;
		for(next_header = headers;
		    smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header)) {
			if(smcp_header_item_key_equal(next_header,
					COAP_HEADER_CONTENT_TYPE))
				content_type = (unsigned char)next_header->value[0];
			else if(smcp_header_item_key_equal(next_header,
					COAP_HEADER_NEXT))
				next = next_header;
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
resend_get_request(smcp_daemon_t smcp) {
	bool ret = false;
	smcp_status_t status = 0;
	coap_header_item_t headers[SMCP_MAX_HEADERS + 1] = {  };

	if(next_data[0]) {
		util_add_header(headers,
			SMCP_MAX_HEADERS,
			COAP_HEADER_NEXT,
			next_data,
			next_len);
	}

	status = smcp_daemon_add_response_handler(
		smcp,
		tid,
		calc_retransmit_timeout(retries),
		0, // Flags
		    (void*)&get_response_handler,
		    (void*)url_data
	    );

	if(status) {
		check(!status);
		fprintf(stderr,
			"smcp_daemon_add_response_handler() returned %d.\n",
			status);
		goto bail;
	}

	status = smcp_daemon_send_request_to_url(
		smcp,
		tid,
		SMCP_METHOD_GET,
		url_data,
		headers,
		NULL,
		0
	    );

	if(status) {
		check(!status);
		fprintf(stderr,
			"smcp_daemon_send_request_to_url() returned %d.\n",
			status);
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

	tid = SMCP_FUNC_RANDOM_UINT32();
	gRet = ERRORCODE_INPROGRESS;

	retries = 0;

	strcpy(url_data, url);
	if(next) {
		memcpy(next_data, next, nextlen);
		next_len = nextlen;
	} else {
		next_data[0] = 0;
	}

	ret = resend_get_request(smcp);

bail:
	return ret;
}

int
tool_cmd_get(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	gRet = ERRORCODE_INPROGRESS;

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

	require(send_get_request(smcp, url, NULL, 0), bail);

	while(gRet == ERRORCODE_INPROGRESS)
		smcp_daemon_process(smcp, -1);

bail:
	smcp_invalidate_response_handler(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
