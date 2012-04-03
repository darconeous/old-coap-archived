/*
 *  cmd_pair.c
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
#include "cmd_pair.h"
#include <smcp/url-helpers.h>
#include <signal.h>
#include "smcpctl.h"

/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 0 }
   };
 */

static int gRet;
static sig_t previous_sigint_handler;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

static void
pair_response_handler(
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
	if(((statuscode < 200) ||
	            (statuscode >= 300)) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED))
		fprintf(stderr, "pair: Result code = %d (%s)\n", statuscode,
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
		gRet = ERRORCODE_OK;
	free(context);
}

bool
resend_pair_request(char* url[2]) {
	bool ret = false;

	require_noerr(smcp_message_begin(smcp_get_current_daemon(),COAP_METHOD_PAIR, COAP_TRANS_TYPE_CONFIRMABLE),bail);
	smcp_message_set_uri(url[0],0);
	smcp_message_set_content(url[1], COAP_HEADER_CSTR_LEN);
	require_noerr(smcp_message_send(),bail);

	ret = true;

bail:
	return ret;
}

static coap_transaction_id_t
send_pair_request(
	smcp_daemon_t smcp, const char* url, const char* url2
) {
	bool ret = false;
	coap_transaction_id_t tid;
	const char** url_ = calloc(2,sizeof(char*));

	require(url_,bail);
	url_[0] = url;
	url_[1] = url2;

	tid = SMCP_FUNC_RANDOM_UINT32();
	//static char tid_str[30];

	gRet = ERRORCODE_INPROGRESS;

	//snprintf(tid_str,sizeof(tid_str),"%d",tid);

//	util_add_header(headers,SMCP_MAX_HEADERS,COAP_HEADER_ID,tid_str);

	if(strcmp(url, url2) == 0) {
		fprintf(stderr, "Pairing a URL to itself is invalid.\n");
		goto bail;
	}

	printf("Pairing \"%s\" to \"%s\"...\n", url, url2);

	require_noerr(smcp_begin_transaction(
			smcp,
			tid,
			30*1000,	// Retry for thirty seconds.
			0, // Flags
			(void*)&resend_pair_request,
			(void*)&pair_response_handler,
			(void*)url_
		), bail);

	ret = true;

bail:
	if(!ret) {
		tid = 0;
		free(url_);
	}
	return tid;
}

int
tool_cmd_pair(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	coap_transaction_id_t tid;

	char url[1000];
	url[0] = 0;

	if((2 == argc) && (0 == strcmp(argv[1], "--help"))) {
		printf("Help not yet implemented for this command.\n");
		return ERRORCODE_HELP;
	}

	gRet = ERRORCODE_UNKNOWN;

	if(getenv("SMCP_CURRENT_PATH")) {
		strncpy(url, getenv("SMCP_CURRENT_PATH"), sizeof(url));
		if(argc >= 2)
			url_change(url, argv[1]);
	} else {
		if(argc >= 2) {
			strncpy(url, argv[1], sizeof(url));
		} else {
			fprintf(stderr, "Bad args.\n");
			gRet = ERRORCODE_BADARG;
			goto bail;
		}
	}

	if(argc == 2) {
		require((tid=send_pair_request(smcp, getenv(
					"SMCP_CURRENT_PATH"), url)), bail);
	} else if(argc == 3) {
		char url2[1000];

		if(getenv("SMCP_CURRENT_PATH")) {
			strncpy(url2, getenv("SMCP_CURRENT_PATH"), sizeof(url2));
			url_change(url2, argv[2]);
		} else {
			strncpy(url2, argv[2], sizeof(url2));
		}

		require((tid=send_pair_request(smcp, url, url2)), bail);
	} else {
		fprintf(stderr, "Bad args.\n");
		gRet = ERRORCODE_BADARG;
		goto bail;
	}

	gRet = ERRORCODE_INPROGRESS;

	while(ERRORCODE_INPROGRESS == gRet)
		smcp_daemon_process(smcp, -1);

bail:
	smcp_invalidate_transaction(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
