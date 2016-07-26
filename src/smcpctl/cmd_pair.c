/*
 *  cmd_pair.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "smcp/assert-macros.h"
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
#include <smcp/smcp-pairing.h>

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

static smcp_status_t
pair_response_handler(
	int			statuscode,
	void*		context
) {
//	smcp_t const self = smcp_get_current_instance();
	char* content = (char*)smcp_inbound_get_content_ptr();
	coap_size_t content_length = smcp_inbound_get_content_len();
	if((statuscode >= COAP_RESULT_100) && show_headers) {
		fprintf(stdout, "\n");
		coap_dump_header(
			stdout,
			"NULL",
			smcp_inbound_get_packet(),
			0
		);
	}
	if(((statuscode < COAP_RESULT_200) ||
	            (statuscode >= COAP_RESULT_300)) &&
	        (statuscode != SMCP_STATUS_TRANSACTION_INVALIDATED))
		fprintf(stderr, "pair: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : coap_code_to_cstr(statuscode));
	if(content &&
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
	return SMCP_STATUS_OK;
}

smcp_status_t
resend_pair_request(char* url[2]) {
	smcp_status_t status;
#if SMCP_ENABLE_PAIRING
	coap_size_t len = 8;
	bool did_mutate = false;
	while(url[0][len] && url[0][len]!='/') {
		len++;
	}

	// Temporarily mutate the input url because I'm lazy.
	if(url[0][len]) {
		did_mutate = true;
		url[0][len] = 0;
	}

	status = smcp_outbound_begin(
		smcp_get_current_instance(),
		COAP_METHOD_PUT,
		COAP_TRANS_TYPE_CONFIRMABLE
	);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(url[0],0);
	require_noerr(status,bail);

	// Root pairings object path
	status = smcp_outbound_add_option(COAP_OPTION_URI_PATH,SMCP_PAIRING_DEFAULT_ROOT_PATH,SMCP_CSTR_LEN);
	require_noerr(status,bail);

	// Path to pair with
	status = smcp_outbound_add_option(COAP_OPTION_URI_PATH,url[0]+len+1,SMCP_CSTR_LEN);
	require_noerr(status,bail);

	// Remote target
	status = smcp_outbound_add_option(COAP_OPTION_URI_PATH,url[1],SMCP_CSTR_LEN);
	require_noerr(status,bail);

	status = smcp_outbound_send();
	require_noerr(status,bail);
bail:
	if(did_mutate) {
		url[0][len] = '/';
	}
#else
	status = SMCP_STATUS_NOT_IMPLEMENTED;
#endif
	return status;
}

static coap_msg_id_t
send_pair_request(
	smcp_t smcp, const char* url, const char* url2
) {
	bool ret = false;
	coap_msg_id_t tid;
	const char** url_ = calloc(2,sizeof(char*));

	require(url_,bail);
	url_[0] = url;
	url_[1] = url2;

	tid = smcp_get_next_msg_id(smcp);
	//static char tid_str[30];

	gRet = ERRORCODE_INPROGRESS;

	if(strcmp(url, url2) == 0) {
		fprintf(stderr, "Pairing a URL to itself is invalid.\n");
		goto bail;
	}

	printf("Pairing \"%s\" to \"%s\"...\n", url, url2);

	require_noerr(smcp_begin_transaction_old(
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
	smcp_t smcp, int argc, char* argv[]
) {
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	coap_msg_id_t tid=0;

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

	while(ERRORCODE_INPROGRESS == gRet) {
		smcp_plat_wait(smcp,1000);
		smcp_plat_process(smcp);
	}

bail:
	smcp_invalidate_transaction_old(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
