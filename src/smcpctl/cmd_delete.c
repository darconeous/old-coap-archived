/*
 *  cmd_delete.c
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
#include "cmd_delete.h"
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


/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 'c', "content-file",NULL,"Use content from the specified input source" },
    { 0 }
   };
 */
static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

static void
delete_response_handler(
	int			statuscode,
	const char* content,
	size_t		content_length,
	void*		context
) {
	if((statuscode != HTTP_RESULT_CODE_OK) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED))
		fprintf(stderr, "delete: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : http_code_to_cstr(statuscode));
	if(content && (statuscode != HTTP_RESULT_CODE_CHANGED) &&
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

smcp_status_t
resend_delete_request(const char* url) {
	smcp_status_t status = 0;

	status = smcp_message_begin(smcp_get_current_daemon(), COAP_METHOD_DELETE, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	status = smcp_message_set_uri(url, 0);
	require_noerr(status,bail);

	status = smcp_message_send();
	require_noerr(status,bail);

	gRet = ERRORCODE_INPROGRESS;

bail:
	return status;
}


coap_transaction_id_t
send_delete_request(
	smcp_daemon_t smcp, const char* url
) {
	coap_transaction_id_t tid = SMCP_FUNC_RANDOM_UINT32();

	require_noerr(smcp_begin_transaction(
			smcp,
			tid,
			30*1000,	// Retry for thirty seconds.
			0, // Flags
			(void*)&resend_delete_request,
			&delete_response_handler,
			    (void*)url
		), bail);

	gRet = ERRORCODE_INPROGRESS;

bail:
	return tid;
}

int
tool_cmd_delete(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	coap_transaction_id_t tid = 0;

	char url[1000] = "";

	if((2 == argc) && (0 == strcmp(argv[1], "--help"))) {
		printf("Help not yet implemented for this command.\n");
		return ERRORCODE_HELP;
	}

	gRet = ERRORCODE_UNKNOWN;

	if(getenv("SMCP_CURRENT_PATH"))
		strncpy(url, getenv("SMCP_CURRENT_PATH"), sizeof(url));

	if(argc == 2) {
		url_change(url, argv[1]);
	} else {
		fprintf(stderr, "Bad args.\n");
		gRet = ERRORCODE_BADARG;
		goto bail;
	}

	require((tid=send_delete_request(smcp, url)), bail);

	gRet = ERRORCODE_INPROGRESS;

	while(ERRORCODE_INPROGRESS == gRet)
		smcp_daemon_process(smcp, -1);

bail:
	smcp_invalidate_transaction(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
