/*
 *  cmd_list.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include "assert_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "smcp.h"
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include "cmd_list.h"
#include <string.h>
#include "url-helpers.h"
#include <math.h>

/*
   static arg_list_item_t option_list[] = {
    { 'h', "help",NULL,"Print Help" },
    { 0 }
   };
 */

static bool listIsDone;
static sig_t previous_sigint_handler;
static coap_transaction_id_t tid;

static void
signal_interrupt(int sig) {
	fprintf(stderr, "Interrupt\n");
	listIsDone = 1;
	signal(SIGINT, previous_sigint_handler);
}

bool send_list_request(
	smcp_daemon_t smcp, const char* url, const char* next);

static int retries = 0;
static char url_data[128];
static char next_data[128];
static size_t next_len = HEADER_CSTR_LEN;
static int smcp_rtt = 100;

int calc_retransmit_timeout(int retries) {
	int ret = smcp_rtt;
	int i;

	for(i = 0; i < retries; i++)
		ret *= 2;

	ret *= (1000 - 150) + (SMCP_FUNC_RANDOM_UINT32() % 300);
	ret /= 1000;

//	if(ret!=smcp_rtt)
//		fprintf(stderr,"(retransmit in %dms)\n",ret);
	return ret;
}

bool resend_list_request(smcp_daemon_t smcp);

static void
list_response_handler(
	smcp_daemon_t		self,
	int					statuscode,
	coap_header_item_t	headers[],
	char*				content,
	size_t				content_length,
	struct sockaddr*	saddr,
	socklen_t			socklen,
	void*				context
) {
	if(statuscode == SMCP_STATUS_TIMEOUT && (retries++ < 8)) {
		resend_list_request(self);
		return;
	} else if(statuscode != SMCP_RESULT_CODE_OK) {
		fprintf(stderr, " *** RESULT CODE = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : smcp_code_to_cstr(statuscode));
	}
	if(content && content_length) {
		coap_header_item_t *next_header;
		char contentBuffer[500];
		smcp_content_type_t content_type = 0;
		for(next_header = headers;
		    smcp_header_item_get_key(next_header);
		    next_header = smcp_header_item_next(next_header)) {
			if(smcp_header_item_key_equal(next_header,
					SMCP_HEADER_CONTENT_TYPE))
				content_type = (unsigned char)next_header->value[0];
		}

		if(content_type != SMCP_CONTENT_TYPE_APPLICATION_LINK_FORMAT) {
			fprintf(stderr, " *** Not a directory\n");
		} else {
			char *iter = content;
			char *end = content + content_length;

			while(iter < end) {
				if(*iter == '<') {
					iter++;

					// print out the node name
					while((iter < end) && (*iter != '>')) {
						printf("%c", *iter++);
					}
					printf("\n");

					// Skip past any arguments
					while((iter < end) && (*iter != ',')) {
						iter++;
					}
					iter++;
				} else {
					iter++;
				}
			}

			content_length =
			    ((content_length > sizeof(contentBuffer) -
			        2) ? sizeof(contentBuffer) - 2 : content_length);

			if(content[content_length - 1] == '\n')
				content[--content_length] = 0;
			else
				content[content_length] = 0;

			for(next_header = headers;
			    smcp_header_item_get_key(next_header);
			    next_header = smcp_header_item_next(next_header)) {
				if(smcp_header_item_key_equal(next_header,
						SMCP_HEADER_MORE)) {
					char* next = smcp_header_item_get_value(next_header);
					if(0 == smcp_header_item_get_value_len(next_header)) {
						// In this case we need to use
						// the last item in the list.
						next = content + content_length - 1;
						while((next != content) && (next[-1] != '\n') &&
						        (next[-1] != ',')) {
							next--;
						}
					} else {
						next[smcp_header_item_get_value_len(next_header)]
						    = 0;
					}
					if(send_list_request(self, (const char*)context, next))
						return;
				}
			}
		}
	}

	listIsDone = true;
}

bool
resend_list_request(smcp_daemon_t smcp) {
	bool ret = false;
	smcp_status_t status = 0;
	coap_header_item_t headers[SMCP_MAX_HEADERS * 2 + 1] = {  };

	if(next_data[0]) {
		util_add_header(headers,
			SMCP_MAX_HEADERS,
			SMCP_HEADER_NEXT,
			next_data,
			next_len);
	}

	status = smcp_daemon_add_response_handler(
		smcp,
		tid,
		calc_retransmit_timeout(retries),
		0, // Flags
		    (void*)&list_response_handler,
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
#if 0
		SMCP_METHOD_LIST,
#else
		SMCP_METHOD_GET,
#endif
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
send_list_request(
	smcp_daemon_t smcp, const char* url, const char* next
) {
	bool ret = false;

	tid = SMCP_FUNC_RANDOM_UINT32();
	listIsDone = false;

	retries = 0;

	strcpy(url_data, url);
	if(next)
		strcpy(next_data, next);
	else
		next_data[0] = 0;

	ret = resend_list_request(smcp);

bail:
	return ret;
}

int
tool_cmd_list(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	int ret = -1;

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

	require(send_list_request(smcp, url, NULL), bail);

	while(!listIsDone)
		smcp_daemon_process(smcp, -1);

	ret = 0;
bail:
	smcp_invalidate_response_handler(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return 0;
}
