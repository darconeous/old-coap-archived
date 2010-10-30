/*
 *  cmd_list.c
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
#include "cmd_list.h"
#include <string.h>
#include <smcp/url-helpers.h>
#include <math.h>
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
static coap_transaction_id_t tid;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

bool send_list_request(
	smcp_daemon_t smcp, const char* url, const char* next, size_t nextlen);

static int retries = 0;
static char url_data[128];
static char next_data[128];
static size_t next_len = ((size_t)(-1));
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

bool resend_list_request(smcp_daemon_t smcp);

static void
list_response_handler(
	smcp_daemon_t	self,
	int				statuscode,
	char*			content,
	size_t			content_length,
	void*			context
) {
	if(statuscode == SMCP_STATUS_TIMEOUT && (retries++ < 8)) {
		resend_list_request(self);
		return;
	}

	if(((statuscode < 200) ||
	            (statuscode >= 300)) &&
	        (statuscode != SMCP_STATUS_HANDLER_INVALIDATED) &&
	        (statuscode != COAP_RESULT_CODE_PARTIAL_CONTENT))
		fprintf(stderr, "list: Result code = %d (%s)\n", statuscode,
			    (statuscode < 0) ? smcp_status_to_cstr(
				statuscode) : coap_code_to_cstr(statuscode));

	// TODO: This implementation currently only works when the content only includes entire records.
	// Chunked encoding could cause single records to be distributed across multiple transactions.
	// This case must eventually be handled.

	if(content && content_length) {
		char contentBuffer[500];
		coap_content_type_t content_type = 0;
		const coap_header_item_t *next = NULL;
		{
			const coap_header_item_t *iter =
			    smcp_daemon_get_current_request_headers(self);
			const coap_header_item_t *end = iter +
			    smcp_daemon_get_current_request_header_count(self);
			for(; iter != end; ++iter) {
				if(iter->key == COAP_HEADER_CONTENT_TYPE)
					content_type = (unsigned char)iter->value[0];
				else if(iter->key == COAP_HEADER_NEXT)
					next = iter;
			}
		}

		if(content_type != COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT) {
			fprintf(stderr, " *** Not a directory\n");
		} else {
			char *iter = content;
			char *end = content + content_length;
			int col_width = 16;

			while(iter < end) {
				if(*iter == '<') {
					char* uri = 0;
					char* name = 0;
					int type = COAP_CONTENT_TYPE_UNKNOWN;
					int uri_len = 0;

					iter++;

					uri = strsep(&iter, ">");
					uri_len = iter - uri - 1;

					// Skip past any arguments
					if(*iter == ';') {
						while((iter < end)) {
							char* key;
							char* value;
							char endchar;

							iter++;
							key = strsep(&iter, "=");
							if(*iter == '"') {
								iter++;
								value = strsep(&iter, "\"");
								endchar = *iter;
							} else {
								value = iter;
								while((iter < end) && (*iter != ',') &&
								        (*iter != ';')) {
									iter++;
								}
								endchar = *iter;
								*iter++ = 0;
							}
							if(0 == strcmp(key, "n"))
								name = value;
							else if(0 == strcmp(key, "ct"))
								type = strtol(value, NULL, 0);
							//printf("%s = %s\n",key,value);
							if(endchar == ',' || (iter >= end))
								break;
						}
					}

					url_shorten_reference((const char*)context, uri);

					printf("%s ", uri);
					if(uri_len < col_width) {
						if(name || (type != COAP_CONTENT_TYPE_UNKNOWN)) {
							uri_len = col_width - uri_len;
							while(uri_len--) {
								printf(" ");
							}
							printf("\t");
						}
					} else {
						printf("\t");
						col_width = uri_len;
					}
					if(name) printf("\"%s\"", name);
					if(type != COAP_CONTENT_TYPE_UNKNOWN) printf(" (%s)",
							coap_content_type_to_cstr(type));
					printf("\n");
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

			if(next &&
			    send_list_request(self, (const char*)context, next->value,
					next->value_len))
				return;
		}
	}

	if(gRet == ERRORCODE_INPROGRESS)
		gRet = 0;
}

bool
resend_list_request(smcp_daemon_t smcp) {
	bool ret = false;
	smcp_status_t status = 0;
	coap_header_item_t headers[SMCP_MAX_HEADERS + 1] = {  };

	if(next_len != ((size_t)(-1))) {
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
		COAP_METHOD_GET,
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
		next_len = ((size_t)(-1));
	}

	ret = resend_list_request(smcp);

bail:
	return ret;
}

int
tool_cmd_list(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	gRet = ERRORCODE_INPROGRESS;

	previous_sigint_handler = signal(SIGINT, &signal_interrupt);

	char url[1000];

	next_len = ((size_t)(-1));

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

	require(send_list_request(smcp, url, NULL, 0), bail);

	while(gRet == ERRORCODE_INPROGRESS)
		smcp_daemon_process(smcp, -1);

bail:
	smcp_invalidate_response_handler(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
