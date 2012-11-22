/*
 *  cmd_list.c
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
#include "cmd_list.h"
#include <string.h>
#include <smcp/url-helpers.h>
#include <math.h>
#include <signal.h>
#include "smcpctl.h"
#include <unistd.h>

static arg_list_item_t option_list[] = {
	{ 'h', "help",		 NULL,	 "Print Help"				 },
	{ 'i', "include",	 NULL,	 "include headers in output" },
	{ 0,   "slice-size", "size", "writeme"					 },
	{ 0,   "follow",	 NULL,	 "writeme"					 },
	{ 0,   "no-follow",	 NULL,	 "writeme"					 },
	{ 0,   "filename-only",	NULL, "Only print out the resulting filenames." },
	{ 't',   "timeout",	"cms", "Timeout value, in milliseconds" },
	{ 0 }
};

static coap_transaction_id_t tid;
static uint16_t size_request;

static int gRet;
static sig_t previous_sigint_handler;
static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

bool send_list_request(
	smcp_t smcp, const char* url, const char* next, size_t nextlen);

static int retries = 0;
static const char* url_data;
static char next_data[256];
static size_t next_len = ((size_t)(-1));
static bool list_show_headers = false;
static int redirect_count = 0;
static const char* original_url;
static int timeout_cms;
static bool list_filename_only;

static char redirect_url[SMCP_MAX_URI_LENGTH + 1];

static void
list_response_handler(
	int statuscode, void* context
) {
	smcp_t const self = smcp_get_current_instance();
	char* content = (char*)smcp_inbound_get_content_ptr();
	size_t content_length = smcp_inbound_get_content_len();
	bool istty = isatty(fileno(stdout));

	if((statuscode >= COAP_RESULT_100) && list_show_headers) {
		if(next_len != ((size_t)(-1)))
			fprintf(stdout, "\n");
		coap_dump_header(
			stdout,
			NULL,
			smcp_inbound_get_packet(),
			0
		);
	}

	if(((statuscode < COAP_RESULT_200) ||
	            (statuscode >= COAP_RESULT_400)) &&
	        (statuscode != SMCP_STATUS_TRANSACTION_INVALIDATED) &&
	        (statuscode != HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT))
	) {
		if(!list_filename_only) {
			fprintf(stderr, "list: Result code = %d (%s)\n", statuscode,
					(statuscode < 0) ? smcp_status_to_cstr(
					statuscode) : coap_code_to_cstr(statuscode));
		}
		if(statuscode<0)
			gRet = statuscode;
		else if(content_length && !list_filename_only) {
			fprintf(stdout,"%s",content);
			if((content[content_length - 1] != '\n'))
				fprintf(stdout,"\n");
		}
		goto bail;
	}

	// TODO: This implementation currently only works when the content only includes entire records.
	// Chunked encoding could cause single records to be distributed across multiple transactions.
	// This case must eventually be handled.

	// TODO: When redirected, we should adjust the URI's to be relative to the original url!

	if(content && content_length) {
		coap_content_type_t content_type = smcp_inbound_get_content_type();
		coap_option_key_t key;
		const uint8_t* value;
		size_t value_len;
		const uint8_t* next_value = NULL;
		size_t next_len;
		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_HEADER_INVALID) {

//			if(key == COAP_HEADER_CONTINUATION_REQUEST) {
//				next_value = value;
//				next_len = value_len;
//			}
			if(key == COAP_HEADER_BLOCK2 && value_len) {
				static uint8_t tmp[5];
				next_len = value_len<3?value_len:3;
				memcpy(tmp,value,next_len);
				if(tmp[next_len-1]&(1<<3)) {
					uint32_t block = 0;
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
				}
			}
		}

		if(content_type != COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT) {
			if(!list_filename_only) {
				if(statuscode >= 300) {
					fwrite(content, content_length, 1, stdout);
					if((content[content_length - 1] != '\n'))
						fprintf(stdout,"\n");
				} else {
					fprintf(stderr, " *** Not a directory\n");
				}
			}
		} else {
			char *iter = content;
			char *end = content + content_length;
			int col_width = 16;

			while(iter && (iter < end)) {
				if(*iter == '<') {
					char* uri = 0;
					char* name = 0;
					char* desc = 0;
					char* v = 0;
					char* sh_url = 0;
					int type = COAP_CONTENT_TYPE_UNKNOWN;
					int uri_len = 0;

					iter++;

					uri = strsep(&iter, ">");
					//uri_len = iter - uri - 1;

					// Skip past any arguments
					if(iter && *iter == ';') {
						while(iter && (iter < end)) {
							char* key;
							char* value;
							char endchar;

							iter++;
							key = strsep(&iter, "=");
							if(!iter)
								break;
							if(*iter == '"') {
								iter++;
								value = strsep(&iter, "\"");
								if(!iter)
									break;
								endchar = *iter++;
							} else {
								value = iter;
								while((iter < end) && (*iter != ',') &&
								        (*iter != ';')) {
									iter++;
								}
								endchar = *iter;
								*iter++ = 0;
							}
							{	// Convert all line feeds into " | ".
								char* value_iter = value;
								for(;*value_iter;value_iter++) {
									if(0==strncmp(value_iter,"%0A",3)) {
										if(value_iter[3]) {
											value_iter[0]=' ';
											value_iter[1]='|';
											value_iter[2]=' ';
										} else {
											value_iter[0]=0;
											value_iter[1]=0;
											value_iter[2]=0;
										}
									}
								}
							}
							url_decode_cstr_inplace(value);
							if(0 == strcmp(key, "n"))
								name = value;
							else if(!name && 0 == strcmp(key, "rt"))
								name = value;
							else if(0 == strcmp(key, "title"))
								desc = value;
							else if(0 == strcmp(key, "v"))
								v = value;
							else if(0 == strcmp(key, "ct"))
								type = strtol(value, NULL, 0);
							else if(0 == strcmp(key, "sh"))
								sh_url = value;
							//printf("%s = %s\n",key,value);
							if(endchar == ',' || (iter >= end))
								break;
							if(endchar == ';')
								iter--;
						}
					}

					char adjusted_uri[SMCP_MAX_URI_LENGTH + 1];

					if(redirect_url[0] && !url_is_absolute(uri)) {
						strcpy(adjusted_uri, redirect_url);
						url_change(adjusted_uri, uri);
						uri = adjusted_uri;
					}
					url_shorten_reference((const char*)original_url, uri);


					if(istty && !list_filename_only && type==COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT)
						uri_len = fprintf(stdout,
							"\033[1;34;40m"
							"%s"
							"\033[0;37;40m"
							,
							uri
						) - 1;
					else
						uri_len = fprintf(stdout,"%s", uri) - 1;
					if(type==COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT)
						fprintf(stdout,"/");
					if(!list_filename_only) {
						if(v)
							fprintf(stdout,"=%s",v);
						fprintf(stdout," ");
						if(uri_len < col_width) {
							if(name || (type != COAP_CONTENT_TYPE_UNKNOWN)) {
								uri_len = col_width - uri_len;
								while(uri_len--) {
									fprintf(stdout," ");
								}
								fprintf(stdout,"\t");
							}
						} else {
							fprintf(stdout,"\t");
							col_width = uri_len;
						}

						if(name && (0 != strcmp(name, uri))) fprintf(stdout,"\"%s\" ",
								name);
						if(sh_url && (0 != strcmp(sh_url, uri))) fprintf(stdout,
								"<%s> ",
								sh_url);
						if(type != COAP_CONTENT_TYPE_UNKNOWN) fprintf(stdout,"[%s] ",
								coap_content_type_to_cstr(type));
						if(desc) fprintf(stdout,"(%s) ",desc);
					}
					fprintf(stdout,"\n");
				} else {
					iter++;
				}
			}

			// Kinda naughty.
			if(content[content_length - 1] == '\n')
				content[--content_length] = 0;
			else
				content[content_length] = 0;

			if(next_value &&
			    send_list_request(self, (const char*)context, (const char*)next_value,
					next_len))
				return;
		}
	}
bail:
	if(gRet == ERRORCODE_INPROGRESS)
		gRet = 0;
}

static smcp_status_t
resend_list_request(void* context) {
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(),COAP_METHOD_GET, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(url_data, 0);
	require_noerr(status,bail);

	char expected_content_type = COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;
	status = smcp_outbound_add_option(COAP_HEADER_ACCEPT,&expected_content_type,1);

	if(next_len != ((size_t)(-1))) {
		status = smcp_outbound_add_option(
			COAP_HEADER_BLOCK2,
			next_data,
			next_len
		);
		require_noerr(status,bail);
	}

//	if(size_request) {
//		smcp_outbound_add_option(
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
send_list_request(
	smcp_t smcp, const char* url, const char* next, size_t nextlen
) {
	bool ret = false;
	smcp_status_t status = 0;

	tid = smcp_get_next_tid(smcp,NULL);
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
		timeout_cms,	// Retry for thirty seconds.
		0, // Flags
		(void*)&resend_list_request,
		(void*)&list_response_handler,
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
tool_cmd_list(
	smcp_t smcp, int argc, char* argv[]
) {
	int i;
	char url[1000];

	gRet = ERRORCODE_INPROGRESS;
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	next_len = ((size_t)(-1));
	url[0] = 0;
	list_show_headers = false;
	redirect_count = 10;
	redirect_url[0] = 0;
	size_request = 0;

	timeout_cms = 30*1000;
	list_filename_only = false;

	BEGIN_LONG_ARGUMENTS(gRet)
	HANDLE_LONG_ARGUMENT("include") list_show_headers = true;
	HANDLE_LONG_ARGUMENT("no-follow") redirect_count = 0;
	HANDLE_LONG_ARGUMENT("follow") redirect_count = 10;
	HANDLE_LONG_ARGUMENT("slice-size") size_request =
	    htons(strtol(argv[++i], NULL, 0));
	HANDLE_LONG_ARGUMENT("timeout") timeout_cms = strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("filename-only") list_filename_only = true;

	HANDLE_LONG_ARGUMENT("help") {
		print_arg_list_help(option_list, argv[0], "[args] <uri>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(gRet)
	HANDLE_SHORT_ARGUMENT('i') list_show_headers = true;
	HANDLE_SHORT_ARGUMENT('f') redirect_count = 10;
	HANDLE_SHORT_ARGUMENT('t') timeout_cms = strtol(argv[++i], NULL, 0);

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

	original_url = url;

	require(send_list_request(smcp, url, NULL, 0), bail);

	while(gRet == ERRORCODE_INPROGRESS)
		smcp_process(smcp, 50);

bail:
	smcp_invalidate_transaction(smcp, tid);
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
