/*	@file main-client.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Plugtest Client Entrypoint
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "smcp/assert-macros.h"

#include <smcp/smcp.h>

bool gFinished;

typedef struct {
	char url[256];
	bool finished,failed;

	coap_code_t outbound_code;
	coap_transaction_type_t outbound_tt;
	coap_code_t expected_code;

	coap_content_type_t outbound_content_type;

	coap_code_t inbound_code;
	smcp_status_t error;
	coap_size_t inbound_content_len;
	int inbound_packets;
	int inbound_dupe_packets;
	int outbound_attempts;

	uint16_t msg_id;
	uint32_t block1_option;
	uint32_t block2_option;

	bool has_block1_option;
	bool has_block2_option;

	smcp_timestamp_t start_time;
	smcp_timestamp_t stop_time;

	enum {
		EXT_NONE      = 0,
		EXT_BLOCK_01  = 1,
		EXT_BLOCK_02  = 2,
		EXT_OBS_01    = 4,
	} extra;

	smcp_transaction_t transaction;
	char response[1024*20];
} test_data_s;

void
dump_test_results(const test_data_s *test_data) {
	printf("\tURL: %s\n",test_data->url);
	if(test_data->inbound_code)
		printf("\tinbound_code: %s (%d)\n", coap_code_to_cstr(test_data->inbound_code), COAP_TO_HTTP_CODE(test_data->inbound_code));

	if(test_data->error || test_data->failed) {
		if(test_data->error)
			printf("\terror: %s (%d)\n", smcp_status_to_cstr(test_data->error), test_data->error);
	}
	{
		smcp_cms_t duration = smcp_plat_timestamp_diff(test_data->stop_time,test_data->start_time);
		//printf("\tstart-time: %d\n", (int)test_data->start_time);
		//printf("\tstop-time: %dms\n", (int)test_data->stop_time);
		printf("\tduration: %dms\n", (int)duration);

	}
	if(test_data->has_block1_option) {
		struct coap_block_info_s block_info;
		coap_decode_block(&block_info, test_data->block1_option);
		printf("\tblock1: %d/%d/%d\n", block_info.block_offset,block_info.block_m,block_info.block_size);
	}
	if(test_data->has_block2_option) {
		struct coap_block_info_s block_info;
		coap_decode_block(&block_info, test_data->block2_option);
		printf("\tblock2: %d/%d/%d\n", block_info.block_offset,block_info.block_m,block_info.block_size);
	}
	printf("\tlast_msg_id: 0x%04X\n", (int)test_data->msg_id);
	printf("\tinbound_content_len: %d\n", (int)test_data->inbound_content_len);
	if(test_data->inbound_packets!=1) {
		printf("\tinbound_packets: %d\n", test_data->inbound_packets);
	}
	if(test_data->inbound_dupe_packets!=0) {
		printf("\tinbound_dupes: %d\n", test_data->inbound_dupe_packets);
	}
	if(test_data->outbound_attempts!=1) {
		printf("\toutbound_attempts: %d\n", test_data->outbound_attempts);
	}
	if(test_data->response[0]!=0) {
		printf("\tresponse: \"%s\"\n", test_data->response);
	}
}

smcp_status_t
resend_test_request(void* context) {
	test_data_s* test_data = context;
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(),test_data->outbound_code, test_data->outbound_tt);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(test_data->url, 0);
	require_noerr(status,bail);

	if (test_data->outbound_content_type != COAP_CONTENT_TYPE_UNKNOWN) {
		status = smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, test_data->outbound_content_type);
		require_noerr(status,bail);
	}

	if (test_data->extra & EXT_BLOCK_01) {
		struct coap_block_info_s block1_info;
		uint32_t resource_length = 200;
		uint32_t block_stop;

		coap_decode_block(&block1_info, test_data->block1_option + (1<<4));

		block_stop = block1_info.block_offset+block1_info.block_size;

		if (block1_info.block_offset < resource_length) {
			if (block_stop >= resource_length) {
				test_data->block1_option &= ~(1<<3);
			} else {
				test_data->block1_option |= (1<<3);
			}

			if (test_data->has_block1_option) {
				test_data->block1_option += (1<<4);
			}

			smcp_outbound_add_option_uint(COAP_OPTION_BLOCK1, test_data->block1_option);

			if (block1_info.block_m) {
				coap_size_t max_len = 0;
				uint32_t i;
				uint32_t block_stop;
				char* content = NULL;
				content = smcp_outbound_get_content_ptr(&max_len);

				if (!content) {
					status = SMCP_STATUS_FAILURE;
					goto bail;
				}

				block_stop = block1_info.block_offset+block1_info.block_size;

				for (i = block1_info.block_offset; i < block_stop; i++) {
					if (!((i + 1) % 64)) {
						content[i-block1_info.block_offset] = '\n';
					} else {
						content[i-block1_info.block_offset] = '0'+(i%10);
					}
				}

				status = smcp_outbound_set_content_len(MIN((coap_code_t)(block_stop-block1_info.block_offset),(coap_code_t)(resource_length-block1_info.block_offset)));
				require_noerr(status,bail);
			}
		}
	}

	if(test_data->extra & EXT_BLOCK_02) {
		smcp_outbound_add_option_uint(COAP_OPTION_BLOCK2, 1);	// 32 byte block size.
	}

	status = smcp_outbound_send();

	if(status) {
		check_noerr(status);
		fprintf(stderr,
			"smcp_outbound_send() returned error %d(%s).\n",
			status,
			smcp_status_to_cstr(status));
		goto bail;
	} else {
		test_data->outbound_attempts++;
	}

bail:
	return status;
}

static smcp_status_t
response_test_handler(int statuscode, void* context) {
	test_data_s * const test_data = context;
	smcp_t interface = smcp_get_current_instance();
	bool has_observe_option = false;
	smcp_status_t status = 0;
	if(!test_data->finished) {
		if (statuscode < 0) {
			test_data->finished = true;
			if (statuscode != SMCP_STATUS_TRANSACTION_INVALIDATED) {
				test_data->error = statuscode;
			}
		} else {
			const uint8_t* value;
			coap_size_t value_len;
			coap_option_key_t key;
			test_data->msg_id = smcp_inbound_get_packet()->msg_id;

			if (smcp_inbound_is_dupe()) {
				test_data->inbound_dupe_packets++;
			} else {
				test_data->inbound_packets++;
			}

			while ((key=smcp_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
				if (key == COAP_OPTION_BLOCK1) {
					test_data->block1_option = 0;
					test_data->has_block1_option = 1;
					test_data->block1_option = coap_decode_uint32(value,(uint8_t)value_len);
					if ( statuscode == COAP_RESULT_231_CONTINUE) {
						smcp_transaction_new_msg_id(interface, test_data->transaction, smcp_get_next_msg_id(interface));
						smcp_transaction_tickle(interface, test_data->transaction);
					}
				}
				if (key == COAP_OPTION_BLOCK2) {
					test_data->block2_option = 0;
					test_data->has_block2_option = 1;
					test_data->block2_option = coap_decode_uint32(value,(uint8_t)value_len);
					if (!(test_data->block2_option & (1<<3))) {
						test_data->finished = true;
					}
				}
				if (key == COAP_OPTION_OBSERVE) {
					if (test_data->inbound_packets > 2) {
						test_data->finished = true;
					}
					has_observe_option = true;
					printf("\tobs-response: \"%s\"\n", smcp_inbound_get_content_ptr());
				}
			}

			if ( !has_observe_option
			  && !test_data->has_block2_option
			  && statuscode != COAP_RESULT_231_CONTINUE
			) {
				test_data->finished = true;
			}

			test_data->inbound_content_len += smcp_inbound_get_content_len();
			test_data->inbound_code = (coap_code_t)statuscode;

			if (test_data->has_block2_option) {
				strncat(test_data->response, smcp_inbound_get_content_ptr(), smcp_inbound_get_content_len());
			} else {
				strncpy(test_data->response, smcp_inbound_get_content_ptr(), smcp_inbound_get_content_len());
			}
		}
	}
	return status;
}

bool
test_simple(smcp_t smcp, test_data_s *test_data, const char* url, const char* rel, coap_code_t outbound_code,coap_transaction_type_t outbound_tt,coap_code_t expected_code, int extra)
{
	smcp_cms_t timeout = 15*MSEC_PER_SEC;
	smcp_status_t status;
#if SMCP_AVOID_MALLOC && !SMCP_TRANSACTION_POOL_SIZE
	struct smcp_transaction_s transaction_backing;
	smcp_transaction_t transaction = &transaction_backing;
#else
	smcp_transaction_t transaction = NULL;
#endif
	int t_flags = SMCP_TRANSACTION_ALWAYS_INVALIDATE | SMCP_TRANSACTION_NO_AUTO_END;
	smcp_timestamp_t expiry = smcp_plat_cms_to_timestamp(timeout+MSEC_PER_SEC);
	memset(test_data,0,sizeof(*test_data));
	test_data->outbound_code = outbound_code;
	test_data->outbound_tt = outbound_tt;
	test_data->expected_code = expected_code;
	test_data->extra = extra;
	test_data->outbound_content_type = COAP_CONTENT_TYPE_UNKNOWN;
	if (extra & EXT_BLOCK_01) {
		test_data->outbound_content_type = COAP_CONTENT_TYPE_TEXT_PLAIN;
		test_data->block1_option = (2 | (1<<3));	// 64 byte block size;
	}
	if(strlen(url) && (url[strlen(url)-1] == '/')) {
		snprintf(test_data->url,sizeof(test_data->url), "%s%s",url,rel);
	} else {
		snprintf(test_data->url,sizeof(test_data->url), "%s/%s",url,rel);
	}

	if (extra & EXT_OBS_01) {
		t_flags = SMCP_TRANSACTION_OBSERVE;
	}

	test_data->start_time = smcp_plat_cms_to_timestamp(0);
	transaction = smcp_transaction_init(
		transaction,
		t_flags,
		(void*)&resend_test_request,
		(void*)&response_test_handler,
		(void*)test_data
	);
	test_data->transaction = transaction;

	status = smcp_transaction_begin(
		smcp,
		transaction,
		timeout
	);

	require_noerr(status, bail);

	while(!test_data->finished && (smcp_plat_timestamp_to_cms(expiry)>0)) {
		status = smcp_plat_wait(smcp, smcp_plat_timestamp_to_cms(expiry));
		require((status==SMCP_STATUS_OK) || (status==SMCP_STATUS_TIMEOUT), bail);

		status = smcp_plat_process(smcp);
		require_noerr(status, bail);
	}

	test_data->stop_time = smcp_plat_cms_to_timestamp(0);

	test_data->failed = true;

	require(smcp_plat_timestamp_to_cms(expiry)>0, bail);
	require(test_data->inbound_code == test_data->expected_code,bail);
	if (expected_code == COAP_CODE_EMPTY) {
		require(test_data->error == SMCP_STATUS_RESET, bail);
	} else {
		require(test_data->error == SMCP_STATUS_OK, bail);
	}
	test_data->failed = false;

bail:
	if (test_data->error == 0) {
		test_data->error = status;
	}
	if (test_data->stop_time == 0) {
		test_data->stop_time = smcp_plat_cms_to_timestamp(0);
	}

	if (transaction) {
		smcp_transaction_end(smcp, transaction);
	}
	return (status == SMCP_STATUS_OK) && !test_data->failed;
}

bool
test_TD_COAP_CORE_01(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_02(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_POST,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_201_CREATED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_03(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_PUT,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_204_CHANGED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_04(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_DELETE,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_202_DELETED,
		EXT_NONE
	);
}





bool
test_TD_COAP_CORE_05(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_06(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_POST,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_201_CREATED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_07(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_PUT,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_204_CHANGED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_08(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"test",
		COAP_METHOD_DELETE,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_202_DELETED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_09(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"separate",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_13(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"seg1/seg2/seg3",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}


bool
test_TD_COAP_CORE_14(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"query?first=1&second=2&third=3",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_17(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"separate",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_31(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		NULL,
		COAP_CODE_EMPTY,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_CODE_EMPTY,
		EXT_NONE
	);
}


bool
test_TD_COAP_LINK_01(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		".well-known/core",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_BLOCK_02(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"large",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	) && test_data->has_block2_option;
}

bool
test_TD_COAP_BLOCK_01(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"large",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_BLOCK_02
	) && test_data->has_block2_option;
}

bool
test_TD_COAP_BLOCK_03(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"large-update",
		COAP_METHOD_PUT,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_204_CHANGED,
		EXT_BLOCK_01
	);
}

bool
test_TD_COAP_BLOCK_04(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"large-create",
		COAP_METHOD_POST,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_201_CREATED,
		EXT_BLOCK_01
	);
}

bool
test_TD_COAP_BLOCK_05(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"large-post",
		COAP_METHOD_POST,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_204_CHANGED,
		EXT_BLOCK_01
	);
}

bool
test_TD_COAP_OBS_01(smcp_t smcp, const char* url, test_data_s *test_data)
{
	return test_simple(
		smcp,
		test_data,
		url,
		"obs",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_OBS_01
	);
}


int
main(int argc, char * argv[]) {
	smcp_t smcp;
	const char* url = "coap://localhost/";
	int errorcount = 0;
	int round_count = 1;
	int round = 0;
	test_data_s test_data;

	SMCP_LIBRARY_VERSION_CHECK();

	smcp = smcp_create();

	smcp_plat_bind_to_port(smcp, SMCP_SESSION_TYPE_UDP, 0);


//	url = "coap://contiki.local./";
//	url = "coap://coap.me/";
//	url = "coap://vs0.inf.ethz.ch/";

	if (argc > 1) url = argv[1];
	if (!smcp) {
		fprintf(stderr,"Unable to allocate smcp instance\n");
		exit(-1);
	}

	if (argc > 2) {
		round_count = atoi(argv[2]);
	}

	printf("Client using port %d. Will test %d rounds.\n", smcp_plat_get_port(smcp), round_count);

#define do_test(x)	do { printf("%s: Testing...\n",#x); if(test_ ## x(smcp,url,&test_data)) { dump_test_results(&test_data); printf("\tRESULT = OK\n\n"); } else { dump_test_results(&test_data); printf("\tRESULT = FAIL ****\n\n"); errorcount++; } } while(0)

#define do_test_expect_fail(x)	do { printf("%s: Testing...\n",#x); if(test_ ## x(smcp,url,&test_data)) { dump_test_results(&test_data); printf("\tRESULT = OK (Unexpected) ****\n\n"); } else { dump_test_results(&test_data); printf("\tRESULT = FAIL (Expected)\n\n"); } } while(0)

	for(round = 0;round<round_count && errorcount==0;round++) {
		printf("\n## Round %d...\n",round+1);

		do_test(TD_COAP_CORE_01);
		do_test(TD_COAP_CORE_02);
		do_test(TD_COAP_CORE_03);
		do_test(TD_COAP_CORE_04);
		do_test(TD_COAP_CORE_05);
		do_test(TD_COAP_CORE_06);
		do_test(TD_COAP_CORE_07);
		do_test(TD_COAP_CORE_08);
		do_test(TD_COAP_CORE_09);

		do_test(TD_COAP_CORE_13);
		do_test(TD_COAP_CORE_14);
		do_test(TD_COAP_CORE_17);
		do_test(TD_COAP_CORE_31);

		do_test(TD_COAP_LINK_01);

#if SMCP_CONF_TRANS_ENABLE_BLOCK2
		do_test(TD_COAP_BLOCK_01);
		do_test(TD_COAP_BLOCK_02);

		do_test_expect_fail(TD_COAP_BLOCK_03);
		do_test_expect_fail(TD_COAP_BLOCK_04);
		do_test_expect_fail(TD_COAP_BLOCK_05);
#endif

		do_test(TD_COAP_OBS_01);
	}

	if (errorcount == 0) {
		printf("\nPASS\n");
	} else {
		printf("\nFAIL\n");
	}

	return errorcount;
}
