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

#include <smcp/assert-macros.h>

#include <smcp/smcp.h>

bool gFinished;

typedef struct {
	char url[256];
	bool finished,failed;

	coap_code_t outbound_code;
	coap_transaction_type_t outbound_tt;
	coap_code_t expected_code;

	coap_code_t inbound_code;
	smcp_status_t error;
	coap_size_t inbound_content_len;
	int inbound_packets;
	int inbound_dupe_packets;
	int outbound_attempts;

	uint32_t block1_option;
	uint32_t block2_option;

	bool has_block1_option;
	bool has_block2_option;

	struct timeval start_time;
	struct timeval stop_time;

	enum {
		EXT_NONE,
		EXT_BLOCK_01,
		EXT_BLOCK_02,
	} extra;
} test_data_s;

void
dump_test_results(const test_data_s *test_data) {
	printf("\tURL: %s\n",test_data->url);
	if(test_data->inbound_code)
		printf("\tinbound_code: %s (%d)\n", coap_code_to_cstr(test_data->inbound_code),test_data->inbound_code);

	if(test_data->error || test_data->failed) {
		if(test_data->error)
			printf("\terror: %s (%d)\n", smcp_status_to_cstr(test_data->error), test_data->error);
	}
	{
		cms_t duration = period_between_timevals_in_cms(&test_data->stop_time,&test_data->start_time);
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
	printf("\tinbound_content_len: %d\n", (int)test_data->inbound_content_len);
	if(test_data->inbound_packets!=1)
		printf("\tinbound_packets: %d\n", test_data->inbound_packets);
	if(test_data->inbound_dupe_packets!=0)
		printf("\tinbound_dupes: %d\n", test_data->inbound_dupe_packets);
	if(test_data->outbound_attempts!=1)
		printf("\toutbound_attempts: %d\n", test_data->outbound_attempts);
}

smcp_status_t
resend_test_request(void* context) {
	test_data_s* test_data = context;
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(),test_data->outbound_code, test_data->outbound_tt);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(test_data->url, 0);
	require_noerr(status,bail);

	if(test_data->extra==EXT_BLOCK_01) {
		struct coap_block_info_s block1_info;
		uint32_t resource_length = 2000;
		if(!test_data->has_block1_option) {
			test_data->block1_option = 2|(1<<3);	// 64 byte block size;
		}

		smcp_outbound_add_option_uint(COAP_OPTION_BLOCK1, test_data->block1_option);

		coap_decode_block(&block1_info, test_data->block1_option);

		if(block1_info.block_m) {
			coap_size_t max_len = 0;
			uint32_t i;
			uint32_t block_stop;
			char* content = NULL;
			content = smcp_outbound_get_content_ptr(&max_len);
			if(!content) {
				status = SMCP_STATUS_FAILURE;
				goto bail;
			}

			block_stop = block1_info.block_offset+block1_info.block_size;

			for(i=block1_info.block_offset;i<block_stop;i++) {
				if(!((i+1)%64))
					content[i-block1_info.block_offset] = '\n';
				else
					content[i-block1_info.block_offset] = '0'+(i%10);
			}

			status = smcp_outbound_set_content_len(MIN(block_stop-block1_info.block_offset,resource_length-block1_info.block_offset));
		}
	}

	if(test_data->extra==EXT_BLOCK_02) {
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
	smcp_status_t status = 0;
	if(!test_data->finished) {
		if(statuscode<0) {
			test_data->finished = true;
			if(statuscode != SMCP_STATUS_TRANSACTION_INVALIDATED)
				test_data->error = statuscode;
		} else {
			const uint8_t* value;
			coap_size_t value_len;
			coap_option_key_t key;
			while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
				if(key == COAP_OPTION_BLOCK1) {
					uint8_t i;
					test_data->block1_option = 0;
					test_data->has_block1_option = 1;
					for(i = 0; i < value_len; i++)
						test_data->block1_option = (test_data->block1_option << 8) + value[i];
				}
				if(key == COAP_OPTION_BLOCK2) {
					uint8_t i;
					test_data->block2_option = 0;
					test_data->has_block2_option = 1;
					for(i = 0; i < value_len; i++)
						test_data->block2_option = (test_data->block2_option << 8) + value[i];
				}
			}

			test_data->inbound_content_len+=smcp_inbound_get_content_len();
			test_data->inbound_code = statuscode;
			if(smcp_inbound_is_dupe())
				test_data->inbound_dupe_packets++;
			else
				test_data->inbound_packets++;
		}
	}
	return status;
}

bool
test_simple(smcp_t smcp, test_data_s *test_data, const char* url, const char* rel, coap_code_t outbound_code,coap_transaction_type_t outbound_tt,coap_code_t expected_code, int extra)
{
	smcp_transaction_t transaction = NULL;
	memset(test_data,0,sizeof(*test_data));
	test_data->outbound_code = outbound_code;
	test_data->outbound_tt = outbound_tt;
	test_data->expected_code = expected_code;
	test_data->extra = extra;
	if(strlen(url) && (url[strlen(url)-1] == '/'))
		snprintf(test_data->url,sizeof(test_data->url), "%s%s",url,rel);
	else
		snprintf(test_data->url,sizeof(test_data->url), "%s/%s",url,rel);

	gettimeofday(&test_data->start_time, NULL);
	transaction = smcp_transaction_init(
		transaction,
		SMCP_TRANSACTION_ALWAYS_INVALIDATE, // Flags
		(void*)&resend_test_request,
		(void*)&response_test_handler,
		(void*)test_data
	);

	smcp_transaction_begin(
		smcp,
		transaction,
		30*MSEC_PER_SEC
	);

	while(!test_data->finished)
		smcp_process(smcp,30*MSEC_PER_SEC);

	gettimeofday(&test_data->stop_time, NULL);

	test_data->failed = true;
	require(test_data->inbound_code == test_data->expected_code,bail);

	test_data->failed = false;

bail:
	return !test_data->failed;
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
test_TD_COAP_CORE_12(smcp_t smcp, const char* url, test_data_s *test_data)
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
test_TD_COAP_CORE_13(smcp_t smcp, const char* url, test_data_s *test_data)
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
test_TD_COAP_CORE_16(smcp_t smcp, const char* url, test_data_s *test_data)
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



int
main(int argc, char * argv[]) {
	smcp_t smcp = smcp_create(61616);
	const char* url = "coap://localhost/";
	int errorcount = 0;
	int round = 0;
	test_data_s test_data;

//	url = "coap://contiki.local./";
//	url = "coap://coap.me/";
//	url = "coap://vs0.inf.ethz.ch/";

	if(argc>1) url = argv[1];
	if(!smcp) {
		fprintf(stderr,"Unable to allocate smcp instance\n");
		exit(-1);
	}

	printf("Client using port %d.\n", smcp_get_port(smcp));

#define do_test(x)	do { printf("%s: Testing...\n",#x); if(test_ ## x(smcp,url,&test_data)) { dump_test_results(&test_data); printf("\tresult = OK\n"); } else { dump_test_results(&test_data); printf("\tresult = FAIL\n"); errorcount++; } } while(0)

	for(round = 0;round<10 && errorcount==0;round++) {
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

		do_test(TD_COAP_CORE_12);
		do_test(TD_COAP_CORE_13);
		do_test(TD_COAP_CORE_16);

		do_test(TD_COAP_LINK_01);

		do_test(TD_COAP_BLOCK_01);
		do_test(TD_COAP_BLOCK_02);
		//do_test(TD_COAP_BLOCK_03);
	}

	return errorcount;
}
