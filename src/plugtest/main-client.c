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
	const char* url;
	bool finished,failed;

	coap_code_t outbound_code;
	coap_transaction_type_t outbound_tt;
	coap_code_t expected_code;

	coap_code_t inbound_code;
	size_t inbound_content_len;

	enum {
		EXT_NONE,
		EXT_BLOCK_01,
	} extra;
} test_data_s;

smcp_status_t
resend_test_request(void* context) {
	test_data_s const * test_data = context;
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(),test_data->outbound_code, test_data->outbound_tt);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(test_data->url, 0);
	require_noerr(status,bail);

	if(test_data->extra==EXT_BLOCK_01) {
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
	}

bail:
	return status;
}

static smcp_status_t
response_test_handler(int statuscode, void* context) {
	test_data_s * const test_data = context;
	smcp_status_t status = 0;
	if(statuscode>0) {
		test_data->inbound_content_len+=smcp_inbound_get_content_len();
		test_data->inbound_code = statuscode;
	} else {
		test_data->finished = true;
	}
	return status;
}

bool
test_simple(smcp_t smcp, const char* url, const char* rel, coap_code_t outbound_code,coap_transaction_type_t outbound_tt,coap_code_t expected_code, int extra)
{
	bool ret = false;
	smcp_transaction_t transaction = NULL;
	test_data_s test_data = {
		.outbound_code = outbound_code,
		.outbound_tt = outbound_tt,
		.expected_code = expected_code,
		.extra = extra,
	};
	asprintf(&test_data.url, "%s%s",url,rel);

	transaction = smcp_transaction_init(
		transaction,
		SMCP_TRANSACTION_ALWAYS_INVALIDATE, // Flags
		(void*)&resend_test_request,
		(void*)&response_test_handler,
		(void*)&test_data
	);

	smcp_transaction_begin(
		smcp,
		transaction,
		30*MSEC_PER_SEC
	);

	while(!test_data.finished)
		smcp_process(smcp,30*MSEC_PER_SEC);

	free((void*)test_data.url);

	require(test_data.inbound_code == test_data.expected_code,bail);

	ret = true;

bail:
	return ret;
}

bool
test_TD_COAP_CORE_01(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_02(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_POST,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_201_CREATED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_03(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_PUT,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_204_CHANGED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_04(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_DELETE,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_202_DELETED,
		EXT_NONE
	);
}





bool
test_TD_COAP_CORE_05(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_06(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_POST,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_201_CREATED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_07(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_PUT,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_204_CHANGED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_08(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"test",
		COAP_METHOD_DELETE,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_202_DELETED,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_09(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"separate",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_12(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"seg1/seg2/seg3",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}


bool
test_TD_COAP_CORE_13(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"query?first=1&second=2&third=3",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_CORE_16(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"separate",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_NONCONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_LINK_01(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		".well-known/core",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_BLOCK_02(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"large",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_NONE
	);
}

bool
test_TD_COAP_BLOCK_01(smcp_t smcp, const char* url)
{
	return test_simple(
		smcp,
		url,
		"large",
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		COAP_RESULT_205_CONTENT,
		EXT_BLOCK_01
	);
}



int
main(int argc, char * argv[]) {
	smcp_t smcp = smcp_create(61616);
	const char* url = "coap://localhost/";
	int errorcount = 0;
	int round = 0;

//	url = "coap://contiki.local./";
//	url = "coap://coap.me/";

	if(argc>1) url = argv[1];
	if(!smcp) {
		fprintf(stderr,"Unable to allocate smcp instance\n");
		exit(-1);
	}

	printf("Client using port %d.\n", smcp_get_port(smcp));

#define do_test(x)	do { printf("%s: Testing...\n",#x); if(test_ ## x(smcp,url)) { printf("%s: result = OK\n",#x); } else { printf("%s: result = FAIL\n",#x); errorcount++; } } while(0)

	for(round = 0;round<10 && errorcount==0;round++) {
		printf("Round %d...\n",round+1);
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
	}

	return errorcount;
}
