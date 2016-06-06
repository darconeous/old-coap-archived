/*!	@file smcp-async.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Asynchronous Response Support
**
**	Copyright (C) 2015 Robert Quattlebaum
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

//#define ASSERT_MACROS_USE_VANILLA_PRINTF 1
//#define VERBOSE_DEBUG 1
//#define DEBUG 1

#include "assert-macros.h"
#include "smcp.h"
#include "smcp-internal.h"
#include "smcp-logging.h"

smcp_status_t
smcp_outbound_begin_async_response(coap_code_t code, struct smcp_async_response_s* x) {
	smcp_status_t ret = 0;
	smcp_t const self = smcp_get_current_instance();

	assert(NULL != x);

	self->inbound.packet = &x->request.header;
	self->inbound.packet_len = x->request_len;
	self->inbound.content_ptr = (char*)x->request.header.token + x->request.header.token_len;
	self->inbound.last_option_key = 0;
	self->inbound.this_option = x->request.header.token;
	self->inbound.is_fake = true;
	smcp_plat_set_remote_sockaddr(&x->sockaddr_remote);
	smcp_plat_set_local_sockaddr(&x->sockaddr_local);

	self->is_processing_message = true;
	self->did_respond = false;

	ret = smcp_outbound_begin_response(code);
	require_noerr(ret, bail);

	self->outbound.packet->msg_id = self->current_transaction->msg_id;

	self->outbound.packet->tt = x->request.header.tt;

	ret = smcp_outbound_set_token(x->request.header.token, x->request.header.token_len);
	require_noerr(ret, bail);

	assert(coap_verify_packet((const char*)x->request.bytes, x->request_len));
bail:
	return ret;
}

smcp_status_t
smcp_start_async_response(struct smcp_async_response_s* x, int flags) {
	smcp_status_t ret = 0;
	smcp_t const self = smcp_get_current_instance();

	require_action_string(x!=NULL,bail,ret=SMCP_STATUS_INVALID_ARGUMENT,"NULL async_response arg");

	require_action_string(
		smcp_inbound_get_packet_length()-smcp_inbound_get_content_len()<=sizeof(x->request),
		bail,
		(smcp_outbound_quick_response(COAP_RESULT_413_REQUEST_ENTITY_TOO_LARGE,NULL),ret=SMCP_STATUS_FAILURE),
		"Request too big for async response"
	);

	x->request_len = smcp_inbound_get_packet_length()-smcp_inbound_get_content_len();
	memcpy(x->request.bytes,smcp_inbound_get_packet(),x->request_len);

	assert(coap_verify_packet((const char*)x->request.bytes, x->request_len));

	x->sockaddr_remote = *smcp_plat_get_remote_sockaddr();
	x->sockaddr_local = *smcp_plat_get_local_sockaddr();

	if(	!(flags & SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK)
		&& self->inbound.packet->tt==COAP_TRANS_TYPE_CONFIRMABLE
	) {
		// Fake inbound packets are created to tickle
		// content out of nodes by the pairing system.
		// Since we are asynchronous, this clearly isn't
		// going to work. Support for this will have to
		// come in the future.
		require_action(!self->inbound.is_fake,bail,ret = SMCP_STATUS_NOT_IMPLEMENTED);

		ret = smcp_outbound_begin_response(COAP_CODE_EMPTY);
		require_noerr(ret, bail);

		ret = smcp_outbound_send();
		require_noerr(ret, bail);
	}

	if(self->inbound.is_dupe) {
		ret = SMCP_STATUS_DUPE;
		goto bail;
	}

bail:
	return ret;
}

smcp_status_t
smcp_finish_async_response(struct smcp_async_response_s* x) {
	x->request_len = 0;
	return SMCP_STATUS_OK;
}

bool
smcp_inbound_is_related_to_async_response(struct smcp_async_response_s* x)
{
	const smcp_sockaddr_t *curr_remote = smcp_plat_get_remote_sockaddr();

	if (x->sockaddr_remote.smcp_port != curr_remote->smcp_port) {
		return false;
	}

	if (x->request.header.token_len != smcp_inbound_get_packet()->token_len) {
		return false;
	}

	if (x->request.header.code != smcp_inbound_get_packet()->code) {
		return false;
	}

	if (0!=memcmp(x->request.header.token, smcp_inbound_get_packet()->token,smcp_inbound_get_packet()->token_len)) {
		return false;
	}

	if (0 == memcmp(
		&x->sockaddr_remote.smcp_addr,
		&curr_remote->smcp_addr,
		sizeof(smcp_addr_t)
	)) {
		return false;
	}

	return true;
}
