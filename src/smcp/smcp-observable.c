/*	@file smcp-observable.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2013 Robert Quattlebaum
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

#include "smcp-observable.h"
#include "smcp-internal.h"
#include "smcp-transaction.h"

#define INVALID_OBSERVER_INDEX		(SMCP_MAX_OBSERVERS)

#define SHOULD_CONFIRM_EVENT_FOR_OBSERVER(obs)		(!((obs)->seq&0x7))

struct smcp_observer_s {
	/**** All of this is private. Don't touch. ****/

	struct smcp_observable_s *observable;
	int8_t next;	// always +1, zero is end of list
	uint8_t key;
	uint32_t seq;
	struct smcp_async_response_s async_response;
	struct smcp_transaction_s transaction;
};

static struct smcp_observer_s observer_table[SMCP_MAX_OBSERVERS];

static int8_t
get_unused_observer_index() {
	int8_t ret = 0;
	for(;ret<SMCP_MAX_OBSERVERS;ret++)
		if(observer_table[ret].async_response.request_len==0
		&& observer_table[ret].next==0
		&& observer_table[ret].transaction.active==0
		)
			break;
	if(ret==SMCP_MAX_OBSERVERS)
		ret = -1;
	return ret;
}

static void
free_observer(struct smcp_observer_s *observer) {
	smcp_observable_t const context = observer->observable;
	int8_t i = observer - observer_table;
#if SMCP_EMBEDDED
	smcp_t const interface = smcp_get_current_instance();
#else
	if(!observer->observable)
		goto bail;
	smcp_t const interface = observer->observable->interface;
#endif

	smcp_transaction_end(interface, &observer->transaction);

	if((context->first_observer==i+1) && (context->last_observer==i+1)) {
		context->first_observer = context->last_observer = 0;
	} else if(context->first_observer==i+1) {
		context->first_observer = observer_table[i].next;
	} else {
		int8_t prev;
		for(prev = context->first_observer-1; prev>=0; i = observer_table[i].next - 1) {
			if(observer_table[prev].next == i)
				break;
		}

		observer_table[prev].next = observer_table[i].next;

		if(context->last_observer == i+1)
			context->last_observer = prev;
	}

bail:
	smcp_finish_async_response(&observer->async_response);
	return;
}

smcp_status_t
smcp_observable_update(smcp_observable_t context, uint8_t key) {
	smcp_status_t ret = SMCP_STATUS_OK;
	smcp_t const interface = smcp_get_current_instance();
	int8_t i;

#if !SMCP_EMBEDDED
	context->interface = interface;
#endif

	if(interface->inbound.is_fake || interface->inbound.is_dupe) {
		goto bail;
	}

	for(i = context->first_observer-1; i >= 0; i = observer_table[i].next - 1) {
		if(observer_table[i].key != key)
			continue;
		if(smcp_inbound_is_related_to_async_response(&observer_table[i].async_response))
			break;
	}

	if(interface->inbound.has_observe_option) {
		if(i == -1) {
			i = get_unused_observer_index();
			if(i == -1)
				goto bail;
			if(context->last_observer == 0) {
				context->first_observer = context->last_observer = i + 1;
			} else {
				observer_table[context->last_observer-1].next = i +1;
				context->last_observer = i + 1;
			}
			observer_table[i].key = key;
			observer_table[i].seq = 0;
			observer_table[i].observable = context;
		}

		smcp_start_async_response(&observer_table[i].async_response,SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK);

		ret = smcp_outbound_add_option_uint(COAP_OPTION_OBSERVE,observer_table[i].seq);
	} else if(i != -1) {
		free_observer(&observer_table[i]);
	}

bail:
	return ret;
}

static smcp_status_t
event_response_handler(int statuscode, struct smcp_observer_s* observer)
{
	if(statuscode==SMCP_STATUS_TIMEOUT) {
		if(SHOULD_CONFIRM_EVENT_FOR_OBSERVER(observer)) {
			statuscode = SMCP_STATUS_RESET;
		} else {
			statuscode = SMCP_STATUS_OK;
		}
	}

	if(statuscode!=SMCP_STATUS_TRANSACTION_INVALIDATED) {
		if(statuscode && ((statuscode < COAP_RESULT_200) || (statuscode >= COAP_RESULT_400))) {
			statuscode = SMCP_STATUS_RESET;
		}
	}

	if(statuscode==SMCP_STATUS_RESET) {
		free_observer(observer);
		return SMCP_STATUS_RESET;
	}

	return SMCP_STATUS_OK;
}

static smcp_status_t
retry_sending_event(struct smcp_observer_s* observer)
{
	smcp_status_t status;
	smcp_t const self = smcp_get_current_instance();

	status = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(status,bail);

	status = smcp_outbound_set_async_response(&observer->async_response);
	require_noerr(status,bail);

	status = smcp_outbound_add_option_uint(COAP_OPTION_OBSERVE,observer->seq);
	require_noerr(status,bail);

	self->outbound.packet->tt = SHOULD_CONFIRM_EVENT_FOR_OBSERVER(observer)?COAP_TRANS_TYPE_CONFIRMABLE:COAP_TRANS_TYPE_NONCONFIRMABLE;

	self->inbound.has_observe_option = true;
	self->is_responding = true;
	self->force_current_outbound_code = true;
	self->is_processing_message = true;
	self->did_respond = false;

#if VERBOSE_DEBUG
	coap_dump_header(
		SMCP_DEBUG_OUT_FILE,
		"FAKE Inbound:\t",
		self->inbound.packet,
		self->inbound.packet_len
	);
#endif

	status = smcp_handle_request(self);
	require(!status||status==SMCP_STATUS_NOT_FOUND||status==SMCP_STATUS_NOT_ALLOWED,bail);

	if(status) {
		smcp_outbound_set_content_len(0);
		smcp_outbound_send();
	}

bail:
	self->is_processing_message = false;
	self->did_respond = false;
	return status;
}

smcp_status_t
smcp_observable_trigger(smcp_observable_t context, uint8_t key, uint8_t flags)
{
	smcp_status_t ret = SMCP_STATUS_OK;
	int8_t i;
#if SMCP_EMBEDDED
	smcp_t const interface = smcp_get_current_instance();
#else
	smcp_t const interface = context->interface;

	if(!interface)
		goto bail;
#endif

	if(!context->first_observer)
		goto bail;

	for(i = context->first_observer-1; i >= 0; i = observer_table[i].next - 1) {
		if(	(observer_table[i].key != SMCP_OBSERVABLE_BROADCAST_KEY)
			&& (key != SMCP_OBSERVABLE_BROADCAST_KEY)
			&& (observer_table[i].key != key)
		) {
			continue;
		}

		observer_table[i].seq++;

		if(observer_table[i].transaction.active) {
			smcp_transaction_tickle(interface, &observer_table[i].transaction);
		} else {
			smcp_transaction_init(
				&observer_table[i].transaction,
				0, // Flags
				(void*)&retry_sending_event,
				(void*)&event_response_handler,
				(void*)&observer_table[i]
			);

			ret = smcp_transaction_begin(
				interface,
				&observer_table[i].transaction,
				SHOULD_CONFIRM_EVENT_FOR_OBSERVER(&observer_table[i])?SMCP_OBSERVER_CON_EVENT_EXPIRATION:SMCP_OBSERVER_NON_EVENT_EXPIRATION
			);
		}
	}

bail:
	return ret;
}
