/*	@file smcp-transaction.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Transaction functions
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

#include <stdio.h>
#include "smcp.h"
#include "smcp-internal.h"
#include "smcp-transaction.h"

#if SMCP_AVOID_MALLOC
static struct smcp_transaction_s smcp_transaction_pool[SMCP_CONF_MAX_TRANSACTIONS];
#endif // SMCP_AVOID_MALLOC

static bt_compare_result_t
smcp_transaction_compare(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_transaction_t lhs = (smcp_transaction_t)lhs_;
	const smcp_transaction_t rhs = (smcp_transaction_t)rhs_;

	if(lhs->msg_id > rhs->msg_id)
		return 1;
	if(lhs->msg_id < rhs->msg_id)
		return -1;
	return 0;
}

static bt_compare_result_t
smcp_transaction_compare_msg_id(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_transaction_t lhs = (smcp_transaction_t)lhs_;
	coap_msg_id_t rhs = (coap_msg_id_t)(uintptr_t)rhs_;

	if(lhs->msg_id > rhs)
		return 1;
	if(lhs->msg_id < rhs)
		return -1;
	return 0;
}

smcp_transaction_t
smcp_transaction_find_via_msg_id(smcp_t self, coap_msg_id_t msg_id) {
	SMCP_EMBEDDED_SELF_HOOK;
	return (smcp_transaction_t)bt_find(
		(void**)&self->transactions,
		(void*)(uintptr_t)msg_id,
		(bt_compare_func_t)smcp_transaction_compare_msg_id,
		self
	);
}

smcp_transaction_t
smcp_transaction_find_via_token(smcp_t self, coap_msg_id_t token) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_transaction_t ret = bt_first(self->transactions);

	// Ouch. Linear search.
	while(ret && ret->token!=token) ret = bt_next(ret);

	return ret;
}

static void
smcp_internal_delete_transaction_(
	smcp_transaction_t handler,
	smcp_t			self
) {
	DEBUG_PRINTF("smcp_internal_delete_transaction_: %p",handler);

	if(!smcp_get_current_instance())
		smcp_set_current_instance(self);

	check(self==smcp_get_current_instance());

	// Remove the timer associated with this handler.
	smcp_invalidate_timer(self, &handler->timer);

	handler->active = 0;

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		(*handler->callback)(
			SMCP_STATUS_TRANSACTION_INVALIDATED,
			handler->context
		);
	}

#if SMCP_AVOID_MALLOC
	if(handler->should_dealloc)
		handler->callback = NULL;
#else
	if(handler->should_dealloc)
		free(handler);
#endif
}

static cms_t
calc_retransmit_timeout(int retries) {
	cms_t ret = COAP_ACK_TIMEOUT * MSEC_PER_SEC;

	ret <<= retries;

	ret *= 1024 + (SMCP_FUNC_RANDOM_UINT32() % (int)(1024*(1-COAP_ACK_RANDOM_FACTOR)));
	ret /= 1024;

#if defined(COAP_MAX_ACK_RETRANSMIT_DURATION)
	if(ret > COAP_MAX_ACK_RETRANSMIT_DURATION*MSEC_PER_SEC)
		ret = COAP_MAX_ACK_RETRANSMIT_DURATION*MSEC_PER_SEC;
#endif

	return ret;
}

void
smcp_transaction_new_msg_id(
	smcp_t			self,
	smcp_transaction_t handler,
	coap_msg_id_t msg_id
) {
	SMCP_EMBEDDED_SELF_HOOK;
	require(handler->active,bail);

	bt_remove(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)NULL,
		self
	);

	assert(!smcp_transaction_find_via_msg_id(self, msg_id));

	handler->msg_id = msg_id;

	bt_insert(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)smcp_internal_delete_transaction_,
		self
	);

bail:
	return;
}

void
smcp_internal_transaction_timeout_(
	smcp_t			self,
	smcp_transaction_t handler
) {
	smcp_status_t status = SMCP_STATUS_TIMEOUT;
	void* context = handler->context;
	cms_t cms = convert_timeval_to_cms(&handler->expiration);

	self->current_transaction = handler;
	if((cms > 0) || !handler->has_fired) {
		if(	(handler->flags&SMCP_TRANSACTION_KEEPALIVE)
			&& cms>SMCP_OBSERVATION_KEEPALIVE_INTERVAL
		) {
			cms = SMCP_OBSERVATION_KEEPALIVE_INTERVAL;
		}

		if(cms<=0)
			cms = 0;

		if(!handler->has_fired && handler->waiting_for_async_response && !(handler->flags&SMCP_TRANSACTION_KEEPALIVE)) {
			status = SMCP_STATUS_OK;
		}

		if(status == SMCP_STATUS_TIMEOUT && handler->resendCallback) {
			// Resend.
			self->outbound.next_tid = handler->msg_id;
			self->is_processing_message = false;
			self->is_responding = false;
			self->did_respond = false;

			status = handler->resendCallback(context);

			if(status == SMCP_STATUS_OK) {
				handler->has_fired = true;
				if((cms > 0) && (self->outbound.packet->tt!=COAP_TRANS_TYPE_NONCONFIRMABLE
					|| handler->attemptCount<2)
				) {
					cms = MIN(cms,calc_retransmit_timeout(handler->attemptCount++));
				}
			} else if(status == SMCP_STATUS_WAIT_FOR_DNS) {
				cms = 100;
				status = SMCP_STATUS_OK;
			}
		} else {
			handler->has_fired = true;
		}

		smcp_schedule_timer(
			self,
			&handler->timer,
			cms
		);
	} else if((handler->flags&SMCP_TRANSACTION_OBSERVE)) {
		// We have expired and we are observable. In this case we
		// need to restart the observing process.

		DEBUG_PRINTF("Observe-Transaction-Timeout: Starting over for %p",handler);

		handler->waiting_for_async_response = false;
		handler->attemptCount = 0;
		handler->last_observe = 0;
		handler->next_block2 = 0;
		smcp_transaction_new_msg_id(self,handler,smcp_get_next_msg_id(self, NULL));
		convert_cms_to_timeval(&handler->expiration, SMCP_OBSERVATION_DEFAULT_MAX_AGE);

		if(handler->resendCallback) {
			// In this case we will be reattempting for a given duration.
			// The first attempt should happen pretty much immediately.
			cms = 0;

			if(handler->flags&SMCP_TRANSACTION_DELAY_START) {
				// Unless this flag is set. Then we need to wait a moment.
				cms = 10 + (SMCP_FUNC_RANDOM_UINT32() % 290);
			}
		}

		if(	(handler->flags&SMCP_TRANSACTION_KEEPALIVE)
			&& cms>SMCP_OBSERVATION_KEEPALIVE_INTERVAL
		) {
			cms = SMCP_OBSERVATION_KEEPALIVE_INTERVAL;
		}

		status = smcp_schedule_timer(
			self,
			&handler->timer,
			cms
		);
	}

	if(status) {
		smcp_response_handler_func callback = handler->callback;

		if(handler->flags&SMCP_TRANSACTION_OBSERVE) {
			// If we are an observing transaction, we need to clean up
			// first by sending one last request without an observe option.
			// TODO: Implement this!
		}

		if(!(handler->flags&SMCP_TRANSACTION_ALWAYS_INVALIDATE) && !(handler->flags&SMCP_TRANSACTION_NO_AUTO_END))
			handler->callback = NULL;
		if(callback)
			(*callback)(status,context);
		if(handler != self->current_transaction)
			return;
		if(!(handler->flags&SMCP_TRANSACTION_NO_AUTO_END))
			smcp_transaction_end(self, handler);
	}

	self->current_transaction = NULL;
}


smcp_transaction_t
smcp_transaction_init(
	smcp_transaction_t handler,
	int	flags,
	smcp_inbound_resend_func resendCallback,
	smcp_response_handler_func	callback,
	void* context
) {
	if(!handler) {
#if SMCP_AVOID_MALLOC
		uint8_t i;
		for(i=0;i<SMCP_CONF_MAX_TRANSACTIONS;i++) {
			handler = &smcp_transaction_pool[i];
			if(!handler->callback)
				break;
			handler = NULL;
		}
#else
		handler = (smcp_transaction_t)calloc(sizeof(*handler), 1);
#endif
		if(handler)
			handler->should_dealloc = 1;
	} else {
		memset(handler,0,sizeof(*handler));
	}

	require(handler!=NULL, bail);

	handler->resendCallback = resendCallback;
	handler->callback = callback;
	handler->context = context;
	handler->flags = flags;

bail:
	return handler;
}

smcp_status_t
smcp_transaction_tickle(
	smcp_t self,
	smcp_transaction_t handler
) {
	SMCP_EMBEDDED_SELF_HOOK;

	smcp_invalidate_timer(self, &handler->timer);

	smcp_schedule_timer(
		self,
		&handler->timer,
		0
	);

	return 0;
}

smcp_status_t
smcp_transaction_begin(
	smcp_t self,
	smcp_transaction_t handler,
	cms_t expiration
) {
	SMCP_EMBEDDED_SELF_HOOK;
	require(handler!=NULL, bail);

	DEBUG_PRINTF("smcp_transaction_begin: %p",handler);

	bt_remove(
		(void**)&self->transactions,
		(void*)handler,
		(bt_compare_func_t)smcp_transaction_compare,
		NULL,
		self
	);

	if(!expiration)
		expiration = COAP_EXCHANGE_LIFETIME*MSEC_PER_SEC;

	handler->token = smcp_get_next_msg_id(self, NULL);
	handler->msg_id = handler->token;
	handler->waiting_for_async_response = false;
	handler->attemptCount = 0;
	handler->last_observe = 0;
	handler->next_block2 = 0;
	handler->active = 1;
	handler->has_fired = false;
	convert_cms_to_timeval(&handler->expiration, expiration);

	if(handler->resendCallback) {
		// In this case we will be reattempting for a given duration.
		// The first attempt should happen pretty much immediately.
		expiration = 0;

		if(handler->flags&SMCP_TRANSACTION_DELAY_START) {
			// Unless this flag is set. Then we need to wait a moment.
			expiration = 10 + (SMCP_FUNC_RANDOM_UINT32() % (MSEC_PER_SEC*COAP_DEFAULT_LEASURE));
		}
	}

	if(	(handler->flags&SMCP_TRANSACTION_KEEPALIVE)
		&& expiration>SMCP_OBSERVATION_KEEPALIVE_INTERVAL
	) {
		expiration = SMCP_OBSERVATION_KEEPALIVE_INTERVAL;
	}

	smcp_schedule_timer(
		self,
		smcp_timer_init(
			&handler->timer,
			(smcp_timer_callback_t)&smcp_internal_transaction_timeout_,
			NULL,
			handler
		),
		expiration
	);

	bt_insert(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)smcp_internal_delete_transaction_,
		self
	);

	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)bt_count((void**)&self->transactions));

bail:
	return 0;
}

smcp_status_t
smcp_transaction_end(
	smcp_t self,
	smcp_transaction_t transaction
) {
	SMCP_EMBEDDED_SELF_HOOK;
	DEBUG_PRINTF("smcp_transaction_end: %p",transaction);

	if(transaction->flags&SMCP_TRANSACTION_OBSERVE) {
		// If we are an observing transaction, we need to clean up
		// first by sending one last request without an observe option.
		// TODO: Implement this!
	}

	if(transaction == self->current_transaction)
		self->current_transaction = NULL;

	if(transaction->active) {
		transaction->active = 0; // Maybe we should remove this line? May be hiding bad behavior.
		bt_remove(
			(void**)&self->transactions,
			(void*)transaction,
			(bt_compare_func_t)smcp_transaction_compare,
			(bt_delete_func_t)smcp_internal_delete_transaction_,
			self
		);
	}
	return 0;
}





//! DEPRECATED.
smcp_status_t
smcp_begin_transaction_old(
	smcp_t						self,
	coap_msg_id_t		tid,
	cms_t						cmsExpiration,
	int							flags,
	smcp_inbound_resend_func	resendCallback,
	smcp_response_handler_func	callback,
	void*						context
) {
	smcp_status_t ret = 0;
	smcp_transaction_t transaction = NULL;

	transaction = smcp_transaction_init(
		transaction,
		flags,
		resendCallback,
		callback,
		context
	);

	ret = smcp_transaction_begin(self,transaction,cmsExpiration);

	require_noerr(ret,bail);
	require(transaction!=NULL,bail);

	transaction->token = tid;

bail:
	return ret;
}

//! DEPRECATED.
smcp_status_t
smcp_invalidate_transaction_old(
	smcp_t			self,
	coap_msg_id_t	tid
) {
	smcp_transaction_t transaction = smcp_transaction_find_via_msg_id(self, tid);
	if(!transaction) {
		transaction = smcp_transaction_find_via_token(self, tid);
	}
	if(transaction)
		smcp_transaction_end(self, transaction);
	return 0;
}

