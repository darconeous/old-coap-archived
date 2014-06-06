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
#include "smcp-auth.h"

#if SMCP_AVOID_MALLOC
static struct smcp_transaction_s smcp_transaction_pool[SMCP_CONF_MAX_TRANSACTIONS];
#endif // SMCP_AVOID_MALLOC

#if SMCP_TRANSACTIONS_USE_BTREE
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
#endif

smcp_transaction_t
smcp_transaction_find_via_msg_id(smcp_t self, coap_msg_id_t msg_id) {
#if SMCP_TRANSACTIONS_USE_BTREE
	return (smcp_transaction_t)bt_find(
		(void*)&self->transactions,
		(void*)(uintptr_t)msg_id,
		(bt_compare_func_t)smcp_transaction_compare_msg_id,
		self
	);
#else
	// Ouch. Linear search.
	smcp_transaction_t ret = self->transactions;
	while(ret && (ret->msg_id != msg_id)) ret = ll_next((void*)ret);
	return ret;
#endif

}

smcp_transaction_t
smcp_transaction_find_via_token(smcp_t self, coap_msg_id_t token) {
	// Ouch. Linear search.
#if SMCP_TRANSACTIONS_USE_BTREE
	smcp_transaction_t ret = bt_first(self->transactions);
	while(ret && (ret->token != token)) ret = bt_next(ret);
#else
	smcp_transaction_t ret = self->transactions;
	while(ret && (ret->token != token)) ret = ll_next((void*)ret);
#endif

	return ret;
}

static void
smcp_internal_delete_transaction_(
	smcp_transaction_t handler,
	smcp_t			self
) {
	DEBUG_PRINTF("smcp_internal_delete_transaction_: %p",handler);

#if !SMCP_TRANSACTIONS_USE_BTREE
	ll_remove((void**)&self->transactions,(void*)handler);
#endif

	// Remove the timer associated with this handler.
	smcp_invalidate_timer(self, &handler->timer);

	handler->active = 0;

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		(*handler->callback)(
			self,
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

	ret *= 512 + (SMCP_FUNC_RANDOM_UINT32() % (int)(512*(COAP_ACK_RANDOM_FACTOR-1.0f)));
	ret /= 512;

#if defined(COAP_MAX_ACK_RETRANSMIT_DURATION)
	if(ret > COAP_MAX_ACK_RETRANSMIT_DURATION*MSEC_PER_SEC)
		ret = COAP_MAX_ACK_RETRANSMIT_DURATION*MSEC_PER_SEC;
#endif
	DEBUG_PRINTF("Will try attempt #%d in %dms",retries,ret);
	return ret;
}

void
smcp_transaction_new_msg_id(
	smcp_t			self,
	smcp_transaction_t handler,
	coap_msg_id_t msg_id
) {
	require(handler->active,bail);

#if SMCP_TRANSACTIONS_USE_BTREE
	bt_remove(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)NULL,
		self
	);
#endif

	assert(!smcp_transaction_find_via_msg_id(self, msg_id));

	handler->msg_id = msg_id;

#if SMCP_TRANSACTIONS_USE_BTREE
	bt_insert(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)smcp_internal_delete_transaction_,
		self
	);
#endif

bail:
	return;
}

static void
smcp_internal_transaction_timeout_(
	smcp_t			self,
	smcp_transaction_t handler
) {
	smcp_status_t status = SMCP_STATUS_TIMEOUT;
	void* context = handler->context;
	cms_t cms = convert_timeval_to_cms(&handler->expiration);

	self->current_transaction = handler;
	if((cms > 0) || (0==handler->attemptCount)) {
		if(	(handler->flags&SMCP_TRANSACTION_KEEPALIVE)
			&& (cms > SMCP_OBSERVATION_KEEPALIVE_INTERVAL)
		) {
			cms = SMCP_OBSERVATION_KEEPALIVE_INTERVAL;
		}

		if(cms <= 0)
			cms = 0;

		if((0==handler->attemptCount) && handler->waiting_for_async_response && !(handler->flags&SMCP_TRANSACTION_KEEPALIVE)) {
			status = SMCP_STATUS_OK;
		}

		if(status == SMCP_STATUS_TIMEOUT && handler->resendCallback) {
			// Resend.
			self->outbound.next_tid = handler->msg_id;
			self->is_processing_message = false;
			self->is_responding = false;
			self->did_respond = false;

			status = handler->resendCallback(self, context);

			if(status == SMCP_STATUS_OK) {
				cms = MIN(cms,calc_retransmit_timeout(handler->attemptCount));

				if (SMCP_TRANSACTION_MAX_ATTEMPTS != handler->attemptCount)
					handler->attemptCount++;
			} else if(status == SMCP_STATUS_WAIT_FOR_DNS) {
				cms = 100;
				status = SMCP_STATUS_OK;
			}
		} else {
			// Huh? Why is this here?
			// TODO: Come back and figure out what I was thinking.
			handler->attemptCount += (0==handler->attemptCount);
		}

		smcp_schedule_timer(
			self,
			&handler->timer,
			cms
		);
#if SMCP_CONF_TRANS_ENABLE_OBSERVING
	} else if((handler->flags&SMCP_TRANSACTION_OBSERVE)) {
		// We have expired and we are observing someone. In this case we
		// need to restart the observing process.

		DEBUG_PRINTF("Observe-Transaction-Timeout: Starting over for %p",handler);

		handler->waiting_for_async_response = false;
		handler->attemptCount = 0;
		handler->last_observe = 0;
#if SMCP_CONF_TRANS_ENABLE_BLOCK2
		handler->next_block2 = 0;
#endif
		smcp_transaction_new_msg_id(self,handler,smcp_get_next_msg_id(self));
		convert_cms_to_timeval(&handler->expiration, SMCP_OBSERVATION_DEFAULT_MAX_AGE);

		if(handler->resendCallback) {
			// In this case we will be reattempting for a given duration.
			// The first attempt should happen pretty much immediately.
			cms = 0;

			if(handler->flags&SMCP_TRANSACTION_DELAY_START) {
				// ...unless this flag is set. Then we need to wait a moment.
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
#endif
	}

	if(status) {
		smcp_response_handler_func callback = handler->callback;

#if SMCP_CONF_TRANS_ENABLE_OBSERVING
		if(handler->flags&SMCP_TRANSACTION_OBSERVE) {
			// If we are an observing transaction, we need to clean up
			// first by sending one last request without an observe option.
			// TODO: Implement this!
		}
#endif

		if(!(handler->flags&SMCP_TRANSACTION_ALWAYS_INVALIDATE) && !(handler->flags&SMCP_TRANSACTION_NO_AUTO_END))
			handler->callback = NULL;

		if(callback)
			(*callback)(self,status,context);

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
	smcp_invalidate_timer(self, &handler->timer);

	smcp_schedule_timer(self,&handler->timer,0);

	return 0;
}

smcp_status_t
smcp_transaction_begin(
	smcp_t self,
	smcp_transaction_t handler,
	cms_t expiration
) {
	require(handler!=NULL, bail);

	DEBUG_PRINTF("smcp_transaction_begin: %p",handler);

#if SMCP_TRANSACTIONS_USE_BTREE
	bt_remove(
		(void**)&self->transactions,
		(void*)handler,
		(bt_compare_func_t)smcp_transaction_compare,
		NULL,
		self
	);
#else
	ll_remove((void**)&self->transactions,(void*)handler);
#endif

	if(expiration<0)
		expiration = COAP_EXCHANGE_LIFETIME*MSEC_PER_SEC;

	handler->token = smcp_get_next_msg_id(self);
	handler->msg_id = handler->token;
	handler->waiting_for_async_response = false;
	handler->attemptCount = 0;
#if SMCP_CONF_TRANS_ENABLE_OBSERVING
	handler->last_observe = 0;
#endif
#if SMCP_CONF_TRANS_ENABLE_BLOCK2
	handler->next_block2 = 0;
#endif
	handler->active = 1;
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

#if SMCP_TRANSACTIONS_USE_BTREE
	bt_insert(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)smcp_transaction_compare,
		(bt_delete_func_t)smcp_internal_delete_transaction_,
		self
	);
	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)bt_count((void**)&self->transactions));
#else
	ll_prepend((void**)&self->transactions,(void*)handler);
	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)ll_count((void**)&self->transactions));
#endif


bail:
	return 0;
}

smcp_status_t
smcp_transaction_end(
	smcp_t self,
	smcp_transaction_t transaction
) {
	DEBUG_PRINTF("smcp_transaction_end: %p",transaction);

#if SMCP_CONF_TRANS_ENABLE_OBSERVING
	if(transaction->flags&SMCP_TRANSACTION_OBSERVE) {
		// If we are an observing transaction, we need to clean up
		// first by sending one last request without an observe option.
		// TODO: Implement this!
	}
#endif

	if(transaction == self->current_transaction)
		self->current_transaction = NULL;

	if(transaction->active) {
		transaction->active = 0; // Maybe we should remove this line? May be hiding bad behavior.
#if SMCP_TRANSACTIONS_USE_BTREE
		bt_remove(
			(void**)&self->transactions,
			(void*)transaction,
			(bt_compare_func_t)smcp_transaction_compare,
			(bt_delete_func_t)smcp_internal_delete_transaction_,
			self
		);
#else
		ll_remove((void**)&self->transactions,(void*)transaction);
		smcp_internal_delete_transaction_(transaction,self);
#endif
	}
	return 0;
}

smcp_status_t
smcp_handle_response(smcp_t self) {
	smcp_status_t ret = 0;
	smcp_transaction_t handler = NULL;
	coap_msg_id_t msg_id = smcp_inbound_get_msg_id(self);

#if VERBOSE_DEBUG
	DEBUG_PRINTF(
		"smcp(%p): Incoming response! msgid=0x%02X",
		self,
		smcp_inbound_get_msg_id()
	);
#if SMCP_TRANSACTIONS_USE_BTREE
	DEBUG_PRINTF("%p: Total Pending Transactions: %d", self,
		(int)bt_count((void**)&self->transactions));
#else
	DEBUG_PRINTF("%p: Total Pending Transactions: %d", self,
		(int)ll_count((void**)&self->transactions));
#endif
#endif // VERBOSE_DEBUG

	{
		coap_msg_id_t token = 0;
		if(self->inbound.packet->token_len == sizeof(coap_msg_id_t)) {
			memcpy(&token,self->inbound.packet->token,sizeof(token));
		}

		handler = smcp_transaction_find_via_msg_id(self,msg_id);

		if (NULL == handler) {
			if (self->inbound.packet->tt < COAP_TRANS_TYPE_ACK) {
				handler = smcp_transaction_find_via_token(self,token);
			}
		} else if (smcp_inbound_get_packet(self)->code != COAP_CODE_EMPTY
			&& token != handler->token
		) {
			handler = NULL;
		}
	}

	if(handler
		&& !handler->multicast
		&& ((0 != memcmp(&handler->saddr.smcp_addr, &self->inbound.saddr.smcp_addr, sizeof(handler->saddr.smcp_addr)))
			|| handler->saddr.smcp_port != self->inbound.saddr.smcp_port
		)
	) {
		DEBUG_PRINTF("Bad address!");
		// Message-ID or token matched, but the address didn't. Fail.
		handler = NULL;
	}

	self->current_transaction = handler;

	if(!handler) {
		// This is an unknown response. If the packet
		// if confirmable, send a reset. If not, don't bother.
		if(self->inbound.packet->tt <= COAP_TRANS_TYPE_NONCONFIRMABLE) {
			DEBUG_PRINTF("Inbound: Unknown Response, sending reset. . .");

			smcp_outbound_begin_response(self, 0);
			self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			ret = smcp_outbound_send(self);
		} else {
			DEBUG_PRINTF("Inbound: Unknown ack or reset, ignoring. . .");
		}
	} else if(	(	self->inbound.packet->tt == COAP_TRANS_TYPE_ACK
			|| self->inbound.packet->tt == COAP_TRANS_TYPE_NONCONFIRMABLE
		)
		&& self->inbound.packet->code == COAP_CODE_EMPTY
		&& (handler->sent_code<COAP_RESULT_100)
	) {
		DEBUG_PRINTF("Inbound: Empty ACK, Async response expected.");
		handler->waiting_for_async_response = true;
	} else if(handler->callback) {
		msg_id = handler->msg_id;

		DEBUG_PRINTF("Inbound: Transaction handling response.");

		// Handle any authentication headers.
		ret = smcp_auth_inbound_init(self);
		require_noerr(ret,bail);

		smcp_inbound_reset_next_option(self);

#if SMCP_CONF_TRANS_ENABLE_OBSERVING
		if((handler->flags & SMCP_TRANSACTION_OBSERVE) && self->inbound.has_observe_option) {
			cms_t cms = self->inbound.max_age*MSEC_PER_SEC;

			if(	self->inbound.has_observe_option
				&& (self->inbound.observe_value<=handler->last_observe)
				&& ((handler->last_observe-self->inbound.observe_value)>0x7FFFFF)
			) {
				DEBUG_PRINTF("Inbound: Skipping older inbound observation. (%d<=%d)",self->inbound.observe_value,handler->last_observe);
				// We've already seen this one. Skip it.
				ret = SMCP_STATUS_DUPE;
				goto bail;
			}

			handler->last_observe = self->inbound.observe_value;

			ret = (*handler->callback)(
				self,
				self->inbound.packet->tt==COAP_TRANS_TYPE_RESET?SMCP_STATUS_RESET:self->inbound.packet->code,
				handler->context
			);

			// TODO: Explain why this is necessary
			if(!self->current_transaction) {
				handler = NULL;
				goto bail;
			}

			// TODO: Explain why this is necessary
			if(msg_id!=handler->msg_id) {
				handler = NULL;
				goto bail;
			}

			if(self->inbound.has_observe_option) {
				handler->waiting_for_async_response = true;
			}

			handler->attemptCount = 0;
			handler->timer.cancel = NULL;

			smcp_invalidate_timer(self, &handler->timer);

			if(!cms) {
				if(self->inbound.has_observe_option)
					cms = CMS_DISTANT_FUTURE;
				else
					cms = SMCP_OBSERVATION_DEFAULT_MAX_AGE;
			}

			convert_cms_to_timeval(&handler->expiration, cms);

			if(	(handler->flags&SMCP_TRANSACTION_KEEPALIVE)
				&& cms>SMCP_OBSERVATION_KEEPALIVE_INTERVAL
			) {
				cms = SMCP_OBSERVATION_KEEPALIVE_INTERVAL;
			}

			smcp_schedule_timer(
				self,
				&handler->timer,
				cms
			);
		} else
#endif // #if SMCP_CONF_TRANS_ENABLE_OBSERVING
		{
			smcp_response_handler_func callback = handler->callback;

			if(!(handler->flags&SMCP_TRANSACTION_ALWAYS_INVALIDATE) && !(handler->flags&SMCP_TRANSACTION_OBSERVE)) {
				handler->callback = NULL;
			}
			ret = (*callback)(
				self,
				(self->inbound.packet->tt==COAP_TRANS_TYPE_RESET)?SMCP_STATUS_RESET:self->inbound.packet->code,
				handler->context
			);

			if(self->current_transaction != handler) {
				handler = NULL;
				goto bail;
			}

			handler->attemptCount = 0;
			handler->waiting_for_async_response = false;
			if(handler->active && msg_id==handler->msg_id) {
#if SMCP_CONF_TRANS_ENABLE_BLOCK2
				if(!ret && (self->inbound.block2_value&(1<<3)) && (handler->flags&SMCP_TRANSACTION_ALWAYS_INVALIDATE)) {
					DEBUG_PRINTF("Inbound: Preparing to request next block...");
					handler->next_block2 = self->inbound.block2_value + (1<<4);
					smcp_transaction_new_msg_id(self, handler, smcp_get_next_msg_id(self));
					smcp_invalidate_timer(self, &handler->timer);
					smcp_schedule_timer(
						self,
						&handler->timer,
						0
					);
				} else
#endif // SMCP_CONF_TRANS_ENABLE_BLOCK2
#if SMCP_CONF_TRANS_ENABLE_OBSERVING
				if (!ret && (handler->flags&SMCP_TRANSACTION_OBSERVE)) {
					cms_t cms = self->inbound.max_age*1000;
#if SMCP_CONF_TRANS_ENABLE_BLOCK2
					handler->next_block2 = 0;
#endif // SMCP_CONF_TRANS_ENABLE_BLOCK2

					smcp_invalidate_timer(self, &handler->timer);

					if(!cms) {
						if(self->inbound.has_observe_option)
							cms = CMS_DISTANT_FUTURE;
						else
							cms = SMCP_OBSERVATION_DEFAULT_MAX_AGE;
					}

					convert_cms_to_timeval(&handler->expiration, cms);

					if(	(handler->flags&SMCP_TRANSACTION_KEEPALIVE)
						&& cms>SMCP_OBSERVATION_KEEPALIVE_INTERVAL
					) {
						cms = SMCP_OBSERVATION_KEEPALIVE_INTERVAL;
					}

					smcp_schedule_timer(
						self,
						&handler->timer,
						cms
					);
				} else
#endif // #if SMCP_CONF_TRANS_ENABLE_OBSERVING
				{
					handler->resendCallback = NULL;
					if(!(handler->flags&SMCP_TRANSACTION_NO_AUTO_END))
						smcp_transaction_end(self, handler);
					handler = NULL;
				}
			}
		}
	}

bail:
	if(ret && handler && !(handler->flags&SMCP_TRANSACTION_NO_AUTO_END)) {
		smcp_transaction_end(self, handler);
	}
	return ret;
}

