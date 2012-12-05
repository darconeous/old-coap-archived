//
//  smcp-transaction.h
//  SMCP
//
//  Created by Robert Quattlebaum on 12/4/12.
//  Copyright (c) 2012 deepdarc. All rights reserved.
//

#ifndef SMCP_smcp_transaction_h
#define SMCP_smcp_transaction_h

#include "smcp-timer.h"
#include "btree.h"

struct smcp_transaction_s {
	struct bt_item_s			bt_item;

	smcp_inbound_resend_func	resendCallback;
	smcp_response_handler_func	callback;
	void*						context;

	// This expiration field has different meaning depending on
	// if this is an observable transaction or not. If it is
	// not observable, the expiration is when the transaction should
	// be "timed out". If it is observable, it is when the
	// max-age expires and we need to restart observing.
	struct timeval				expiration;
	struct smcp_timer_s			timer;

	coap_transaction_id_t		token;
	coap_transaction_id_t		msg_id;

	uint32_t					last_observe;
	uint32_t					next_block2;

	uint8_t						flags;
	uint8_t						attemptCount:4,
								waiting_for_async_response:1,
								should_dealloc:1,
								active:1,
								needs_to_close_observe:1;
};


#endif
