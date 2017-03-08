/*!	@file smcp-pairing.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2016 Robert Quattlebaum
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

#ifndef __SMCP_PAIRING_H__
#define __SMCP_PAIRING_H__ 1

#include "smcp.h"
#include "smcp-observable.h"
#include "smcp-async.h"
#include "smcp-variable_handler.h"

__BEGIN_DECLS

/*!	@addtogroup smcp-extras
**	@{
*/

/*!	@defgroup smcp-pairing Pairing Subsystem
**	@{
**
**	The SMCP pairing subsystem implements a generic way to link
**	two resources so that changes to one cause the other
**	to be modified automatically. This allows you to avoid having
**	to implement such capability yourself.
**
**	For example, let's say that you had two smart light switches
**	that exposed the path `/1/dimmer_value`. If you observe
**	this path, you get asyncronous updates whenever somoene
**	adjusts that dimmer. Pairing allows you to have changes
**	to `/1/dimmer_value` on one of those smart light switches
**	automatically update `/1/dimmer_value` on the other.
**
**	There are three types of pairing, of which currently only one is
**	currently implemented:
**
**	* **Pull-type**, where the resource being observed is remote
**	  and the resource being changed is local. *(Implemented)*
**	* **Push-type**, where the resource being observed is local
**	  and the resource being changed is remote. *(Not yet implemented)*
**	* **Sync-Type**, where the both local and remote resources
**	  are observed and kept in-sync. *(Not yet implemented)*
**
**	This system is convenient because it provides a way to implement
**	generic, highly-flexible machine-to-machine communication with very
**	little additional code.
*/

#if SMCP_CONF_MAX_PAIRINGS

#define COAP_RESOURCE_TYPE_PAIRING_MANAGER		"pairing-manager"

struct smcp_pairing_mgr_s;
typedef struct smcp_pairing_mgr_s *smcp_pairing_mgr_t;

struct smcp_pairing_s;
typedef struct smcp_pairing_s *smcp_pairing_t;

typedef enum {
	SMCP_PAIRING_TYPE_NONE = 0,

	//! Observed remote resource POSTs to a local resource.
	SMCP_PAIRING_TYPE_PULL = 1,

	//! Observed local resource POSTs to a remote resource.
	/*! Not yet implemented. */
	SMCP_PAIRING_TYPE_PUSH = 2,

	//! Remote and local resources are kept in sync.
	/*! Not yet implemented. */
	SMCP_PAIRING_TYPE_SYNC = 3,
} smcp_pairing_type_t;

struct smcp_pairing_s {
	struct smcp_variable_handler_s var_handler;

	uint8_t index;
	bool stable:1;
	bool enabled:1;
	bool in_use:1;
	unsigned type:2;

	smcp_status_t last_code;
	uint32_t seq;
	int fire_count;
	coap_content_type_t content_type;

	char local_path[SMCP_MAX_URI_LENGTH];
	char remote_url[SMCP_MAX_URI_LENGTH];

	coap_size_t request_len;
	union {
		struct coap_header_s header;
		uint8_t bytes[SMCP_ASYNC_RESPONSE_MAX_LENGTH];
	} request;

	struct smcp_transaction_s transaction;
};

struct smcp_pairing_mgr_s {
	struct smcp_observable_s observable;
	struct smcp_pairing_s pairing_table[SMCP_CONF_MAX_PAIRINGS];

#if !SMCP_EMBEDDED
	smcp_t smcp_instance;
#endif

	// This function pointer should commit all stable
	// pairings to non-volatile memory, preserving their
	// `id` numbers. When the app starts up, it should retrieve
	// those pairings and recreate them.
	void (*commit_stable_pairings)(void* context, smcp_pairing_mgr_t mgr);
	void *context;
};

SMCP_API_EXTERN smcp_pairing_mgr_t smcp_pairing_mgr_init(
	smcp_pairing_mgr_t self,
	smcp_t smcp_instance
);

SMCP_API_EXTERN smcp_status_t smcp_pairing_mgr_request_handler(
	smcp_pairing_mgr_t self
);

SMCP_API_EXTERN smcp_pairing_t smcp_pairing_mgr_new_pairing(
	smcp_pairing_mgr_t self,
	const char* local_path,
	const char* remote_url,
	uint8_t requested_id
);

SMCP_API_EXTERN smcp_pairing_t smcp_pairing_mgr_pairing_begin(
	smcp_pairing_mgr_t self
);

SMCP_API_EXTERN smcp_pairing_t smcp_pairing_mgr_pairing_next(
	smcp_pairing_mgr_t self,
	smcp_pairing_t prev
);

SMCP_API_EXTERN uint8_t smcp_pairing_get_id(smcp_pairing_t self);

SMCP_API_EXTERN bool smcp_pairing_get_stable(smcp_pairing_t self);

SMCP_API_EXTERN smcp_status_t smcp_pairing_set_stable(smcp_pairing_t self, bool x);

SMCP_API_EXTERN bool smcp_pairing_get_enabled(smcp_pairing_t self);

SMCP_API_EXTERN smcp_status_t smcp_pairing_set_enabled(smcp_pairing_t self, bool x);

SMCP_API_EXTERN smcp_pairing_type_t smcp_pairing_get_type(smcp_pairing_t self);

SMCP_API_EXTERN smcp_status_t smcp_pairing_set_type(smcp_pairing_t self, smcp_pairing_type_t x);

SMCP_API_EXTERN coap_content_type_t smcp_pairing_get_content_type(smcp_pairing_t self);

SMCP_API_EXTERN smcp_status_t smcp_pairing_set_content_type(smcp_pairing_t self, coap_content_type_t x);

SMCP_API_EXTERN const char* smcp_pairing_get_local_path(smcp_pairing_t self);

SMCP_API_EXTERN const char* smcp_pairing_get_remote_url(smcp_pairing_t self);

SMCP_API_EXTERN void smcp_pairing_mgr_delete(
	smcp_pairing_mgr_t self,
	smcp_pairing_t pairing
);

#endif // SMCP_CONF_MAX_PAIRINGS > 0

/*!	@} */
/*!	@} */

__END_DECLS

#endif //__SMCP_PAIRING_H__
