/*	@file smcp.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
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

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert-macros.h"

#include "smcp.h"
#include "smcp-internal.h"
#include "smcp-logging.h"
#include "smcp-helpers.h"
#include "smcp-timer.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// MARK: -

#if SMCP_EMBEDDED
struct smcp_s smcp_global_instance;
#elif SMCP_MULTITHREAD && HAVE_PTHREAD
#include <pthread.h>
static pthread_key_t smcp_current_instance_key;
static pthread_once_t smcp_current_instance_once;
void
smcp_current_instance_setup(void)
{
	pthread_key_create(&smcp_current_instance_key, NULL);
}
void
smcp_set_current_instance(smcp_t x)
{
	pthread_once(&smcp_current_instance_once, smcp_current_instance_setup);
	pthread_setspecific(smcp_current_instance_key, (void*)x);
}
smcp_t
smcp_get_current_instance()
{
	pthread_once(&smcp_current_instance_once, smcp_current_instance_setup);
	return (smcp_t)pthread_getspecific(smcp_current_instance_key);
}
#else
static smcp_t smcp_current_instance;
void
smcp_set_current_instance(smcp_t x)
{
	smcp_current_instance = (x);
}
smcp_t
smcp_get_current_instance()
{
	return smcp_current_instance;
}
#endif

#if !SMCP_EMBEDDED
void
___smcp_check_version(uint32_t x)
{
	if (x != ___SMCP_CONFIG_ID) {
		assert_printf("SMCP Library Incompatability, you must recompile! lib:%u prog:%u", ___SMCP_CONFIG_ID, x);
		abort();
	}
}
#endif // !SMCP_EMBEDDED

// MARK: -
// MARK: SMCP Implementation

smcp_t
smcp_create(void) {
#if !SMCP_EMBEDDED
	smcp_t ret = NULL;

	ret = (smcp_t)calloc(1, sizeof(struct smcp_s));

	require(ret != NULL, bail);

	ret = smcp_init(ret);

bail:
	return ret;
#else
	return smcp_init(&smcp_global_instance);
#endif
}

smcp_t
smcp_init(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

	if (NULL == self) {
		return NULL;
	}

	// Clear the entire structure.
	memset(self, 0, sizeof(*self));

	return smcp_plat_init(self);
}

void
smcp_release(smcp_t self) {

	SMCP_EMBEDDED_SELF_HOOK;
	require(self, bail);

	// Delete all pending transactions
	while(self->transactions) {
		smcp_transaction_end(self, self->transactions);
	}

	// Delete all timers
	while(self->timers) {
		smcp_timer_t timer = self->timers;
		if(timer->cancel)
			timer->cancel(self, timer->context);
		smcp_invalidate_timer(self, timer);
	}

	smcp_plat_finalize(self);

#if !SMCP_EMBEDDED
	free(self);
#endif

bail:
	return;
}

void
smcp_set_proxy_url(smcp_t self,const char* url) {
	SMCP_EMBEDDED_SELF_HOOK;
	assert(self);
#if SMCP_AVOID_MALLOC && SMCP_EMBEDDED
	self->proxy_url = url;
#else
	free((void*)self->proxy_url);
	if(url)
		self->proxy_url = strdup(url);
	else
		self->proxy_url = NULL;
#endif
	DEBUG_PRINTF("CoAP Proxy URL set to %s",self->proxy_url);
}

void
smcp_set_default_request_handler(smcp_t self, smcp_request_handler_func request_handler, void* context)
{
	SMCP_EMBEDDED_SELF_HOOK;
	assert(self);
	self->request_handler = request_handler;
	self->request_handler_context = context;
}

// MARK: -
// MARK: VHost Support

#if SMCP_CONF_ENABLE_VHOSTS
smcp_status_t
smcp_vhost_add(smcp_t self,const char* name, smcp_request_handler_func func, void* context) {
	smcp_status_t ret = SMCP_STATUS_OK;
	struct smcp_vhost_s *vhost;
	SMCP_EMBEDDED_SELF_HOOK;

	DEBUG_PRINTF("Adding VHost \"%s\": handler:%p context:%p",name,func,context);

	require_action(name && (name[0]!=0), bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(self->vhost_count < SMCP_MAX_VHOSTS, bail, ret = SMCP_STATUS_FAILURE);

	vhost = &self->vhost[self->vhost_count++];

	strncpy(vhost->name,name,sizeof(vhost->name)-1);
	vhost->func = func;
	vhost->context = context;

bail:
	return ret;
}

smcp_status_t
smcp_vhost_route(smcp_request_handler_func* func, void** context) {
	smcp_t const self = smcp_get_current_instance();
	coap_option_key_t key;

	if(self->vhost_count) {
		const uint8_t* value;
		coap_size_t value_len = 0;

		smcp_inbound_reset_next_option();

		while((key = smcp_inbound_next_option(&value,&value_len))!=COAP_OPTION_INVALID) {
			if(key >= COAP_OPTION_URI_HOST)
				break;
		}

		if(value_len>(sizeof(self->vhost[0].name)-1))
			return SMCP_STATUS_INVALID_ARGUMENT;

		if(key == COAP_OPTION_URI_HOST) {
			int i;
			for(i=0;i<self->vhost_count;i++) {
				if(strncmp(self->vhost[i].name,(const char*)value,value_len) && self->vhost[i].name[value_len]==0) {
					*func = self->vhost[i].func;
					*context = self->vhost[i].context;
					break;
				}
			}
		}
	}

	return SMCP_STATUS_OK;
}

#endif

// MARK: -
// MARK: Other

coap_msg_id_t
smcp_get_next_msg_id(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

	if(!self->last_msg_id)
		self->last_msg_id = (uint16_t)SMCP_FUNC_RANDOM_UINT32();

#if DEBUG
	// Sequential in debug mode.
	self->last_msg_id++;
#else
	// Somewhat shuffled in non-debug mode.
	self->last_msg_id = self->last_msg_id*23873 + 41;
#endif

	return self->last_msg_id;
}

#if !SMCP_EMBEDDED || DEBUG
const char* smcp_status_to_cstr(int x) {
	switch(x) {
	case SMCP_STATUS_OK: return "OK"; break;
	case SMCP_STATUS_HOST_LOOKUP_FAILURE: return "Hostname Lookup Failure";
		break;
	case SMCP_STATUS_FAILURE: return "Unspecified Failure"; break;
	case SMCP_STATUS_INVALID_ARGUMENT: return "Invalid Argument"; break;
	case SMCP_STATUS_UNSUPPORTED_URI: return "Unsupported URI"; break;
	case SMCP_STATUS_MALLOC_FAILURE: return "Malloc Failure"; break;
	case SMCP_STATUS_TRANSACTION_INVALIDATED: return "Handler Invalidated";
		break;
	case SMCP_STATUS_TIMEOUT: return "Timeout"; break;
	case SMCP_STATUS_NOT_IMPLEMENTED: return "Not Implemented"; break;
	case SMCP_STATUS_NOT_FOUND: return "Not Found"; break;
	case SMCP_STATUS_H_ERRNO: return "H_ERRNO"; break;
	case SMCP_STATUS_RESPONSE_NOT_ALLOWED: return "Response not allowed";
		break;

	case SMCP_STATUS_LOOP_DETECTED: return "Loop detected"; break;
	case SMCP_STATUS_BAD_ARGUMENT: return "Bad Argument"; break;
	case SMCP_STATUS_MESSAGE_TOO_BIG: return "Message Too Big"; break;

	case SMCP_STATUS_NOT_ALLOWED: return "Not Allowed"; break;

	case SMCP_STATUS_BAD_OPTION: return "Bad Option"; break;
	case SMCP_STATUS_DUPE: return "Duplicate"; break;

	case SMCP_STATUS_RESET: return "Transaction Reset"; break;
	case SMCP_STATUS_URI_PARSE_FAILURE: return "URI Parse Failure"; break;

	case SMCP_STATUS_WAIT_FOR_DNS: return "Wait For DNS"; break;
	case SMCP_STATUS_WAIT_FOR_SESSION: return "Wait For Session"; break;

	case SMCP_STATUS_ERRNO:
#if SMCP_USE_BSD_SOCKETS
		return strerror(errno); break;
#else
		return "ERRNO!?"; break;
#endif
	default:
		{
			static char cstr[30];
			sprintf(cstr, "Unknown Status (%d)", x);
			return cstr;
		}
		break;
	}
	return NULL;
}
#endif

coap_code_t smcp_convert_status_to_result_code(smcp_status_t status) {
	coap_code_t ret = COAP_RESULT_500_INTERNAL_SERVER_ERROR;

	switch(status) {
	case SMCP_STATUS_OK:
		ret = COAP_RESULT_200;
		break;
	case SMCP_STATUS_NOT_FOUND:
		ret = COAP_RESULT_404_NOT_FOUND;
		break;
	case SMCP_STATUS_NOT_IMPLEMENTED:
		ret = COAP_RESULT_501_NOT_IMPLEMENTED;
		break;
	case SMCP_STATUS_NOT_ALLOWED:
		ret = COAP_RESULT_405_METHOD_NOT_ALLOWED;
		break;
	case SMCP_STATUS_UNSUPPORTED_URI:
		ret = COAP_RESULT_400_BAD_REQUEST;
		break;
	case SMCP_STATUS_BAD_OPTION:
		ret = COAP_RESULT_402_BAD_OPTION;
		break;
#if SMCP_USE_BSD_SOCKETS
	case SMCP_STATUS_ERRNO:
		if (errno == EPERM) {
			ret = COAP_RESULT_403_FORBIDDEN;
		}
		break;
#endif
	}

	return ret;
}

