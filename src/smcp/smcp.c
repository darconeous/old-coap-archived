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

#include <libnyoci/libnyoci.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// MARK: -

#if NYOCI_SINGLETON
struct smcp_s smcp_global_instance;
#elif NYOCI_THREAD_SAFE && HAVE_PTHREAD
#include <pthread.h>
static pthread_key_t smcp_current_instance_key;
static pthread_once_t smcp_current_instance_once;
void
smcp_current_instance_setup(void)
{
	pthread_key_create(&smcp_current_instance_key, NULL);
}
void
nyoci_set_current_instance(nyoci_t x)
{
	pthread_once(&smcp_current_instance_once, smcp_current_instance_setup);
	pthread_setspecific(smcp_current_instance_key, (void*)x);
}
nyoci_t
nyoci_get_current_instance()
{
	pthread_once(&smcp_current_instance_once, smcp_current_instance_setup);
	return (nyoci_t)pthread_getspecific(smcp_current_instance_key);
}
#else
static nyoci_t smcp_current_instance;
void
nyoci_set_current_instance(nyoci_t x)
{
	smcp_current_instance = (x);
}
nyoci_t
nyoci_get_current_instance()
{
	return smcp_current_instance;
}
#endif

#if !NYOCI_SINGLETON
void
___nyoci_check_version(uint32_t x)
{
	if (x != ___NYOCI_CONFIG_ID) {
		assert_printf("SMCP Library Incompatability, you must recompile! lib:%u prog:%u", ___NYOCI_CONFIG_ID, x);
		abort();
	}
}
#endif // !NYOCI_SINGLETON

// MARK: -
// MARK: SMCP Implementation

nyoci_t
nyoci_create(void) {
#if !NYOCI_SINGLETON
	nyoci_t ret = NULL;

	ret = (nyoci_t)calloc(1, sizeof(struct smcp_s));

	require(ret != NULL, bail);

	ret = nyoci_init(ret);

bail:
	return ret;
#else
	return nyoci_init(&smcp_global_instance);
#endif
}

nyoci_t
nyoci_init(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;

	if (NULL == self) {
		return NULL;
	}

	// Clear the entire structure.
	memset(self, 0, sizeof(*self));

	return smcp_plat_init(self);
}

void
nyoci_release(nyoci_t self) {

	NYOCI_SINGLETON_SELF_HOOK;
	require(self, bail);

	// Delete all pending transactions
	while(self->transactions) {
		nyoci_transaction_end(self, self->transactions);
	}

	// Delete all timers
	while(self->timers) {
		nyoci_timer_t timer = self->timers;
		if(timer->cancel)
			timer->cancel(self, timer->context);
		nyoci_invalidate_timer(self, timer);
	}

	smcp_plat_finalize(self);

#if !NYOCI_SINGLETON
	free(self);
#endif

bail:
	return;
}

void
nyoci_set_proxy_url(nyoci_t self,const char* url) {
	NYOCI_SINGLETON_SELF_HOOK;
	assert(self);
#if NYOCI_AVOID_MALLOC && NYOCI_SINGLETON
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
nyoci_set_default_request_handler(nyoci_t self, nyoci_request_handler_func request_handler, void* context)
{
	NYOCI_SINGLETON_SELF_HOOK;
	assert(self);
	self->request_handler = request_handler;
	self->request_handler_context = context;
}

// MARK: -
// MARK: VHost Support

#if NYOCI_CONF_ENABLE_VHOSTS
nyoci_status_t
nyoci_vhost_add(nyoci_t self,const char* name, nyoci_request_handler_func func, void* context) {
	nyoci_status_t ret = NYOCI_STATUS_OK;
	struct nyoci_vhost_s *vhost;
	NYOCI_SINGLETON_SELF_HOOK;

	DEBUG_PRINTF("Adding VHost \"%s\": handler:%p context:%p",name,func,context);

	require_action(name && (name[0]!=0), bail, ret = NYOCI_STATUS_INVALID_ARGUMENT);
	require_action(self->vhost_count < NYOCI_MAX_VHOSTS, bail, ret = NYOCI_STATUS_FAILURE);

	vhost = &self->vhost[self->vhost_count++];

	strncpy(vhost->name,name,sizeof(vhost->name)-1);
	vhost->func = func;
	vhost->context = context;

bail:
	return ret;
}

nyoci_status_t
smcp_vhost_route(nyoci_request_handler_func* func, void** context) {
	nyoci_t const self = nyoci_get_current_instance();
	coap_option_key_t key;

	if(self->vhost_count) {
		const uint8_t* value;
		coap_size_t value_len = 0;

		nyoci_inbound_reset_next_option();

		while((key = nyoci_inbound_next_option(&value,&value_len))!=COAP_OPTION_INVALID) {
			if(key >= COAP_OPTION_URI_HOST)
				break;
		}

		if(value_len>(sizeof(self->vhost[0].name)-1))
			return NYOCI_STATUS_INVALID_ARGUMENT;

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

	return NYOCI_STATUS_OK;
}

#endif

// MARK: -
// MARK: Other

coap_msg_id_t
nyoci_get_next_msg_id(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;

	if (0 == self->last_msg_id) {
		self->last_msg_id = (uint16_t)NYOCI_FUNC_RANDOM_UINT32();
	}

#if DEBUG
	// Sequential in debug mode.
	self->last_msg_id++;
#else
	// Somewhat shuffled in non-debug mode.
	self->last_msg_id = self->last_msg_id*23873 + 41;
#endif

	return self->last_msg_id;
}

const char* nyoci_status_to_cstr(int x) {
	switch(x) {
	case NYOCI_STATUS_OK: return "OK"; break;
	case NYOCI_STATUS_HOST_LOOKUP_FAILURE: return "Hostname Lookup Failure";
		break;
	case NYOCI_STATUS_FAILURE: return "Unspecified Failure"; break;
	case NYOCI_STATUS_INVALID_ARGUMENT: return "Invalid Argument"; break;
	case NYOCI_STATUS_UNSUPPORTED_URI: return "Unsupported URI"; break;
	case NYOCI_STATUS_MALLOC_FAILURE: return "Malloc Failure"; break;
	case NYOCI_STATUS_TRANSACTION_INVALIDATED: return "Handler Invalidated";
		break;
	case NYOCI_STATUS_TIMEOUT: return "Timeout"; break;
	case NYOCI_STATUS_NOT_IMPLEMENTED: return "Not Implemented"; break;
	case NYOCI_STATUS_NOT_FOUND: return "Not Found"; break;
	case NYOCI_STATUS_H_ERRNO: return "H_ERRNO"; break;
	case NYOCI_STATUS_RESPONSE_NOT_ALLOWED: return "Response not allowed";
		break;

	case NYOCI_STATUS_LOOP_DETECTED: return "Loop detected"; break;
	case NYOCI_STATUS_BAD_ARGUMENT: return "Bad Argument"; break;
	case NYOCI_STATUS_MESSAGE_TOO_BIG: return "Message Too Big"; break;

	case NYOCI_STATUS_NOT_ALLOWED: return "Not Allowed"; break;

	case NYOCI_STATUS_BAD_OPTION: return "Bad Option"; break;
	case NYOCI_STATUS_DUPE: return "Duplicate"; break;

	case NYOCI_STATUS_RESET: return "Transaction Reset"; break;
	case NYOCI_STATUS_URI_PARSE_FAILURE: return "URI Parse Failure"; break;

	case NYOCI_STATUS_WAIT_FOR_DNS: return "Wait For DNS"; break;
	case NYOCI_STATUS_WAIT_FOR_SESSION: return "Wait For Session"; break;

	case NYOCI_STATUS_SESSION_ERROR: return "Session Error"; break;
	case NYOCI_STATUS_SESSION_CLOSED: return "Session Closed"; break;

	case NYOCI_STATUS_ERRNO:
#if NYOCI_USE_BSD_SOCKETS
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

coap_code_t nyoci_convert_status_to_result_code(nyoci_status_t status) {
	coap_code_t ret = COAP_RESULT_500_INTERNAL_SERVER_ERROR;

	switch(status) {
	case NYOCI_STATUS_OK:
		ret = COAP_RESULT_200;
		break;
	case NYOCI_STATUS_NOT_FOUND:
		ret = COAP_RESULT_404_NOT_FOUND;
		break;
	case NYOCI_STATUS_NOT_IMPLEMENTED:
		ret = COAP_RESULT_501_NOT_IMPLEMENTED;
		break;
	case NYOCI_STATUS_NOT_ALLOWED:
		ret = COAP_RESULT_405_METHOD_NOT_ALLOWED;
		break;
	case NYOCI_STATUS_UNSUPPORTED_URI:
		ret = COAP_RESULT_400_BAD_REQUEST;
		break;
	case NYOCI_STATUS_BAD_OPTION:
		ret = COAP_RESULT_402_BAD_OPTION;
		break;
	case NYOCI_STATUS_UNSUPPORTED_MEDIA_TYPE:
		ret = COAP_RESULT_415_UNSUPPORTED_MEDIA_TYPE;
		break;
#if NYOCI_USE_BSD_SOCKETS
	case NYOCI_STATUS_ERRNO:
		if (errno == EPERM) {
			ret = COAP_RESULT_403_FORBIDDEN;
		}
		break;
#endif
	}

	return ret;
}

