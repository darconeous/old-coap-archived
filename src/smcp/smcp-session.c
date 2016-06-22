/*!	@file smcp-session.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Session tracking
**
**	Copyright (C) 2014 Robert Quattlebaum
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

#if !SMCP_DEBUG_TIMERS && !VERBOSE_DEBUG
#undef DEBUG_PRINTF
#define DEBUG_PRINTF(fmt, ...) do { } while(0)
#endif

#include <stdio.h>

bool
smcp_session_type_supports_multicast(smcp_session_type_t session_type)
{
	return session_type == SMCP_SESSION_TYPE_UDP;
}

bool
smcp_session_type_is_reliable(smcp_session_type_t session_type)
{
	return false
#if SMCP_TCP
		|| (session_type == SMCP_SESSION_TYPE_TCP)
#endif
#if SMCP_TLS
		|| (session_type == SMCP_SESSION_TYPE_TLS)
#endif
	;
}

smcp_session_type_t
smcp_session_type_from_uri_scheme(const char* uri_scheme)
{
	smcp_session_type_t ret = SMCP_SESSION_TYPE_NIL;

#if SMCP_DTLS
	if (strequal_const(uri_scheme, COAP_URI_SCHEME_COAPS)) {
		ret = SMCP_SESSION_TYPE_DTLS;
	} else
#endif

#if SMCP_TCP
	if (strequal_const(uri_scheme, COAP_URI_SCHEME_COAP_TCP)) {
		ret = SMCP_SESSION_TYPE_TCP;
	} else
#endif

#if SMCP_TLS
	if (strequal_const(uri_scheme, COAP_URI_SCHEME_COAPS_TCP)) {
		ret = SMCP_SESSION_TYPE_TLS;
	} else
#endif

	if (strequal_const(uri_scheme, COAP_URI_SCHEME_COAP)) {
		ret = SMCP_SESSION_TYPE_UDP;
	}
	return ret;
}

uint16_t
smcp_default_port_from_session_type(smcp_session_type_t type)
{
	uint16_t ret = 0;

	switch (type) {
	case SMCP_SESSION_TYPE_UDP: ret = COAP_DEFAULT_PORT; break;
#if SMCP_DTLS
	case SMCP_SESSION_TYPE_DTLS: ret = COAP_DEFAULT_TLS_PORT; break;
#endif
#if SMCP_TCP
	case SMCP_SESSION_TYPE_TCP: ret = COAP_DEFAULT_PORT; break;
#endif
#if SMCP_TLS
	case SMCP_SESSION_TYPE_TLS: ret = COAP_DEFAULT_TLS_PORT; break;
#endif
	default: break;
	}
	return ret;
}
