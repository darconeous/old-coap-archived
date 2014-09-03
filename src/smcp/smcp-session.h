/*!	@file smcp-session.h
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

#ifndef SMCP_smcp_session_h
#define SMCP_smcp_session_h

__BEGIN_DECLS

/*!	@addtogroup smcp
**	@{
*/

typedef enum {
	SMCP_SESSION_TYPE_NIL,
	SMCP_SESSION_TYPE_UDP,
	SMCP_SESSION_TYPE_TCP,
	SMCP_SESSION_TYPE_DTLS,
	SMCP_SESSION_TYPE_TLS
} smcp_session_type_t;


SMCP_API_EXTERN bool smcp_session_type_supports_multicast(smcp_session_type_t session_type);

SMCP_API_EXTERN bool smcp_session_type_is_reliable(smcp_session_type_t session_type);

SMCP_INTERNAL_EXTERN smcp_session_type_t smcp_session_type_from_uri_scheme(const char* uri_scheme);

//!	Returns the default port number for the given session type.
SMCP_INTERNAL_EXTERN uint16_t smcp_default_port_from_session_type(smcp_session_type_t type);

/*!	@} */

__END_DECLS

#endif
