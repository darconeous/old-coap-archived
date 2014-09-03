/*!	@file smcp-async.h
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

#ifndef SMCP_smcp_async_h
#define SMCP_smcp_async_h

#include "smcp.h"

__BEGIN_DECLS

/*!	@addtogroup smcp
**	@{
*/

//struct smcp_session_s;
//
/*!	@defgroup smcp_async Asynchronous response support API
**	@{
*/

#define SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK		(1<<0)

struct smcp_async_response_s {
	smcp_sockaddr_t sockaddr_local;
	smcp_sockaddr_t sockaddr_remote;

	coap_size_t request_len;
	union {
		struct coap_header_s header;
		uint8_t bytes[80];
	} request;
};

typedef struct smcp_async_response_s* smcp_async_response_t;

SMCP_API_EXTERN bool smcp_inbound_is_related_to_async_response(struct smcp_async_response_s* x);

SMCP_API_EXTERN smcp_status_t smcp_start_async_response(struct smcp_async_response_s* x,int flags);

SMCP_API_EXTERN smcp_status_t smcp_finish_async_response(struct smcp_async_response_s* x);

SMCP_API_EXTERN smcp_status_t smcp_outbound_begin_async_response(coap_code_t code, struct smcp_async_response_s* x);

/*!	@} */


/*!	@} */

__END_DECLS

#endif
