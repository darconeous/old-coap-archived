/*	@file smcp-plat-ssl.h
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

#ifndef SMCP_smcp_plat_ssl_h
#define SMCP_smcp_plat_ssl_h

#include "smcp.h"

#define SMCP_PLAT_SSL_DEFAULT_CONTEXT		NULL

SMCP_API_EXTERN smcp_status_t smcp_plat_ssl_set_context(
	smcp_t self, void* context
);

SMCP_API_EXTERN void* smcp_plat_ssl_get_context(smcp_t self);

SMCP_API_EXTERN void smcp_plat_ssl_set_remote_hostname(const char* hostname);

SMCP_API_EXTERN smcp_status_t smcp_plat_ssl_inbound_packet_process(
	smcp_t self,
	char* buffer,
	int packet_length
);

SMCP_API_EXTERN smcp_status_t smcp_plat_ssl_outbound_packet_process(
	smcp_t self,
	const uint8_t* data_ptr,
	int data_len
);

#endif // SMCP_smcp_plat_ssl_h
