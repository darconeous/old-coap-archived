/*!	@file smcp-auth.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Experimental authentication functions
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

#ifndef __SMCP_AUTH_H__
#define __SMCP_AUTH_H__ 1

#include "smcp.h"

__BEGIN_DECLS

/*!	@addtogroup smcp
**	@{
*/

/*!	@defgroup smcp-auth Authentication API
**	@{
**	@brief Experimental authentication interface
**
**	This is an experimental interface for handling both internal
**	(i.e. DIGEST-MD5) and external (i.e. DTLS) authentication. It
**	is a work in progress and is subject to change.
*/

#define	SMCP_AUTH_CRED_USERNAME		(0)
#define SMCP_AUTH_CRED_PASSWORD		(1)
#define SMCP_AUTH_CRED_DIGEST_HA1	(2)

#define SMCP_AUTH_MECH_NONE			(1<<0)
#define SMCP_AUTH_MECH_DIGEST		(1<<1)
#define SMCP_AUTH_MECH_DTLS			(1<<2)
#define SMCP_AUTH_MECH_ANY			(0xFF)

typedef uint8_t smcp_auth_mech_t;

#if SMCP_USE_EXPERIMENTAL_DIGEST_AUTH
struct smcp_auth_outbound_s {
};

struct smcp_auth_inbound_s {
	smcp_auth_mech_t mech;
	const char cn[64];
};

struct smcp_auth_transaction_s {
	smcp_auth_mech_t mech;
	const char* cn;
};
#endif

//////////////////////////////////////////////////
// Inbound Methods

extern smcp_status_t smcp_auth_inbound_init(smcp_t self);

extern const char* smcp_auth_inbound_get_username(smcp_t self);

//! Describes external authentication (e.g. DTLS)
/*!	Must be called between smcp_inbound_start_packet() and smcp_inbound_finish_packet().
**	@sa smcp-auth */
extern smcp_status_t smcp_inbound_set_ext_auth(
	smcp_t smcp,
	const char* cn,			//!< Common Name
	const char* mechanism	//!< Authentication Mechanism
);

//////////////////////////////////////////////////
// Outbound Methods

extern smcp_status_t smcp_auth_outbound_init(smcp_t self);

extern smcp_status_t smcp_auth_outbound_finalize(smcp_t self);

extern smcp_status_t smcp_auth_outbound_use_dtls(smcp_t self);

extern bool smcp_auth_outbound_is_using_dtls(smcp_t self);

extern smcp_status_t smcp_auth_outbound_set_credentials(smcp_t self, const char* username, const char* password);

//extern smcp_status_t smcp_auth_get_cred(
//	const char* realm,
//	const char* host,
//	const char* path,
//	int key,
//	uint8_t* value,
//	size_t value_size
//);

/*!	@} */

/*!	@addtogroup smcp-net
**	@{
*/

/*!	@} */

/*!	@} */

__END_DECLS

#endif // __SMCP_AUTH_H__
