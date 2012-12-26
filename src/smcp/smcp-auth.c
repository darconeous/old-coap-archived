/*	@file smcp-auth.c
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

#include "assert_macros.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "smcp-internal.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"
#include "smcp-auth.h"
#include "smcp.h"
#include "ll.h"
#include "url-helpers.h"

#if CONTIKI
#include "contiki.h"
#include "net/uip-udp-packet.h"
#include "net/uiplib.h"
#include "net/tcpip.h"
#include "net/resolv.h"
extern uint16_t uip_slen;
#endif

// COAP_OPTION_AUTHENTICATE

#define SMCP_AUTH_SCHEME_CUSTOM			(0x00)
#define SMCP_AUTH_SCHEME_BASIC			(0x01)
#define SMCP_AUTH_SCHEME_DIGEST			(0x02)
#define SMCP_AUTH_SCHEME_SASL			(0x03)
#define SMCP_AUTH_SCHEME_NEGOTIATE		(0x04)
#define SMCP_AUTH_SCHEME_NTLM			(0x05)

#define SMCP_AUTH_PARAM_KEY_CUSTOM		(0x00)

#define SMCP_AUTH_PARAM_KEY_REALM		(0x01)
#define SMCP_AUTH_PARAM_KEY_USERNAME	(0x02)
#define SMCP_AUTH_PARAM_KEY_NONCE		(0x03)
#define SMCP_AUTH_PARAM_KEY_RESPONSE	(0x04)
#define SMCP_AUTH_PARAM_KEY_OPAQUE		(0x05)
#define SMCP_AUTH_PARAM_KEY_CNONCE		(0x06)
#define SMCP_AUTH_PARAM_KEY_NC			(0x07)
#define SMCP_AUTH_PARAM_KEY_URI			(0x08)
#define SMCP_AUTH_PARAM_KEY_QOP			(0x09)
#define SMCP_AUTH_PARAM_KEY_STALE		(0x0a)
#define SMCP_AUTH_PARAM_KEY_RSPAUTH		(0x11)
#define SMCP_AUTH_PARAM_KEY_NEXTNONCE	(0x12)

#define SMCP_AUTH_PARAM_KEY_CHALLENGE	(0x0b)
#define SMCP_AUTH_PARAM_KEY_MECHANISMS	(0x0c)
#define SMCP_AUTH_PARAM_KEY_ID			(0x0d)
#define SMCP_AUTH_PARAM_KEY_CREDENTIALS	(0x0e)
#define SMCP_AUTH_PARAM_KEY_BLOB_BASE16	(0x0f)
#define SMCP_AUTH_PARAM_KEY_BLOB_BASE64	(0x10)


#define SMCP_AUTH_VALTYPE_LITERAL		(0x0)
#define SMCP_AUTH_VALTYPE_INTEGER		(0x1)
#define SMCP_AUTH_VALTYPE_BLOB_BASE16	(0x2)
#define SMCP_AUTH_VALTYPE_BLOB_BASE64	(0x3)


// -------------------------------------------

#ifndef SMCP_AUTH_DIGEST_NONCE_LENGTH
#define SMCP_AUTH_DIGEST_NONCE_LENGTH	8
#endif

#ifndef SMCP_AUTH_DIGEST_USERNAME_LENGTH
#define SMCP_AUTH_DIGEST_USERNAME_LENGTH	15
#endif

#ifndef SMCP_AUTH_DIGEST_NONCE_TABLE_SIZE
#define SMCP_AUTH_DIGEST_NONCE_TABLE_SIZE	8
#endif

struct smcp_auth_user_s {
	struct smcp_auth_user_s* next;
	char username[SMCP_AUTH_DIGEST_USERNAME_LENGTH+1];
	fasthash_hash_t ha1;
};

struct smcp_auth_nonce_s {
	struct smcp_auth_user_s* user;
	uint8_t nonce[SMCP_AUTH_DIGEST_NONCE_LENGTH];
	uint32_t nc;
	time_t nonce_expiration;
};

typedef struct smcp_auth_user_s* smcp_auth_user_t;
typedef struct smcp_auth_nonce_s* smcp_auth_nonce_t;

static smcp_auth_user_t current_outbound_user;
static smcp_auth_nonce_t current_outbound_nonce;

static struct smcp_auth_user_s global_temp_auth_user;
static struct smcp_auth_nonce_s global_nonce_table[SMCP_AUTH_DIGEST_NONCE_TABLE_SIZE];

// -------------------------------------------

//static uint8_t value_type_for_key(uint8_t key) {
//	static uint8_t lookup[] = {
//		[SMCP_AUTH_PARAM_KEY_CUSTOM]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_REALM]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_USERNAME]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_NONCE]=SMCP_AUTH_VALTYPE_BLOB_BASE16,
//		[SMCP_AUTH_PARAM_KEY_RESPONSE]=SMCP_AUTH_VALTYPE_BLOB_BASE16,
//		[SMCP_AUTH_PARAM_KEY_OPAQUE]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_CNONCE]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_NC]=SMCP_AUTH_VALTYPE_INTEGER,
//		[SMCP_AUTH_PARAM_KEY_URI]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_QOP]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_CHALLENGE]=SMCP_AUTH_VALTYPE_BLOB_BASE64,
//		[SMCP_AUTH_PARAM_KEY_MECHANISMS]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_ID]=SMCP_AUTH_VALTYPE_LITERAL,
//		[SMCP_AUTH_PARAM_KEY_CREDENTIALS]=SMCP_AUTH_VALTYPE_BLOB_BASE64,
//		[SMCP_AUTH_PARAM_KEY_BLOB_BASE16]=SMCP_AUTH_VALTYPE_BLOB_BASE16,
//		[SMCP_AUTH_PARAM_KEY_BLOB_BASE64]=SMCP_AUTH_VALTYPE_BLOB_BASE64,
//	};
//	if(key<(sizeof(lookup)/sizeof(*lookup)))
//		return lookup[key];
//	return 0;
//}

smcp_auth_user_t
smcp_auth_get_remote_user(const char* username) {
	return NULL;
}

void
smcp_auth_user_set(smcp_auth_user_t auth_user,const char* username,const char* password,const char* realm) {
	strlcpy(auth_user->username,username,sizeof(auth_user->username));

	fasthash_start(0);
	fasthash_feed((const uint8_t*)auth_user->username, strlen(auth_user->username));
	fasthash_feed_byte(':');
	fasthash_feed((const uint8_t*)realm, strlen(realm));
	fasthash_feed_byte(':');
	fasthash_feed((const uint8_t*)password, strlen(password));
	auth_user->ha1 = fasthash_finish();
}


smcp_status_t
smcp_auth_get_cred(
	const char* realm,
	const char* url,
	int key,
	uint8_t* value,
	size_t value_size
) {
	// TODO: Writeme!
	return SMCP_STATUS_NOT_IMPLEMENTED;
}

smcp_status_t
smcp_auth_verify_request() {
	smcp_status_t ret = SMCP_STATUS_OK;
	coap_option_key_t key;
	const uint8_t* authvalue;
	size_t authvalue_len;

	// For testing purposes only!
	if(smcp_inbound_get_packet()->code >1 && smcp_inbound_get_packet()->code<COAP_RESULT_100) {
		ret = SMCP_STATUS_UNAUTHORIZED;
	}

	while((key = smcp_inbound_next_option(&authvalue,&authvalue_len))!=COAP_OPTION_INVALID) {
		if(key==COAP_OPTION_PROXY_URI) {
			// For testing purposes only!
			ret = SMCP_STATUS_OK;
		}
		if(key==COAP_OPTION_AUTHENTICATE) {
			// For testing purposes only!
			ret = SMCP_STATUS_OK;
			// writeme!
		}
	}

	if(smcp_inbound_origin_is_local()) {
		ret = SMCP_STATUS_OK;
	}

	ret = SMCP_STATUS_OK;

	// For testing purposes only!
	if(ret==SMCP_STATUS_UNAUTHORIZED) {
		smcp_outbound_begin_response(COAP_RESULT_401_UNAUTHORIZED);
		smcp_outbound_add_option(COAP_OPTION_AUTHENTICATE,NULL,0);
		smcp_outbound_send();
	}

	return ret;
}

smcp_status_t
smcp_auth_handle_response(smcp_transaction_t transaction) {
	// TODO: Writeme!
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_auth_add_options() {
	// TODO: Writeme!
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_auth_outbound_finish() {
	// This method is for updating the response values in the authenticate
	// header, if it needs to be updated for digest-auth-int.

	// TODO: Writeme!

	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_auth_outbound_set_credentials(const char* username, const char* password) {
	smcp_status_t ret = SMCP_STATUS_OK;

	// TODO: Writeme!
	smcp_auth_user_t auth_user = smcp_auth_get_remote_user(username);
	struct smcp_auth_nonce_s *auth_nonce;

	if(!auth_user) {
		require(username,bail);
		require(password,bail);

		auth_user = &global_temp_auth_user;

		smcp_auth_user_set(auth_user,username,password,"");
	}

	// Just do something stupid for now.
	ret = smcp_outbound_add_option(COAP_OPTION_AUTHENTICATE, NULL, 0);

bail:
	return ret;
}

const char*
smcp_auth_get_username() {
	// TODO: Writeme!
	return NULL;
}
