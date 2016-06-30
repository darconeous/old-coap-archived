/*	@file smcp-pairing.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert-macros.h"
#include "smcp.h"

#if SMCP_CONF_MAX_PAIRINGS > 0

#include "smcp-internal.h"
#include "smcp-logging.h"
#include "smcp-pairing.h"
#include "url-helpers.h"
#include "string-utils.h"

enum {
	I_STABLE,
	I_ENABLED,
	I_CONTENT_TYPE,
	I_LOCAL_PATH,
	I_REMOTE_URL,
	I_CODE,
	I_FIRE_COUNT,
	I_COUNT
};

static const char* names[I_COUNT] = {
	[I_STABLE] = "s",
	[I_ENABLED] = "e",
	[I_CONTENT_TYPE] = "t",
	[I_LOCAL_PATH] = "l",
	[I_REMOTE_URL] = "r",
	[I_CODE] = "c",
	[I_FIRE_COUNT] = "f",
};

static const char* lf_title[I_COUNT] = {
	[I_STABLE] = "stable",
	[I_ENABLED] = "enabled",
	[I_CONTENT_TYPE] = "content-type",
	[I_LOCAL_PATH] = "local-path",
	[I_REMOTE_URL] = "remote-url",
	[I_CODE] = "last-code",
	[I_FIRE_COUNT] = "fire-count",
};

smcp_pairing_mgr_t
smcp_pairing_mgr_init(
	smcp_pairing_mgr_t self,
	smcp_t smcp_instance
) {
	memset(self, 0, sizeof(*self));

	self->smcp_instance = smcp_instance;

	return self;
}

static smcp_pairing_mgr_t
pairing_mgr_from_pairing(smcp_pairing_t pairing) {
	return (smcp_pairing_mgr_t)((uint8_t*)&pairing[-pairing->index]-sizeof(struct smcp_observable_s));
}

static void
smcp_pairing_mgr_commit_stable(
	smcp_pairing_mgr_t self
) {
	if (self->commit_stable_pairings != NULL) {
		(*self->commit_stable_pairings)(self->context, self);
	}
}

bool
smcp_pairing_get_stable(smcp_pairing_t self)
{
	return self->stable;
}

smcp_status_t
smcp_pairing_set_stable(smcp_pairing_t self, bool x)
{
	smcp_pairing_mgr_t mgr = pairing_mgr_from_pairing(self);
	if (x != self->stable) {
		self->stable = x;

		smcp_pairing_mgr_commit_stable(mgr);
		smcp_observable_trigger(&self->var_handler.observable, I_STABLE, 0);
	}

	return SMCP_STATUS_OK;
}

bool
smcp_pairing_get_enabled(smcp_pairing_t self)
{
	return self->enabled;
}

smcp_status_t
smcp_pairing_set_enabled(smcp_pairing_t self, bool x)
{
	smcp_status_t status = SMCP_STATUS_OK;
	smcp_pairing_mgr_t mgr = pairing_mgr_from_pairing(self);

	if (x != self->enabled) {
		self->enabled = x;

		if (self->stable) {
			smcp_pairing_mgr_commit_stable(mgr);
		}

		if (self->enabled) {
			status = smcp_transaction_begin(
				mgr->smcp_instance,
				&self->transaction,
				30 * MSEC_PER_SEC
			);

		} else {
			status = smcp_transaction_end(
				mgr->smcp_instance,
				&self->transaction
			);
		}
		smcp_observable_trigger(&self->var_handler.observable, I_ENABLED, 0);
	}

	return SMCP_STATUS_OK;
}

coap_content_type_t
smcp_pairing_get_content_type(smcp_pairing_t self)
{
	return self->content_type;
}

smcp_status_t
smcp_pairing_set_content_type(smcp_pairing_t self, coap_content_type_t x)
{
	smcp_pairing_mgr_t mgr = pairing_mgr_from_pairing(self);

	if (x != self->content_type) {
		self->content_type = x;

		if (self->stable) {
			smcp_pairing_mgr_commit_stable(mgr);
		}

		smcp_observable_trigger(&self->var_handler.observable, I_CONTENT_TYPE, 0);
	}

	return SMCP_STATUS_OK;
}





smcp_pairing_type_t
smcp_pairing_get_type(smcp_pairing_t self)
{
	return self->type;
}

smcp_status_t
smcp_pairing_set_type(smcp_pairing_t self, smcp_pairing_type_t x)
{
	smcp_pairing_mgr_t mgr = pairing_mgr_from_pairing(self);

	if (x != self->type) {
		// Only pull is currently supported
		if (x != SMCP_PAIRING_TYPE_PULL) {
			return SMCP_STATUS_NOT_IMPLEMENTED;
		}

		if (self->enabled) {
			// TODO: Handle the transition from self->type to x.
		}

		self->type = x;

		if (self->stable) {
			smcp_pairing_mgr_commit_stable(mgr);
		}
	}

	return SMCP_STATUS_OK;
}

uint8_t
smcp_pairing_get_id(smcp_pairing_t self)
{
	return self->index;
}

const char*
smcp_pairing_get_local_path(smcp_pairing_t self)
{
	return self->local_path;
}

const char*
smcp_pairing_get_remote_url(smcp_pairing_t self)
{
	return self->remote_url;
}

static smcp_status_t
pairing_response_handler_callback(int statuscode, smcp_pairing_t pairing)
{
	smcp_status_t ret = SMCP_STATUS_OK;
	smcp_t const smcp_instance = smcp_get_current_instance();

	if ( pairing->last_code != statuscode
	  && statuscode != SMCP_STATUS_TRANSACTION_INVALIDATED
	) {
		pairing->last_code = statuscode;
		smcp_observable_trigger(&pairing->var_handler.observable, I_CODE, 0);
	}

	if (statuscode > 0) {
		pairing->fire_count++;
		smcp_observable_trigger(&pairing->var_handler.observable, I_FIRE_COUNT, 0);
	}

	if (statuscode == COAP_RESULT_205_CONTENT) {
		// Store all of our state on the stack so that
		// we can restore it after we handle the fake
		// POST request.
		bool did_respond = smcp_instance->did_respond;
		bool is_fake = smcp_instance->inbound.is_fake;
		const struct coap_header_s*	packet = smcp_instance->inbound.packet;
		coap_size_t packet_len = smcp_instance->inbound.packet_len;
		const smcp_sockaddr_t remote_sockaddr = *smcp_plat_get_remote_sockaddr();

		// Indicate that this packet is synthesized.
		smcp_instance->inbound.is_fake = true;

		// Indicate that we have already responded so that
		// the handler doesn't attempt to send its own response.
		smcp_instance->did_respond = true;

		// Update the msg_id on our fake packet so that
		// duplicate detection works properly.
		pairing->request.header.msg_id = packet->msg_id;

		// Make the remote address appear to be local in origin.
		smcp_plat_set_remote_sockaddr(smcp_plat_get_local_sockaddr());

		// Set up our fake packet header+options.
		smcp_instance->inbound.packet = &pairing->request.header;
		smcp_instance->inbound.packet_len = pairing->request_len;
		smcp_inbound_reset_next_option();

		if (smcp_inbound_get_content_type() == SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED) {
			char* key = NULL;
			char* value = NULL;
			smcp_instance->inbound.content_len = 0;
			while(
				url_form_next_value(
					(char**)&smcp_instance->inbound.content_ptr,
					&key,
					&value
				)
				&& key
				&& value
			) {
				if (strequal_const(key, "v")) {
					smcp_instance->inbound.content_ptr = value;
					smcp_instance->inbound.content_len = (coap_size_t)strlen(value);
					break;
				}
			}
		}

		// Handle our fake request.
		ret = smcp_handle_request();

		check_noerr(ret);

		// Restore everything.
		smcp_plat_set_remote_sockaddr(&remote_sockaddr);
		smcp_instance->inbound.is_fake = is_fake;
		smcp_instance->did_respond = did_respond;
		smcp_instance->inbound.packet = packet;
		smcp_instance->inbound.packet_len = packet_len;
	}

	ret = SMCP_STATUS_OK;

	return ret;
}

static smcp_status_t
pairing_resend_callback(smcp_pairing_t pairing)
{
	smcp_status_t status = 0;

	status = smcp_outbound_begin(smcp_get_current_instance(), COAP_METHOD_GET, COAP_TRANS_TYPE_CONFIRMABLE);

	require_noerr(status, bail);

	status = smcp_outbound_set_uri(pairing->remote_url, 0);

	require_noerr(status, bail);

	if (pairing->content_type != COAP_CONTENT_TYPE_UNKNOWN) {
		smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, pairing->content_type);
	}

	status = smcp_outbound_send();

bail:
	return status;
}

static smcp_status_t
smcp_paring_variable_handler(
	smcp_variable_handler_t node,
	uint8_t action,
	uint8_t i,
	char* value
) {
	smcp_status_t ret = SMCP_STATUS_OK;
	smcp_pairing_t pairing = (smcp_pairing_t)node;

	if (i >= I_COUNT) {
		ret = SMCP_STATUS_NOT_FOUND;
		goto bail;
	}

	if (action == SMCP_VAR_GET_KEY) {
		strcpy(value, names[i]);

	} else if (action == SMCP_VAR_GET_LF_TITLE) {
		strcpy(value, lf_title[i]);

	} else if (action == SMCP_VAR_GET_OBSERVABLE) {
		switch (i) {
		case I_STABLE:
		case I_ENABLED:
		case I_CONTENT_TYPE:
		case I_FIRE_COUNT:
		case I_CODE:
			ret = SMCP_STATUS_OK;
			break;
		case I_LOCAL_PATH:
		case I_REMOTE_URL:
			ret = SMCP_STATUS_NOT_IMPLEMENTED;
			break;
		}

	} else if (action == SMCP_VAR_GET_VALUE) {
		switch (i) {
		case I_STABLE:
			int32_to_dec_cstr(value, pairing->stable);
			break;
		case I_ENABLED:
			int32_to_dec_cstr(value, pairing->enabled);
			break;
		case I_CONTENT_TYPE:
			int32_to_dec_cstr(value, pairing->content_type);
			break;
		case I_CODE:
			int32_to_dec_cstr(value, (pairing->last_code > 0)?COAP_TO_HTTP_CODE(pairing->last_code):pairing->last_code);
			break;
		case I_FIRE_COUNT:
			int32_to_dec_cstr(value, pairing->fire_count);
			break;
		case I_LOCAL_PATH:
			strcpy(value, pairing->local_path);
			break;
		case I_REMOTE_URL:
			strcpy(value, pairing->remote_url);
			break;
		}

	} else if (action == SMCP_VAR_SET_VALUE) {
		switch (i) {
		case I_STABLE:
			ret = smcp_pairing_set_stable(pairing, str2bool(value));
			break;
		case I_ENABLED:
			ret = smcp_pairing_set_enabled(pairing, str2bool(value));
			break;
		case I_FIRE_COUNT:
			pairing->fire_count = 0;
			break;

		case I_CODE:
		case I_CONTENT_TYPE:
		case I_LOCAL_PATH:
		case I_REMOTE_URL:
			ret = SMCP_STATUS_NOT_IMPLEMENTED;
			break;
		}

	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

bail:
	return ret;
}

smcp_pairing_t
smcp_pairing_mgr_new_pairing(
	smcp_pairing_mgr_t self,
	const char* local_path_arg,
	const char* remote_url,
	uint8_t i
) {
	smcp_pairing_t ret = NULL;
	uint8_t j;
	assert(self != NULL);
	assert(local_path_arg != NULL);
	assert(remote_url != NULL);

	// Find a free slot, using the given `i` as an
	// initial suggestion.
	if ( (i >= SMCP_CONF_MAX_PAIRINGS)
	  || self->pairing_table[i].in_use
	) {
		for (i = 0; i < SMCP_CONF_MAX_PAIRINGS; i++) {
			if (!self->pairing_table[i].in_use) {
				break;
			}
		}
	}

	require(i < SMCP_CONF_MAX_PAIRINGS, bail);

	// Check for duplicates.
	for (j = 0; j < SMCP_CONF_MAX_PAIRINGS; j++) {
		if (!self->pairing_table[j].in_use) {
			break;
		}
		if ( (0 == strcmp(local_path_arg, self->pairing_table[j].local_path))
		  && (0 == strcmp(remote_url, self->pairing_table[j].remote_url))
		) {
			// A pairing already exists for this local path and remote url.
			goto bail;
		}
	}

	ret = &self->pairing_table[i];

	ret->index = i;
	ret->in_use = true;
	ret->enabled = false;
	ret->stable = false;
	ret->type = SMCP_PAIRING_TYPE_PULL;
	ret->content_type = COAP_CONTENT_TYPE_UNKNOWN;
	ret->var_handler.func = smcp_paring_variable_handler;

	ret->request.header.version = COAP_VERSION;
	ret->request.header.tt = COAP_TRANS_TYPE_NONCONFIRMABLE;
	ret->request.header.token_len = 0;
	ret->request.header.code = COAP_METHOD_POST;
	ret->request_len = sizeof(ret->request.header);

	strlcpy(ret->local_path, local_path_arg, sizeof(ret->local_path));

	// TODO: Rewrite this to properly handle query components!
	{
		char* local_path = ret->local_path;
		const bool has_trailing_slash = local_path[0]?('/' == local_path[strlen(local_path)-1]):false;
		uint8_t* options_end = ret->request.header.token;
		char* component = NULL;

		// Move past any preceding slashes.
		while (local_path[0] == '/') {
			local_path++;
		}

		while (url_path_next_component(&local_path,&component)) {
			// TODO: SECURITY: Add bounds check!
			coap_ssize_t added_len = coap_insert_option(
				(uint8_t*)ret->request.header.token + ret->request.header.token_len,
				(uint8_t*)options_end,
				COAP_OPTION_URI_PATH,
				(const uint8_t*)component,
				(coap_size_t)strlen(component)
			);

			options_end += added_len;
			ret->request_len += added_len;
		}

		if (has_trailing_slash) {
			coap_ssize_t added_len = coap_insert_option(
				(uint8_t*)ret->request.header.token + ret->request.header.token_len,
				(uint8_t*)options_end,
				COAP_OPTION_URI_PATH,
				(const uint8_t*)"",
				0
			);

			options_end += added_len;
			ret->request_len += added_len;
		}

		*options_end++ = 0xFF;
		ret->request_len++;
	}

	strlcpy(ret->local_path, local_path_arg, sizeof(ret->local_path));
	strlcpy(ret->remote_url, remote_url, sizeof(ret->remote_url));

	smcp_transaction_init(
		&ret->transaction,
		SMCP_TRANSACTION_ALWAYS_INVALIDATE
		| SMCP_TRANSACTION_OBSERVE
		| SMCP_TRANSACTION_NO_AUTO_END
		| SMCP_TRANSACTION_DELAY_START
		| SMCP_TRANSACTION_KEEPALIVE,
		(smcp_inbound_resend_func)&pairing_resend_callback,
		(smcp_response_handler_func)&pairing_response_handler_callback,
		ret
	);

bail:
	return ret;
}

void
smcp_pairing_mgr_delete(
	smcp_pairing_mgr_t self,
	smcp_pairing_t pairing
) {
	assert(self != NULL);

	// Make sure that prev is actually pointing to
	// something in the pairing table.
	assert(pairing >= self->pairing_table);
	assert(pairing < &self->pairing_table[SMCP_CONF_MAX_PAIRINGS]);

	smcp_pairing_set_stable(pairing, 0);
	smcp_pairing_set_enabled(pairing, 0);

	pairing->in_use = false;
}

smcp_pairing_t
smcp_pairing_mgr_pairing_begin(
	smcp_pairing_mgr_t self
) {
	smcp_pairing_t ret = NULL;
	int i;

	assert(self != NULL);

	for (i = 0; i < SMCP_CONF_MAX_PAIRINGS; i++) {
		if (self->pairing_table[i].in_use) {
			break;
		}
	}

	if (i < SMCP_CONF_MAX_PAIRINGS) {
		ret = &self->pairing_table[i];
	}

	return ret;
}

smcp_pairing_t
smcp_pairing_mgr_pairing_next(
	smcp_pairing_mgr_t self,
	smcp_pairing_t prev
) {
	assert(self != NULL);

	// Make sure that prev is actually pointing to
	// something in the pairing table.
	assert(prev >= self->pairing_table);
	assert(prev < &self->pairing_table[SMCP_CONF_MAX_PAIRINGS]);

	for (prev++; prev < &self->pairing_table[SMCP_CONF_MAX_PAIRINGS]; prev++) {
		if (prev->in_use) {
			break;
		}
	}

	if (prev >= &self->pairing_table[SMCP_CONF_MAX_PAIRINGS]) {
		prev = NULL;
	}

	return prev;
}

static char
get_hex_char(int x) {
	return "0123456789abcdef"[x&0xF];
}

static smcp_status_t
request_handler_get_listing_(
	smcp_pairing_mgr_t self
) {
	smcp_status_t ret = 0;
	int i;
	char name_str[3] = { };

	// Fetching the pairing table.
	ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(ret, bail);

	ret = smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);
	require_noerr(ret, bail);

	for (i = 0; i < SMCP_CONF_MAX_PAIRINGS; i++) {
		if (!self->pairing_table[i].in_use) {
			continue;
		}
		name_str[0] = get_hex_char(i >> 4);
		name_str[1] = get_hex_char(i >> 0);

		smcp_outbound_append_content("<", SMCP_CSTR_LEN);
		smcp_outbound_append_content(name_str, SMCP_CSTR_LEN);

		smcp_outbound_append_content("/>;ct=40;obs,", SMCP_CSTR_LEN);

#if SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
		smcp_outbound_append_content("\n", SMCP_CSTR_LEN);
#endif
	}

	ret = smcp_outbound_send();

bail:
	return ret;
}

static smcp_status_t
request_handler_new_pairing_(
	smcp_pairing_mgr_t self
) {
	smcp_status_t ret = SMCP_STATUS_OK;
	coap_content_type_t content_type;
	coap_size_t content_len;
	char* local_path = NULL;
	char* remote_url = NULL;
	char* content_ptr = NULL;
	char* key = NULL;
	char* value = NULL;
	smcp_pairing_t pairing = NULL;
	char name_str[3] = { };

	content_type = smcp_inbound_get_content_type();
	content_ptr = (char*)smcp_inbound_get_content_ptr();
	content_len = smcp_inbound_get_content_len();

	switch (content_type) {
	case COAP_CONTENT_TYPE_UNKNOWN:
	case COAP_CONTENT_TYPE_TEXT_PLAIN:
	case SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED:
		content_len = 0;
		while(
			url_form_next_value(
				(char**)&content_ptr,
				&key,
				&value
			)
			&& key
			&& value
		) {
			if (strequal_const(key, "r")) {
				remote_url = value;
				DEBUG_PRINTF("new_pairing: remote_url=\"%s\"", remote_url);
			} else if (strequal_const(key, "l")) {
				local_path = value;
				DEBUG_PRINTF("new_pairing: local_path=\"%s\"", local_path);
			}
		}
		break;

	default:
		return smcp_outbound_quick_response(HTTP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE, NULL);
		break;
	}

	pairing = smcp_pairing_mgr_new_pairing(
		self,
		local_path,
		remote_url,
		0
	);

	if (!pairing) {
		return smcp_outbound_quick_response(COAP_RESULT_400_BAD_REQUEST, "(400) Failed to create pairing");
	}

	name_str[0] = get_hex_char(pairing->index >> 4);
	name_str[1] = get_hex_char(pairing->index >> 0);

	smcp_outbound_begin_response(COAP_RESULT_201_CREATED);
	smcp_outbound_add_option(COAP_OPTION_LOCATION_PATH, name_str, SMCP_CSTR_LEN);
	smcp_outbound_append_content(name_str, SMCP_CSTR_LEN);
	smcp_outbound_send();

bail:
	return ret;
}

smcp_status_t
smcp_pairing_mgr_request_handler(
	smcp_pairing_mgr_t self
) {
	smcp_status_t ret = 0;
	const smcp_method_t method = smcp_inbound_get_code();
	coap_option_key_t key;
	const uint8_t* value;
	coap_size_t value_len;
	smcp_pairing_t pairing;
	bool missing_trailing_slash = false;

	if (smcp_inbound_next_option(&value, &value_len) != COAP_OPTION_URI_PATH) {
		missing_trailing_slash = true;
	}

	if (value_len == 0) {
		// listing pairings

		if (method == COAP_METHOD_GET) {
			if (missing_trailing_slash) {
				return smcp_outbound_quick_response(COAP_RESULT_400_BAD_REQUEST, "(400) Needs trailing slash");
			}
			return request_handler_get_listing_(self);

		} else if (method == COAP_METHOD_POST) {
			return request_handler_new_pairing_(self);

		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
			goto bail;
		}

	} else if (value_len == 2) {
		// Query on a specific pairing.
		const char str[3] = {value[0], value[1], 0};
		int i;

		errno = 0;

#if HAVE_STRTOL
		i = strtol(str, NULL, 16);
#else
		i = atoi(str); // TODO: This isn't base16!
#endif

		if (errno) {
			ret = SMCP_STATUS_NOT_FOUND;
			goto bail;
		}
		pairing = &self->pairing_table[i];

		key = smcp_inbound_peek_option(&value, &value_len);

		if ( (i < 0)
		  || (i >= SMCP_CONF_MAX_PAIRINGS)
		  || (!pairing->in_use)
		) {
			ret = SMCP_STATUS_NOT_FOUND;
			goto bail;
		}

		if (key != COAP_OPTION_URI_PATH) {
			value_len = 0;
		}

		if ( (method == COAP_METHOD_GET)
		  || (method == COAP_METHOD_PUT)
		  || (method == COAP_METHOD_POST)
		  || ( (method == COAP_METHOD_DELETE) && (value_len > 0) )
		) {
			// hand off handling of this to variable node.
			return smcp_variable_handler_request_handler(&pairing->var_handler);

		} else if (method == COAP_METHOD_DELETE) {
			// Delete this pairing.
			smcp_pairing_mgr_delete(self, pairing);
			return smcp_outbound_quick_response(COAP_RESULT_202_DELETED, NULL);
		}

	} else {
		ret = SMCP_STATUS_NOT_FOUND;
	}

bail:
	return ret;
}

#endif // SMCP_CONF_MAX_PAIRINGS > 0
