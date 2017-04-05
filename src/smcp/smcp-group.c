/*	@file smcp-group.c
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
#include <libnyoci/libnyoci.h>
#include "smcp.h"

#if SMCP_CONF_MAX_GROUPS > 0

#include "smcp-group.h"
#include <libnyoci/nyoci-internal.h>
#include <libnyoci/nyoci-logging.h>
#include <libnyoci/url-helpers.h>
#include <libnyoci/string-utils.h>

enum {
	I_STABLE,
	I_ENABLED,
	I_FQDN,
	I_ADDR,
	I_COUNT,
};

static const char* names[I_COUNT] = {
	[I_STABLE] = "s",
	[I_ENABLED] = "e",
	[I_FQDN] = "n",
	[I_ADDR] = "a",
};

static const char* lf_title[I_COUNT] = {
	[I_STABLE] = "stable",
	[I_ENABLED] = "enabled",
	[I_FQDN] = "fqdn",
	[I_ADDR] = "address",
};

smcp_group_mgr_t
smcp_group_mgr_init(
	smcp_group_mgr_t self,
	nyoci_t nyoci_instance
) {
	memset(self, 0, sizeof(*self));

#if !NYOCI_SINGLETON
	self->nyoci_instance = nyoci_instance;
#endif

	return self;
}

static smcp_group_mgr_t
group_mgr_from_group(smcp_group_t group) {
	return (smcp_group_mgr_t)((uint8_t*)&group[-group->index]-sizeof(struct nyoci_observable_s));
}

static void
smcp_group_mgr_commit_stable(
	smcp_group_mgr_t self
) {
	if (self->commit_stable_groups != NULL) {
		(*self->commit_stable_groups)(self->context, self);
	}
}

bool
smcp_group_get_stable(smcp_group_t self)
{
	return self->stable;
}

nyoci_status_t
smcp_group_set_stable(smcp_group_t self, bool x)
{
	smcp_group_mgr_t mgr = group_mgr_from_group(self);
	if (x != self->stable) {
		self->stable = x;

		smcp_group_mgr_commit_stable(mgr);
		nyoci_observable_trigger(&self->var_handler.observable, I_STABLE, 0);
	}

	return NYOCI_STATUS_OK;
}

bool
smcp_group_get_enabled(smcp_group_t self)
{
	return self->enabled;
}

nyoci_status_t
smcp_group_set_enabled(smcp_group_t self, bool x)
{
	nyoci_status_t status = NYOCI_STATUS_OK;
	smcp_group_mgr_t mgr = group_mgr_from_group(self);
#if NYOCI_SINGLETON
	nyoci_t const nyoci_instance = nyoci_get_current_instance();
#else
	nyoci_t const nyoci_instance = mgr->nyoci_instance;
#endif

	if (x != self->enabled) {
		self->enabled = x;

		if (self->stable) {
			smcp_group_mgr_commit_stable(mgr);
		}

		if (self->enabled) {
			if (NYOCI_IS_ADDR_UNSPECIFIED(&self->addr.nyoci_addr)) {
				status = nyoci_plat_lookup_hostname(self->fqdn, &self->addr, NYOCI_LOOKUP_HOSTNAME_FLAG_DEFAULT);
			}

			if (status == NYOCI_STATUS_OK) {
				status = nyoci_plat_multicast_join(nyoci_instance, &self->addr, 0);
			}
		} else {
			status = nyoci_plat_multicast_leave(nyoci_instance, &self->addr, 0);
		}
		nyoci_observable_trigger(&self->var_handler.observable, I_ENABLED, 0);
	}

	return status;
}

uint8_t
smcp_group_get_id(smcp_group_t self)
{
	return self->index;
}

const char*
smcp_group_get_fqdn(smcp_group_t self)
{
	return self->fqdn;
}

const nyoci_sockaddr_t*
smcp_group_get_addr(smcp_group_t self)
{
	return &self->addr;
}


static nyoci_status_t
smcp_group_variable_handler(
	nyoci_var_handler_t node,
	uint8_t action,
	uint8_t i,
	char* value
) {
	nyoci_status_t ret = NYOCI_STATUS_OK;
	smcp_group_t group = (smcp_group_t)node;

	if (i >= I_COUNT) {
		ret = NYOCI_STATUS_NOT_FOUND;
		goto bail;
	}

	if (action == NYOCI_VAR_GET_KEY) {
		strcpy(value, names[i]);

	} else if (action == NYOCI_VAR_GET_LF_TITLE) {
		strcpy(value, lf_title[i]);

	} else if (action == NYOCI_VAR_GET_OBSERVABLE) {
		switch (i) {
		case I_STABLE:
		case I_ENABLED:
			ret = NYOCI_STATUS_OK;
			break;
		case I_FQDN:
		case I_ADDR:
			ret = NYOCI_STATUS_NOT_IMPLEMENTED;
			break;
		}

	} else if (action == NYOCI_VAR_GET_VALUE) {
		switch (i) {
		case I_STABLE:
			int32_to_dec_cstr(value, group->stable);
			break;
		case I_ENABLED:
			int32_to_dec_cstr(value, group->enabled);
			break;
		case I_FQDN:
			strcpy(value, group->fqdn);
			break;
		case I_ADDR:
			NYOCI_ADDR_NTOP(value, NYOCI_VARIABLE_MAX_VALUE_LENGTH, &group->addr.nyoci_addr);
			break;
		}

	} else if (action == NYOCI_VAR_SET_VALUE) {
		switch (i) {
		case I_STABLE:
			ret = smcp_group_set_stable(group, str2bool(value));
			break;
		case I_ENABLED:
			ret = smcp_group_set_enabled(group, str2bool(value));
			break;
		case I_FQDN:
		case I_ADDR:
			ret = NYOCI_STATUS_NOT_IMPLEMENTED;
			break;
		}

	} else {
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
	}

bail:
	return ret;
}

smcp_group_t
smcp_group_mgr_new_group(
	smcp_group_mgr_t self,
	const char* fqdn,
	const nyoci_sockaddr_t* addr,
	uint8_t i
) {
	smcp_group_t ret = NULL;
	uint8_t j;
	assert(self != NULL);
	assert(fqdn != NULL);

	// Find a free slot, using the given `i` as an
	// initial suggestion.
	if ( (i >= SMCP_CONF_MAX_GROUPS)
	  || self->group_table[i].in_use
	) {
		for (i = 0; i < SMCP_CONF_MAX_GROUPS; i++) {
			if (!self->group_table[i].in_use) {
				break;
			}
		}
	}

	require(i < SMCP_CONF_MAX_GROUPS, bail);

	// Check for duplicates.
	for (j = 0; j < SMCP_CONF_MAX_GROUPS; j++) {
		if (!self->group_table[j].in_use) {
			break;
		}
		if ( (0 == strcmp(fqdn, self->group_table[j].fqdn))) {
			// This group already exists.
			goto bail;
		}
	}

	ret = &self->group_table[i];

	ret->index = i;
	ret->in_use = true;
	ret->enabled = false;
	ret->stable = false;
	ret->var_handler.func = smcp_group_variable_handler;

	{
		const nyoci_sockaddr_t x = NYOCI_SOCKADDR_INIT;
		ret->addr = x;
	}

	strlcpy(ret->fqdn, fqdn, sizeof(ret->fqdn));

	if (addr != NULL) {
		ret->addr = *addr;
	} else {
		nyoci_plat_lookup_hostname(ret->fqdn, &ret->addr, NYOCI_LOOKUP_HOSTNAME_FLAG_DEFAULT);
	}

bail:
	return ret;
}

void
smcp_group_mgr_delete(
	smcp_group_mgr_t self,
	smcp_group_t group
) {
	assert(self != NULL);

	// Make sure that prev is actually pointing to
	// something in the group table.
	assert(group >= self->group_table);
	assert(group < &self->group_table[SMCP_CONF_MAX_GROUPS]);

	smcp_group_set_stable(group, false);
	smcp_group_set_enabled(group, false);

	group->in_use = false;
}

smcp_group_t
smcp_group_mgr_groups_begin(
	smcp_group_mgr_t self
) {
	smcp_group_t ret = NULL;
	int i;

	assert(self != NULL);

	for (i = 0; i < SMCP_CONF_MAX_GROUPS; i++) {
		if (self->group_table[i].in_use) {
			break;
		}
	}

	if (i < SMCP_CONF_MAX_GROUPS) {
		ret = &self->group_table[i];
	}

	return ret;
}

smcp_group_t
smcp_group_mgr_groups_next(
	smcp_group_mgr_t self,
	smcp_group_t prev
) {
	assert(self != NULL);

	// Make sure that prev is actually pointing to
	// something in the group table.
	assert(prev >= self->group_table);
	assert(prev < &self->group_table[SMCP_CONF_MAX_GROUPS]);

	for (prev++; prev < &self->group_table[SMCP_CONF_MAX_GROUPS]; prev++) {
		if (prev->in_use) {
			break;
		}
	}

	if (prev >= &self->group_table[SMCP_CONF_MAX_GROUPS]) {
		prev = NULL;
	}

	return prev;
}

static char
get_hex_char(int x) {
	return "0123456789abcdef"[x & 0xF];
}

static nyoci_status_t
request_handler_get_listing_(
	smcp_group_mgr_t self
) {
	nyoci_status_t ret = 0;
	int i;
	char name_str[3] = { };

	// Fetching the group table.
	ret = nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(ret, bail);

	ret = nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);
	require_noerr(ret, bail);

	for (i = 0; i < SMCP_CONF_MAX_GROUPS; i++) {
		if (!self->group_table[i].in_use) {
			continue;
		}
		name_str[0] = get_hex_char(i >> 4);
		name_str[1] = get_hex_char(i >> 0);

		nyoci_outbound_append_content("<", NYOCI_CSTR_LEN);
		nyoci_outbound_append_content(name_str, NYOCI_CSTR_LEN);

		nyoci_outbound_append_content("/>;ct=40;obs,", NYOCI_CSTR_LEN);

#if NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT
		nyoci_outbound_append_content("\n", NYOCI_CSTR_LEN);
#endif
	}

	ret = nyoci_outbound_send();

bail:
	return ret;
}

static nyoci_status_t
request_handler_new_group_(
	smcp_group_mgr_t self
) {
	nyoci_status_t ret = NYOCI_STATUS_OK;
	coap_content_type_t content_type;
	coap_size_t content_len;
	char* fqdn = NULL;
	char* addr_cstr = NULL;
	nyoci_sockaddr_t saddr = { };
	char* content_ptr = NULL;
	char* key = NULL;
	char* value = NULL;
	smcp_group_t group = NULL;
	char name_str[3] = { };

	content_type = nyoci_inbound_get_content_type();
	content_ptr = (char*)nyoci_inbound_get_content_ptr();
	content_len = nyoci_inbound_get_content_len();

	switch (content_type) {
	case COAP_CONTENT_TYPE_UNKNOWN:
	case COAP_CONTENT_TYPE_TEXT_PLAIN:
	case NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED:
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

			if (strequal_const(key, names[I_FQDN])) {
				fqdn = value;
				DEBUG_PRINTF("new_group: fqdn=\"%s\"", value);
			} else if (strequal_const(key, names[I_ADDR])) {
				addr_cstr = value;
				DEBUG_PRINTF("new_group: addr=\"%s\"", value);
			}
		}
		break;

	default:
		return nyoci_outbound_quick_response(HTTP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE, NULL);
		break;
	}

	if (NULL == addr_cstr) {
		require_action(NULL != fqdn, bail, ret = NYOCI_STATUS_INVALID_ARGUMENT);
		addr_cstr = fqdn;
	} else if (NULL == fqdn) {
		fqdn = addr_cstr;
	}

	nyoci_plat_lookup_hostname(addr_cstr, &saddr, NYOCI_LOOKUP_HOSTNAME_FLAG_DEFAULT);

	group = smcp_group_mgr_new_group(
		self,
		fqdn,
		&saddr,
		0
	);

	if (!group) {
		return nyoci_outbound_quick_response(COAP_RESULT_400_BAD_REQUEST, "(400) Failed to create group");
	}

	// Default to enabled.
	smcp_group_set_enabled(group, true);

	name_str[0] = get_hex_char(group->index >> 4);
	name_str[1] = get_hex_char(group->index >> 0);

	nyoci_outbound_begin_response(COAP_RESULT_201_CREATED);
	nyoci_outbound_add_option(COAP_OPTION_LOCATION_PATH, name_str, NYOCI_CSTR_LEN);
	nyoci_outbound_append_content(name_str, NYOCI_CSTR_LEN);
	nyoci_outbound_send();

bail:
	return ret;
}

nyoci_status_t
smcp_group_mgr_request_handler(
	smcp_group_mgr_t self
) {
	nyoci_status_t ret = 0;
	const coap_code_t method = nyoci_inbound_get_code();
	coap_option_key_t key;
	const uint8_t* value;
	coap_size_t value_len;
	smcp_group_t group;
	bool missing_trailing_slash = false;

	if (nyoci_inbound_next_option(&value, &value_len) != COAP_OPTION_URI_PATH) {
		missing_trailing_slash = true;
	}

	if (value_len == 0) {
		// listing groups

		if (method == COAP_METHOD_GET) {
			if (missing_trailing_slash) {
				return nyoci_outbound_quick_response(COAP_RESULT_400_BAD_REQUEST, "(400) Needs trailing slash");
			}
			return request_handler_get_listing_(self);

		} else if (method == COAP_METHOD_POST) {
			return request_handler_new_group_(self);

		} else {
			ret = NYOCI_STATUS_NOT_ALLOWED;
			goto bail;
		}

	} else if (value_len == 2) {
		// Query on a specific group.
		const char str[3] = {value[0], value[1], 0};
		int i;

		errno = 0;

#if HAVE_STRTOL
		i = strtol(str, NULL, 16);
#else
		i = atoi(str); // TODO: This isn't base16!
#endif

		if (errno) {
			ret = NYOCI_STATUS_NOT_FOUND;
			goto bail;
		}
		group = &self->group_table[i];

		key = nyoci_inbound_peek_option(&value, &value_len);

		if ( (i < 0)
		  || (i >= SMCP_CONF_MAX_GROUPS)
		  || (!group->in_use)
		) {
			ret = NYOCI_STATUS_NOT_FOUND;
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
			return nyoci_var_handler_request_handler(&group->var_handler);

		} else if (method == COAP_METHOD_DELETE) {
			// Delete this group.
			smcp_group_mgr_delete(self, group);
			return nyoci_outbound_quick_response(COAP_RESULT_202_DELETED, NULL);
		}

	} else {
		ret = NYOCI_STATUS_NOT_FOUND;
	}

bail:
	return ret;
}

#endif // SMCP_CONF_MAX_GROUPS > 0
