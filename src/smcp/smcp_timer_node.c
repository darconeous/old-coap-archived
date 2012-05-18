
#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert_macros.h"
#include "smcp_timer.h"
#include "smcp_timer_node.h"

#include <stdio.h>
#include <stdlib.h>
#include "smcp.h"
#include "url-helpers.h"
#include "smcp_node.h"
#include <string.h>
#include <ctype.h>

#include "smcp_helpers.h"
#include "smcp_pairing.h"

#if __AVR__
PROGMEM
#endif
const char list_content[] =
    "<r>;n=\"Running\";rel=\"var\";ct=205,"
    "<r?v=1>;rel=\"action\";n=\"Start\","
    "<r?v=0>;rel=\"action\";n=\"Stop\","
    "<r?v=!v>;rel=\"action\";n=\"Toggle\","
    "<?rst>;n=\"Reset\";rel=\"action\","
    "<?rstrt>;n=\"Restart\";rel=\"action\","
    "<!f>;n=\"Trigger\";rel=\"event\","
    "<p>;n=\"Period\";rel=\"var\";ct=205,"
    "<rem>;n=\"Remaining\";rel=\"var\";ct=205,"
    "<arstrt>;n=\"Autorestart\";rel=\"var\";ct=205"
;


void
smcp_timer_node_dealloc(smcp_timer_node_t x) {
	free(x);
}

smcp_timer_node_t
smcp_timer_node_alloc() {
	smcp_timer_node_t ret =
	    (smcp_timer_node_t)calloc(sizeof(struct smcp_timer_node_s), 1);

	ret->node.finalize = (void (*)(smcp_node_t)) & smcp_timer_node_dealloc;
	return ret;
}

/*
smcp_status_t smcp_static_content_fetcher(
	void* context,
	char* content,
	size_t* content_length,
	coap_content_type_t* content_type
) {

	if(content_length && content) {
		*content_length = snprintf(content, *content_length, "v=%s", (char*)context);
	}
	if(content_type)
		*content_type = SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;

	return SMCP_STATUS_OK;
}
*/

#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
smcp_status_t smcp_timer_node_content_fetcher(
	smcp_timer_node_t self,
	char* content,
	size_t* content_length,
	coap_content_type_t* content_type
) {

	if(content_length && content) {
		*content_length = snprintf(content, *content_length, "count=%d", ++self->count);
	}
	if(content_type)
		*content_type = SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;

	return SMCP_STATUS_OK;
}
#endif

void smcp_timer_node_fired(
	smcp_daemon_t smcp, void* context
) {
	smcp_timer_node_t const self = context;

#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	smcp_daemon_trigger_custom_event_with_node(
		self,
		&self->node,
		"!f",
		(void*)&smcp_timer_node_content_fetcher,
		self
	);
#else
	smcp_daemon_trigger_custom_event_with_node(
		self,
		&self->node,
		"!f",
		NULL,
		NULL
	);
#endif

	if(self->autorestart) {
		smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);
		smcp_daemon_schedule_timer(
			smcp,
			&self->timer,
			self->period
		);
	} else {
		self->remaining = 0;
		smcp_daemon_trigger_event_with_node(
			smcp,
			&self->node,
			"r"
		);
	}
}

void smcp_timer_node_start(smcp_timer_node_t self) {
	smcp_daemon_t smcp = (smcp_daemon_t)smcp_node_get_root(&self->node);
	if(!smcp_daemon_timer_is_scheduled(smcp,
			&self->timer)) {
		smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);
		if(self->remaining)
			smcp_daemon_schedule_timer(smcp,
				&self->timer,
				self->remaining);
		else
			smcp_daemon_schedule_timer(smcp,
				&self->timer,
				self->period);
		smcp_daemon_trigger_event_with_node(
			smcp,
			&self->node,
			"r"
		);
	}
}

void smcp_timer_node_stop(smcp_timer_node_t self) {
	smcp_daemon_t smcp = (smcp_daemon_t)smcp_node_get_root(&self->node);
	if(smcp_daemon_timer_is_scheduled(smcp,
			&self->timer)) {
		self->remaining = convert_timeval_to_cms(&self->timer.fire_date);
		smcp_daemon_invalidate_timer(smcp, &self->timer);
		smcp_daemon_trigger_event_with_node(
			smcp,
			&self->node,
			"r"
		);
	}
}

void smcp_timer_node_toggle(smcp_timer_node_t self) {
	smcp_daemon_t smcp = (smcp_daemon_t)smcp_node_get_root(&self->node);
	if(smcp_daemon_timer_is_scheduled(smcp, &self->timer))
		smcp_timer_node_stop(self);
	else
		smcp_timer_node_start(self);
}

void smcp_timer_node_restart(smcp_timer_node_t self) {
	smcp_daemon_t smcp = (smcp_daemon_t)smcp_node_get_root(&self->node);
	bool previously_running = smcp_daemon_timer_is_scheduled(
		smcp,
		&self->timer
	);

	if(previously_running)
		smcp_timer_node_stop(self);

	self->remaining = self->period;
#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	self->count = 0;
#endif

	if(!previously_running) {
		smcp_timer_node_start(self);
	} else {
		smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);
		smcp_daemon_schedule_timer(smcp,
			&self->timer,
			self->period);
	}
}

void smcp_timer_node_reset(smcp_timer_node_t self) {
	smcp_daemon_t smcp = (smcp_daemon_t)smcp_node_get_root(&self->node);
	if(smcp_daemon_timer_is_scheduled(smcp,
			&self->timer) || self->remaining == 0)
		smcp_timer_node_restart(self);
	else
		self->remaining = self->period;
#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	self->count = 0;
#endif
}

int smcp_timer_node_get_remaining(smcp_timer_node_t self) {
	smcp_daemon_t smcp = (smcp_daemon_t)smcp_node_get_root(&self->node);
	if(smcp_daemon_timer_is_scheduled(smcp, &self->timer))
		return convert_timeval_to_cms(&self->timer.fire_date);
	return self->remaining;
}

void smcp_timer_node_set_autorestart(
	smcp_timer_node_t self, bool x
) {
	self->autorestart = x;
}

static smcp_status_t
smcp_timer_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = 0;
	const smcp_daemon_t self = smcp_get_current_daemon();
	coap_content_type_t content_type = smcp_inbound_get_content_type();
	char* query = NULL;
#if !HAS_ALLOCA
	char query_tmp[128];
#endif
	coap_option_key_t key;
	uint8_t* value;
	size_t value_len;

	enum {
		PATH_ROOT,
		PATH_RUNNING,
		PATH_FIRE,
		PATH_REMAINING,
		PATH_PERIOD,
		PATH_AUTORESTART,
	} path = PATH_ROOT;
	
	if(smcp_inbound_option_strequal(COAP_HEADER_URI_PATH,"r"))
		path = PATH_RUNNING;
	else if(smcp_inbound_option_strequal(COAP_HEADER_URI_PATH,"!f"))
		path = PATH_FIRE;
	else if(smcp_inbound_option_strequal(COAP_HEADER_URI_PATH,"rem"))
		path = PATH_REMAINING;
	else if(smcp_inbound_option_strequal(COAP_HEADER_URI_PATH,"p"))
		path = PATH_PERIOD;
	else if(smcp_inbound_option_strequal(COAP_HEADER_URI_PATH,"arstrt"))
		path = PATH_AUTORESTART;
	
	if(path!=PATH_ROOT)
		smcp_inbound_next_header(NULL,NULL);

	{
		while((key=smcp_inbound_next_header(&value, &value_len))!=COAP_HEADER_INVALID) {
			require_action(key!=COAP_HEADER_URI_PATH,bail,ret=SMCP_STATUS_NOT_FOUND);

			if(key == COAP_HEADER_URI_QUERY && ((value[0]=='v')||(value[0]=='r'))) {
#if HAS_ALLOCA
				query = alloca(value_len + 1);
#else
				query = query_tmp;
#endif
				memcpy(query, value, value_len);
				query[value_len] = 0;
			} else {
				require_action_string(
					!COAP_HEADER_IS_REQUIRED(key),
					bail,
					ret=SMCP_STATUS_BAD_OPTION,
					coap_option_key_to_cstr(key, false)
				);
			}
		}
	}

	if(	!query
		&& (content_type == SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED)
	) {
		query = (char*)smcp_inbound_get_content_ptr();
	}

	if(!query)
		query = "";

	// TODO: Clean this up!
	if(path==PATH_ROOT) {
		if((method == COAP_METHOD_PUT) || (method == COAP_METHOD_POST)) {
			if(strhasprefix_const(query, "rst")) {
				smcp_timer_node_reset((smcp_timer_node_t)node);
				smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
				smcp_outbound_send();
			} else if(strequal_const(query, "rstrt")) {
				smcp_timer_node_reset((smcp_timer_node_t)node);
				smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
				smcp_outbound_send();
			} else {
				ret = SMCP_STATUS_NOT_ALLOWED;
			}
		} else if(method == COAP_METHOD_GET) {
			ret = smcp_outbound_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			content_type = COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;
			ret = smcp_outbound_add_option(
				COAP_HEADER_CONTENT_TYPE,
				(const void*)&content_type,
				1
			);
			ret = smcp_outbound_set_content(list_content, COAP_HEADER_CSTR_LEN);
			ret = smcp_outbound_send();
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else if(path==PATH_RUNNING) {
		if(method == COAP_METHOD_GET) {
			int v = smcp_daemon_timer_is_scheduled(
				smcp_get_current_daemon(),
				&((smcp_timer_node_t)node)->timer
			);
			ret = smcp_outbound_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			ret = smcp_outbound_set_var_content_int(v);
			ret = smcp_outbound_send();
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			while(url_form_next_value((char**)&query, &key,
					&value) && key && value) {
				if(strequal_const(key, "v")) {
					if(isdigit(value[0])) {
						if(atoi(value))
							smcp_timer_node_start((smcp_timer_node_t)node);
						else
							smcp_timer_node_stop((smcp_timer_node_t)node);
					} else if(strequal_const(value, "!v")) {
						smcp_timer_node_toggle((smcp_timer_node_t)node);
					}
					smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
					smcp_outbound_send();
					break;
				}
			}
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else if(path==PATH_FIRE) {
		ret = SMCP_STATUS_NOT_ALLOWED;
	} else if(path==PATH_PERIOD) {
		if(method == COAP_METHOD_GET) {
			smcp_outbound_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_outbound_set_var_content_unsigned_long_int(((smcp_timer_node_t)node)->period);
			smcp_outbound_send();
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			while(
				url_form_next_value(
					(char**)&query,
					&key,
					&value
				)
				&& key
				&& value
			) {
				if(strequal_const(key, "v")) {
					((smcp_timer_node_t)node)->period = atoi(value);
					smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
					smcp_outbound_send();
					break;
				}
			}
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else if(path==PATH_REMAINING) {
		if(method == COAP_METHOD_GET) {
			smcp_outbound_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_outbound_set_var_content_int(smcp_timer_node_get_remaining((smcp_timer_node_t)node));
			smcp_outbound_send();
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			while(url_form_next_value((char**)&query, &key,
					&value) && key && value) {
				if(strequal_const(key, "v")) {
					    ((smcp_timer_node_t)node)->remaining = atoi(value);
					if(smcp_daemon_timer_is_scheduled(self,
							&((smcp_timer_node_t)node)->timer)) {
						smcp_daemon_invalidate_timer(self,
							&((smcp_timer_node_t)node)->timer);
						smcp_daemon_schedule_timer(self,
							&((smcp_timer_node_t)node)->timer,
							    ((smcp_timer_node_t)node)->remaining);
					}

					smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
					smcp_outbound_send();

					break;
				}
			}
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else if(path==PATH_AUTORESTART) {
		if(method == COAP_METHOD_GET) {
			smcp_outbound_begin_response(HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_CONTENT));
			smcp_outbound_set_var_content_int(((smcp_timer_node_t)node)->autorestart);
			smcp_outbound_send();
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			while(url_form_next_value((char**)&query, &key,
					&value) && key && value) {
				if(strequal_const(key, "v")) {
					((smcp_timer_node_t)node)->autorestart =
						!!atoi(value);

					smcp_outbound_begin_response(COAP_RESULT_204_CHANGED);
					smcp_outbound_send();

					ret = smcp_daemon_trigger_event_with_node(
						smcp_get_current_daemon(),
						node,
						"arstrt"
					);

					check_noerr(ret);

					break;
				}
			}
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
	} else {
		ret = smcp_default_request_handler(
			node,
			method
		);
		goto bail;
	}

bail:
	return ret;
}


smcp_timer_node_t
smcp_timer_node_init(
	smcp_timer_node_t	self,
	smcp_node_t			parent,
	const char*			name
) {
	require(self || (self = smcp_timer_node_alloc()), bail);

	self = (smcp_timer_node_t)smcp_node_init(&self->node,(void*)parent,name);

	require_string(self!=NULL, bail,"Node init failed.");

	((smcp_node_t)&self->node)->request_handler = &smcp_timer_request_handler;

	smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);

	self->autorestart = true;
	self->period = 5 * MSEC_PER_SEC;

bail:
	return self;
}
