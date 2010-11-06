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
    "<running>;rel=\"var\";ct=205,"
    "<running?v=1>;rel=\"action\";n=\"Start\","
    "<running?v=0>;rel=\"action\";n=\"Stop\","
    "<running?v=!v>;rel=\"action\";n=\"Toggle\","
    "<?reset>;rel=\"action\","
    "<?restart>;rel=\"action\","
    "<!fire>;rel=\"event\","
    "<period>;rel=\"var\";ct=205,"
    "<remaining>;rel=\"var\";ct=205,"
    "<autorestart>;rel=\"var\";ct=205"
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


void smcp_timer_node_fired(
	smcp_daemon_t smcp, void* context
) {
	smcp_timer_node_t const self = context;

#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	char content[10];
	snprintf(content, sizeof(content), "count=%d", ++self->count);
	smcp_daemon_trigger_event_with_node(smcp,
		&self->node,
		"!fire",
		content,
		strlen(content),
		SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
#else
	smcp_daemon_trigger_event_with_node(smcp,
		&self->node,
		"!fire",
		NULL,
		0,
		0);
#endif

	if(self->autorestart) {
		smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);
		smcp_daemon_schedule_timer(self->smcpd_instance,
			&self->timer,
			self->period);
	} else {
		self->remaining = 0;
		smcp_daemon_trigger_event_with_node(self->smcpd_instance,
			&self->node,
			"running",
			"v=0",
			3,
			SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	}
}

void smcp_timer_node_start(smcp_timer_node_t self) {
	if(!smcp_daemon_timer_is_scheduled(self->smcpd_instance,
			&self->timer)) {
		smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);
		if(self->remaining)
			smcp_daemon_schedule_timer(self->smcpd_instance,
				&self->timer,
				self->remaining);
		else
			smcp_daemon_schedule_timer(self->smcpd_instance,
				&self->timer,
				self->period);
		smcp_daemon_trigger_event_with_node(self->smcpd_instance,
			&self->node,
			"running",
			"v=1",
			3,
			SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	}
}

void smcp_timer_node_stop(smcp_timer_node_t self) {
	if(smcp_daemon_timer_is_scheduled(self->smcpd_instance,
			&self->timer)) {
		self->remaining = convert_timeval_to_cms(&self->timer.fire_date);
		smcp_daemon_invalidate_timer(self->smcpd_instance, &self->timer);
		smcp_daemon_trigger_event_with_node(self->smcpd_instance,
			&self->node,
			"running",
			"v=0",
			3,
			SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);
	}
}

void smcp_timer_node_toggle(smcp_timer_node_t self) {
	if(smcp_daemon_timer_is_scheduled(self->smcpd_instance, &self->timer))
		smcp_timer_node_stop(self);
	else
		smcp_timer_node_start(self);
}

void smcp_timer_node_restart(smcp_timer_node_t self) {
	bool previously_running = smcp_daemon_timer_is_scheduled(
		self->smcpd_instance,
		&self->timer);

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
		smcp_daemon_schedule_timer(self->smcpd_instance,
			&self->timer,
			self->period);
	}
}

void smcp_timer_node_reset(smcp_timer_node_t self) {
	if(smcp_daemon_timer_is_scheduled(self->smcpd_instance,
			&self->timer) || self->remaining == 0)
		smcp_timer_node_restart(self);
	else
		self->remaining = self->period;
#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	self->count = 0;
#endif
}

int smcp_timer_node_get_remaining(smcp_timer_node_t self) {
	if(smcp_daemon_timer_is_scheduled(self->smcpd_instance, &self->timer))
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
	smcp_method_t	method,
	const char*		path,
	const char*		content,
	size_t			content_length
) {
	smcp_daemon_t self = smcp_get_current_daemon();
	smcp_status_t ret = 0;
	coap_header_item_t reply_headers[5] = {};
	coap_content_type_t content_type =
	    SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;
	char tmp_content[10];

	int reply_code = 0;
	const char* reply_content = NULL;
	size_t reply_content_len = 0;
	char* query = NULL;

	const coap_header_item_t *iter =
	    smcp_daemon_get_current_request_headers();
	const coap_header_item_t *end = iter +
	    smcp_daemon_get_current_request_header_count();

	for(; iter != end; ++iter) {
		if(iter->key == COAP_HEADER_CONTENT_TYPE) {
			content_type = *(unsigned char*)iter->value;
		} else if(iter->key == COAP_HEADER_URI_QUERY) {
			query = alloca(iter->value_len + 1);
			memcpy(query, iter->value, iter->value_len);
			query[iter->value_len] = 0;
		}
	}

	if(!query &&
	        (content_type == SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED))
		query = (char*)content;

	if(!query)
		query = "";

	// TODO: Clean this up!
	if(!path || path[0] == 0) {
		if((method == COAP_METHOD_PUT) || (method == COAP_METHOD_POST)) {
			if(strhasprefix_const(query, "reset")) {
				smcp_timer_node_reset((smcp_timer_node_t)node);
				reply_code = COAP_RESULT_CODE_OK;
			} else if(strequal_const(query, "restart")) {
				smcp_timer_node_reset((smcp_timer_node_t)node);
				reply_code = COAP_RESULT_CODE_OK;
			} else {
				reply_code = COAP_RESULT_CODE_METHOD_NOT_ALLOWED;
			}
		} else if((method == COAP_METHOD_GET)) {
			content_type = COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;
			util_add_header(
				reply_headers,
				sizeof(reply_headers) / sizeof(*reply_headers) - 1,
				COAP_HEADER_CONTENT_TYPE,
				    (const void*)&content_type,
				1
			);

			reply_code = COAP_RESULT_CODE_OK;

#if __AVR__
			// TODO: Make sure this actually works!
			reply_content = alloca(sizeof(list_content));
			assert(reply_content);
			strcpy_P((char*)reply_content, list_content);
#else
			reply_content = list_content;
#endif
			reply_content_len = sizeof(list_content) - 1;
		} else {
			reply_code = COAP_RESULT_CODE_METHOD_NOT_ALLOWED;
		}
	} else if(strhasprefix_const(path, "running")) {
		if((method == COAP_METHOD_GET)) {
			reply_code = COAP_RESULT_CODE_OK;
			reply_content_len = 3;
			if(smcp_daemon_timer_is_scheduled(smcp_get_current_daemon(),
					&((smcp_timer_node_t)node)->timer))
				reply_content = "v=1";
			else
				reply_content = "v=0";
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			reply_code = COAP_RESULT_CODE_OK;
			while(url_form_next_value((char**)&query, &key,
					&value) && key && value) {
				if(strequal_const(key, "v")) {
					if(isdigit(value[0])) {
						if(strtol(value, NULL, 0))
							smcp_timer_node_start((smcp_timer_node_t)node);
						else
							smcp_timer_node_stop((smcp_timer_node_t)node);
						reply_code = COAP_RESULT_CODE_OK;
					} else if(strequal_const(value, "!v")) {
						smcp_timer_node_toggle((smcp_timer_node_t)node);
						reply_code = COAP_RESULT_CODE_OK;
					}
					break;
				}
			}
		} else if(method == COAP_METHOD_PAIR) {
			ret = smcp_default_request_handler(
				node,
				method,
				path,
				content,
				content_length
			    );
			goto bail;
		} else {
			reply_code = COAP_RESULT_CODE_METHOD_NOT_ALLOWED;
		}
	} else if(strequal_const(path, "!fire")) {
		if((method == COAP_METHOD_PAIR)) {
			ret = smcp_default_request_handler(
				node,
				method,
				path,
				content,
				content_length
			    );
			goto bail;
		} else {
			reply_code = COAP_RESULT_CODE_METHOD_NOT_ALLOWED;
		}
	} else if(strhasprefix_const(path, "period")) {
		if((method == COAP_METHOD_GET)) {
			snprintf(tmp_content, sizeof(tmp_content), "v=%lu",
				    (long unsigned int)((smcp_timer_node_t)node)->period);
			reply_code = COAP_RESULT_CODE_OK;
			reply_content = tmp_content;
			reply_content_len = strlen(tmp_content);
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			reply_code = COAP_RESULT_CODE_OK;
			while(url_form_next_value((char**)&query, &key,
					&value) && key && value) {
				if(strequal_const(key, "v")) {
					    ((smcp_timer_node_t)node)->period = strtol(value,
						NULL,
						0);
					reply_code = COAP_RESULT_CODE_OK;
					break;
				}
			}
		} else {
			reply_code = COAP_RESULT_CODE_METHOD_NOT_ALLOWED;
		}
	} else if(strhasprefix_const(path, "remaining")) {
		if((method == COAP_METHOD_GET)) {
			snprintf(tmp_content,
				sizeof(tmp_content),
				"v=%d",
				smcp_timer_node_get_remaining((smcp_timer_node_t)node));
			reply_code = COAP_RESULT_CODE_OK;
			reply_content = tmp_content;
			reply_content_len = strlen(tmp_content);
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			reply_code = COAP_RESULT_CODE_OK;
			while(url_form_next_value((char**)&query, &key,
					&value) && key && value) {
				if(strequal_const(key, "v")) {
					    ((smcp_timer_node_t)node)->remaining = strtol(
						value,
						NULL,
						0);
					if(smcp_daemon_timer_is_scheduled(self,
							&((smcp_timer_node_t)node)->timer)) {
						smcp_daemon_invalidate_timer(self,
							&((smcp_timer_node_t)node)->timer);
						smcp_daemon_schedule_timer(self,
							&((smcp_timer_node_t)node)->timer,
							    ((smcp_timer_node_t)node)->remaining);
					}
					reply_code = COAP_RESULT_CODE_OK;

					break;
				}
			}
		} else {
			reply_code = COAP_RESULT_CODE_METHOD_NOT_ALLOWED;
		}
	} else if(strhasprefix_const(path, "autorestart")) {
		if((method == COAP_METHOD_GET)) {
			reply_code = COAP_RESULT_CODE_OK;
			reply_content_len = 3;
			if(((smcp_timer_node_t)node)->autorestart)
				reply_content = "v=1";
			else
				reply_content = "v=0";
		} else if((method == COAP_METHOD_PUT) ||
		        (method == COAP_METHOD_POST)) {
			char* key = NULL;
			char* value = NULL;
			reply_code = COAP_RESULT_CODE_OK;
			while(url_form_next_value((char**)&query, &key,
					&value) && key && value) {
				if(strequal_const(key, "v")) {
					    ((smcp_timer_node_t)node)->autorestart = !!strtol(
						value,
						NULL,
						10);
					reply_code = COAP_RESULT_CODE_OK;
					break;
				}
			}
		} else if((method == COAP_METHOD_PAIR)) {
			ret = smcp_default_request_handler(
				node,
				method,
				path,
				content,
				content_length
			    );
			goto bail;
		} else {
			reply_code = COAP_RESULT_CODE_METHOD_NOT_ALLOWED;
		}
	} else {
		ret = smcp_default_request_handler(
			node,
			method,
			path,
			content,
			content_length
		    );
		goto bail;
	}

	if(reply_code) {
		smcp_daemon_send_response(reply_code,
			reply_headers,
			reply_content,
			reply_content_len);
	}

bail:
	return ret;
}


smcp_timer_node_t
smcp_timer_node_init(
	smcp_timer_node_t	self,
	smcp_daemon_t		smcp,
	smcp_node_t			parent,
	const char*			name
) {
	require(self || (self = smcp_timer_node_alloc()), bail);

	require(smcp_node_init(
			&self->node,
			    (void*)parent,
			name
		), bail);

	    ((smcp_node_t)&self->node)->request_handler =
	    &smcp_timer_request_handler;

	smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);

	self->autorestart = true;
	self->period = 5 * MSEC_PER_SEC;
	self->smcpd_instance = smcp;

bail:
	return self;
}
