#include "assert_macros.h"
#include "smcp_timer.h"
#include "smcp_timer_node.h"

#include <stdio.h>
#include <stdlib.h>
#include "smcp.h"
#include "url-helpers.h"
#include "smcp_node.h"
#include <string.h>

//////////////////////////////////////////////////////////////////

/*
    reset = smcp_node_init_action(NULL,(void*)ret, "reset");
    smcp_node_init_variable(NULL,(void*)ret, "period");
    smcp_node_init_variable(NULL,(void*)ret, "auto-reset");
    smcp_node_init_action(NULL,(void*)ret, "start");
    smcp_node_init_event(NULL,(void*)ret, "fire");
 */
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

static const char list_content[] =
    "<running>,\n"
    "<running?v=1>;n=\"Start\",\n"
    "<running?v=0>;n=\"Stop\",\n"
    "<?reset>,\n"
    "<!fire>,\n"
    "<period>,\n"
    "<remaining>,\n"
    "<auto-restart>,\n"
;


void smcp_timer_node_fired(
	smcp_daemon_t smcp, void* context
) {
	smcp_timer_node_t self = context;
	smcp_status_t status;
	char path[128];

	memset(path, 0, sizeof(path));

	status = smcp_node_get_path(&self->node, path, sizeof(path));

	check_string(!status, smcp_status_to_cstr(status));

	printf("Timer \"%s\" fired.\n", path);

	strncat(path, "!fire", sizeof(path) - 1);

	status = smcp_daemon_trigger_event(
		smcp,
		path,
		NULL,   // const char* content,
		0,      // size_t content_length,
		0       // smcp_content_type_t content_type
	    );

	check_string(!status, smcp_status_to_cstr(status));

	if(self->autorestart)
		smcp_timer_node_reset(self);
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
	}
}

void smcp_timer_node_stop(smcp_timer_node_t self) {
	if(smcp_daemon_timer_is_scheduled(self->smcpd_instance,
			&self->timer)) {
		self->remaining = convert_timeval_to_cms(&self->timer.fire_date);
		smcp_daemon_invalidate_timer(self->smcpd_instance, &self->timer);
	}
}

void smcp_timer_node_toggle(smcp_timer_node_t self) {
	if(smcp_daemon_timer_is_scheduled(self->smcpd_instance, &self->timer))
		smcp_timer_node_stop(self);
	else
		smcp_timer_node_start(self);
}

void smcp_timer_node_reset(smcp_timer_node_t self) {
	smcp_timer_node_stop(self);
	self->remaining = self->period;
	smcp_timer_node_start(self);
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
	smcp_daemon_t		self,
	smcp_node_t			node,
	smcp_method_t		method,
	const char*			path,
	coap_header_item_t	headers[],
	const char*			content,
	size_t				content_length
) {
	smcp_status_t ret = 0;
	coap_header_item_t reply_headers[5] = {};
	smcp_content_type_t content_type =
	    SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;

	coap_header_item_t *next_header;

	for(next_header = headers;
	    smcp_header_item_get_key(next_header);
	    next_header = smcp_header_item_next(next_header)) {
		if(smcp_header_item_key_equal(next_header, COAP_HEADER_TOKEN))
			reply_headers[0] = *next_header;
		else if(smcp_header_item_key_equal(next_header,
				COAP_HEADER_CONTENT_TYPE))
			content_type = *(unsigned char*)smcp_header_item_get_value(
				next_header);
	}

	if(0 == strcmp(path, "")) {
		switch(method) {
		case SMCP_METHOD_GET:
			content_type = SMCP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;
			util_add_header(
				reply_headers,
				SMCP_MAX_HEADERS,
				COAP_HEADER_CONTENT_TYPE,
				    (const void*)&content_type,
				1
			);

			smcp_daemon_send_response(
				self,
				SMCP_RESULT_CODE_OK,
				reply_headers,
				list_content,
				sizeof(list_content) - 1
			);

			break;
		default:
			break;
		}
	} else if(0 == strcmp(path, "running")) {
		if((method == SMCP_METHOD_GET)) {
			char content[10];
			snprintf(content,
				sizeof(content),
				"v=%d",
				smcp_timer_node_get_remaining((smcp_timer_node_t)node));
			if(smcp_daemon_timer_is_scheduled(self,
					&((smcp_timer_node_t)node)->timer)) {
				smcp_daemon_send_response(self,
					SMCP_RESULT_CODE_OK,
					reply_headers,
					"v=1",
					3);
			} else {
				smcp_daemon_send_response(self,
					SMCP_RESULT_CODE_OK,
					reply_headers,
					"v=0",
					3);
			}
		} else if((method == SMCP_METHOD_PUT) ||
		        (method == SMCP_METHOD_POST)) {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_NOT_IMPLEMENTED,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else if(0 == strcmp(path, "running?v=1")) { // Start
		if((method == SMCP_METHOD_PUT) || (method == SMCP_METHOD_POST)) {
			smcp_timer_node_start((smcp_timer_node_t)node);
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_OK,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else if(0 == strcmp(path, "running?v=0")) { // Stop
		if((method == SMCP_METHOD_PUT) || (method == SMCP_METHOD_POST)) {
			smcp_timer_node_stop((smcp_timer_node_t)node);
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_OK,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else if(0 == strcmp(path, "running?toggle")) { // Toggle
		if((method == SMCP_METHOD_PUT) || (method == SMCP_METHOD_POST)) {
			smcp_timer_node_start((smcp_timer_node_t)node);
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_OK,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else if(0 == strcmp(path, "?reset")) {
		if((method == SMCP_METHOD_PUT) || (method == SMCP_METHOD_POST)) {
			smcp_timer_node_reset((smcp_timer_node_t)node);
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_OK,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else if(0 == strcmp(path, "!fire")) {
		smcp_daemon_send_response(self,
			SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
			reply_headers,
			NULL,
			0);
	} else if(0 == strcmp(path, "period")) {
		if((method == SMCP_METHOD_GET)) {
			char content[10];
			snprintf(content, sizeof(content), "v=%d",
				    ((smcp_timer_node_t)node)->period);
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_OK,
				reply_headers,
				content,
				strlen(content));
		} else if((method == SMCP_METHOD_PUT) ||
		        (method == SMCP_METHOD_POST)) {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_NOT_IMPLEMENTED,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else if(0 == strcmp(path, "remaining")) {
		if((method == SMCP_METHOD_GET)) {
			char content[10];
			snprintf(content,
				sizeof(content),
				"v=%d",
				smcp_timer_node_get_remaining((smcp_timer_node_t)node));
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_OK,
				reply_headers,
				content,
				strlen(content));
		} else if((method == SMCP_METHOD_PUT) ||
		        (method == SMCP_METHOD_POST)) {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_NOT_IMPLEMENTED,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else if(0 == strcmp(path, "auto-restart")) {
		if((method == SMCP_METHOD_GET)) {
			if(((smcp_timer_node_t)node)->autorestart) {
				smcp_daemon_send_response(self,
					SMCP_RESULT_CODE_OK,
					reply_headers,
					"v=1",
					3);
			} else {
				smcp_daemon_send_response(self,
					SMCP_RESULT_CODE_OK,
					reply_headers,
					"v=0",
					3);
			}
		} else if((method == SMCP_METHOD_PUT) ||
		        (method == SMCP_METHOD_POST)) {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_NOT_IMPLEMENTED,
				reply_headers,
				NULL,
				0);
		} else {
			smcp_daemon_send_response(self,
				SMCP_RESULT_CODE_METHOD_NOT_ALLOWED,
				reply_headers,
				NULL,
				0);
		}
	} else {
		ret = smcp_default_request_handler(
			self,
			node,
			method,
			path,
			headers,
			content,
			content_length
		    );
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

	require(smcp_node_init_subdevice(
			&self->node,
			    (void*)parent,
			name
		), bail);

	    ((smcp_device_node_t)&self->node)->unhandled_request =
	    &smcp_timer_request_handler;

	smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);

	self->autorestart = true;
	self->period = 15 * MSEC_PER_SEC;
	self->smcpd_instance = smcp;

bail:
	return self;
}
