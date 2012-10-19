/*	@file smcp_timer_node.c
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

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert_macros.h"
#include "smcp-opts.h"
#include "smcp-timer.h"
#include "smcp-timer_node.h"

#include <stdio.h>
#include <stdlib.h>
#include "smcp.h"
#include "url-helpers.h"
#include "smcp-node.h"
#include <string.h>
#include <ctype.h>

#include "smcp-helpers.h"
#include "smcp-pairing.h"

void
smcp_timer_node_dealloc(smcp_timer_node_t x) {
	free(x);
}

smcp_timer_node_t
smcp_timer_node_alloc() {
	smcp_timer_node_t ret =
	    (smcp_timer_node_t)calloc(sizeof(struct smcp_timer_node_s), 1);

	ret->node.node.finalize = (void (*)(smcp_node_t)) & smcp_timer_node_dealloc;
	return ret;
}

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
	smcp_t smcp, void* context
) {
	smcp_timer_node_t const self = context;

#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	smcp_trigger_custom_event_with_node(
		&self->node.node,
		"!f",
		(void*)&smcp_timer_node_content_fetcher,
		self
	);
#else
	smcp_trigger_custom_event_with_node(
		&self->node.node,
		"!f",
		NULL,
		NULL
	);
#endif

	if(self->autorestart) {
		smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);
		smcp_schedule_timer(
			smcp,
			&self->timer,
			self->period
		);
	} else {
		self->remaining = 0;
		smcp_trigger_event_with_node(
			smcp,
			&self->node.node,
			"r"
		);
	}
}

void smcp_timer_node_start(smcp_timer_node_t self) {
	smcp_t smcp = (smcp_t)smcp_node_get_root(&self->node.node);
	if(!smcp_timer_is_scheduled(smcp,
			&self->timer)) {
		smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);
		if(self->remaining)
			smcp_schedule_timer(smcp,
				&self->timer,
				self->remaining);
		else
			smcp_schedule_timer(smcp,
				&self->timer,
				self->period);
		smcp_trigger_event_with_node(
			smcp,
			&self->node.node,
			"r"
		);
		smcp_trigger_event_with_node(
			smcp,
			&self->node.node,
			"r!v=1"
		);
	}
}

void smcp_timer_node_stop(smcp_timer_node_t self) {
	smcp_t smcp = (smcp_t)smcp_node_get_root(&self->node.node);
	if(smcp_timer_is_scheduled(smcp,
			&self->timer)) {
		self->remaining = convert_timeval_to_cms(&self->timer.fire_date);
		smcp_invalidate_timer(smcp, &self->timer);
		smcp_trigger_event_with_node(
			smcp,
			&self->node.node,
			"r"
		);
		smcp_trigger_event_with_node(
			smcp,
			&self->node.node,
			"r!v=0"
		);
	}
}

void smcp_timer_node_toggle(smcp_timer_node_t self) {
	smcp_t smcp = (smcp_t)smcp_node_get_root(&self->node.node);
	if(smcp_timer_is_scheduled(smcp, &self->timer))
		smcp_timer_node_stop(self);
	else
		smcp_timer_node_start(self);
}

void smcp_timer_node_restart(smcp_timer_node_t self) {
	smcp_t smcp = (smcp_t)smcp_node_get_root(&self->node.node);
	bool previously_running = smcp_timer_is_scheduled(
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
		smcp_schedule_timer(smcp,
			&self->timer,
			self->period);
	}
}

void smcp_timer_node_reset(smcp_timer_node_t self) {
	smcp_t smcp = (smcp_t)smcp_node_get_root(&self->node.node);
	if(smcp_timer_is_scheduled(smcp,
			&self->timer) || self->remaining == 0)
		smcp_timer_node_restart(self);
	else
		self->remaining = self->period;
#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	self->count = 0;
#endif
}

int smcp_timer_node_get_remaining(smcp_timer_node_t self) {
	smcp_t smcp = (smcp_t)smcp_node_get_root(&self->node.node);
	if(smcp_timer_is_scheduled(smcp, &self->timer))
		return convert_timeval_to_cms(&self->timer.fire_date);
	return self->remaining;
}

void smcp_timer_node_set_autorestart(
	smcp_timer_node_t self, bool x
) {
	self->autorestart = x;
}

static smcp_status_t
timer_node_var_func(
	smcp_variable_node_t node,
	uint8_t action,
	uint8_t path,
	char* value
) {
	smcp_status_t ret = 0;
	enum {
		PATH_RUNNING=0,
		PATH_FIRE,
		PATH_REMAINING,
		PATH_PERIOD,
		PATH_AUTORESTART,
		PATH_RESTART,

		PATH_COUNT,
	};

	if(path>=PATH_COUNT) {
		ret = SMCP_STATUS_NOT_FOUND;
	} else if(action==SMCP_VAR_GET_KEY) {
		static const char* path_names[] = {
			"r",
			"!f",
			"rem",
			"p",
			"arstrt",
			"rstrt"
		};
		strcpy(value,path_names[path]);
	} else if(action==SMCP_VAR_GET_VALUE) {
		int v = 0;
		if(path==PATH_RUNNING) {
			v = smcp_timer_is_scheduled(
				smcp_get_current_instance(),
				&((smcp_timer_node_t)node)->timer
			);
		} else if(path==PATH_FIRE) {
			ret = SMCP_STATUS_NOT_ALLOWED;
		} else if(path==PATH_REMAINING) {
			v = smcp_timer_node_get_remaining((smcp_timer_node_t)node);
		} else if(path==PATH_PERIOD) {
			v = ((smcp_timer_node_t)node)->period;
		} else if(path==PATH_AUTORESTART) {
			v = ((smcp_timer_node_t)node)->autorestart;
		} else {
			ret = SMCP_STATUS_NOT_ALLOWED;
		}
		sprintf(value,"%d",v);
	} else if(action==SMCP_VAR_SET_VALUE) {
		if(path==PATH_RUNNING) {
			if(isdigit(value[0])) {
				if(atoi(value))
					smcp_timer_node_start((smcp_timer_node_t)node);
				else
					smcp_timer_node_stop((smcp_timer_node_t)node);
			} else if(strequal_const(value, "!v")) {
				smcp_timer_node_toggle((smcp_timer_node_t)node);
			}
		} else if(path==PATH_FIRE) {
			ret = SMCP_STATUS_NOT_ALLOWED;
		} else if(path==PATH_REMAINING) {
			const smcp_t const self = smcp_get_current_instance();
			((smcp_timer_node_t)node)->remaining = atoi(value);
			if(smcp_timer_is_scheduled(self, &((smcp_timer_node_t)node)->timer)) {
				smcp_invalidate_timer(self,&((smcp_timer_node_t)node)->timer);
				ret = smcp_schedule_timer(
					self,
					&((smcp_timer_node_t)node)->timer,
					((smcp_timer_node_t)node)->remaining
				);
			}
		} else if(path==PATH_PERIOD) {
			((smcp_timer_node_t)node)->period = atoi(value);
		} else if(path==PATH_RESTART) {
				smcp_timer_node_restart((smcp_timer_node_t)node);
		} else if(path==PATH_AUTORESTART) {
			((smcp_timer_node_t)node)->autorestart = atoi(value);
		}
	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

	return ret;
}

smcp_timer_node_t
smcp_timer_node_init(
	smcp_timer_node_t	self,
	smcp_node_t			parent,
	const char*			name
) {
	require(self || (self = smcp_timer_node_alloc()), bail);

	self = (smcp_timer_node_t)smcp_variable_node_init(&self->node,(void*)parent,name);

	require_string(self!=NULL, bail,"Node init failed.");

	self->node.func = &timer_node_var_func;

	smcp_timer_init(&self->timer, &smcp_timer_node_fired, NULL, self);

	self->autorestart = true;
	self->period = 5 * MSEC_PER_SEC;

bail:
	return self;
}
