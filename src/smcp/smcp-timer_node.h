/*	@file smcp-timer_node.h
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

#ifndef __SMCP_TIMER_NODE_H__
#define __SMCP_TIMER_NODE_H__ 1

#include "smcp.h"
#include "smcp-timer.h"
#include "smcp-node.h"
#include "smcp-variable_node.h"

__BEGIN_DECLS

typedef struct smcp_timer_node_s {
	struct smcp_variable_node_s	node;
	struct smcp_timer_s timer;
	uint32_t			period;
	uint32_t			remaining;
#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	uint32_t			count;
#endif
	uint8_t				autorestart;
} *smcp_timer_node_t;

smcp_timer_node_t smcp_timer_node_alloc();
smcp_timer_node_t smcp_timer_node_init(
	smcp_timer_node_t	self,
	smcp_node_t			parent,
	const char*			name
);


void smcp_timer_node_start(smcp_timer_node_t self);
void smcp_timer_node_stop(smcp_timer_node_t self);
void smcp_timer_node_reset(smcp_timer_node_t self);
void smcp_timer_node_restart(smcp_timer_node_t self);
void smcp_timer_node_set_autorestart(smcp_timer_node_t self, bool x);

__END_DECLS

#endif //__SMCP_TIMER_NODE_H__
