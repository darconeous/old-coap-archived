/*	@file smcp-variable_node.h
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

#ifndef __SMCP_VARIABLE_NODE_H__
#define __SMCP_VARIABLE_NODE_H__ 1

#include "smcp-node.h"

struct smcp_variable_node_s;
typedef struct smcp_variable_node_s *smcp_variable_node_t;

#define SMCP_VARIABLE_MAX_VALUE_LENGTH		(127)

enum {
	SMCP_VAR_GET_KEY,
	SMCP_VAR_CHECK_KEY,
	SMCP_VAR_SET_VALUE,
	SMCP_VAR_GET_VALUE,
};

struct smcp_variable_node_s {
	struct smcp_node_s node;
	void* context;
	smcp_status_t (*func)(
		smcp_variable_node_t node,
		uint8_t action,
		uint8_t i,
		char* value
	);
};

#define smcp_node_init_variable smcp_variable_node_init

extern smcp_variable_node_t smcp_variable_node_init(
	smcp_variable_node_t self, smcp_node_t parent, const char* name);

extern smcp_status_t smcp_refresh_variable(
	smcp_t daemon, smcp_variable_node_t node);

#endif //__SMCP_TIMER_NODE_H__
