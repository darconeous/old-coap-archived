/*	@file smcp_variable_node.h
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

#include "smcp_node.h"

struct smcp_variable_node_s;
typedef struct smcp_variable_node_s *smcp_variable_node_t;

// Size = sizeof(struct smcp_node_s)+2*sizeof(void*) = 10*sizeof(void*)
struct smcp_variable_node_s {
	struct smcp_node_s	node;
	smcp_status_t		(*get_func)(
		smcp_variable_node_t node,
		char* content,
		size_t* content_length,
		coap_content_type_t* content_type
	);
	smcp_status_t		(*post_func)(
		smcp_variable_node_t node,
		char* content,
		size_t content_length,
		coap_content_type_t content_type
	);
};


#define smcp_node_init_variable smcp_variable_node_init

extern smcp_variable_node_t smcp_variable_node_init(
	smcp_variable_node_t self, smcp_node_t parent, const char* name);

extern smcp_status_t smcp_daemon_refresh_variable(
	smcp_daemon_t daemon, smcp_variable_node_t node);

#endif //__SMCP_TIMER_NODE_H__
