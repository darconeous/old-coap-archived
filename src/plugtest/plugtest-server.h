/*	@file plugtest-server.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Plugtest Server Object Header
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

#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>
#include <smcp/smcp-timer.h>
#include <smcp/smcp-observable.h>

struct plugtest_server_s {
	struct smcp_node_s test;
	struct smcp_node_s seg1;
	struct smcp_node_s seg2;
	struct smcp_node_s seg3;
	struct smcp_node_s query;
	struct smcp_node_s separate;
	struct smcp_node_s large;
	struct smcp_node_s large_update;
	struct smcp_node_s large_create;
	struct smcp_node_s obs;
	struct smcp_timer_s obs_timer;
	struct smcp_observable_s observable;
};

extern smcp_status_t plugtest_server_init(struct plugtest_server_s *self,smcp_node_t root);
