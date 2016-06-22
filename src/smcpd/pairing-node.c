/*	@file pairing-node.c
**	@brief Pairing Management Node
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

#define DEBUG 1
#define VERBOSE_DEBUG 1

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include <smcp/assert-macros.h>

#include <stdio.h>
#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>
#include <smcp/smcp-pairing.h>

#include "pairing-node.h"

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
//#include <unistd.h>
//#include <signal.h>
//#include <sys/wait.h>
//#include <sys/stat.h>
//#include <fcntl.h>
//#include <poll.h>
//#include <smcp/fasthash.h>

struct pairing_node_s {
	struct smcp_node_s node;
	struct smcp_pairing_mgr_s pairing_mgr;
};

void
pairing_node_dealloc(pairing_node_t x) {
	free(x);
}

pairing_node_t
pairing_node_alloc() {
	pairing_node_t ret = (pairing_node_t)calloc(sizeof(struct pairing_node_s), 1);
	ret->node.finalize = (void (*)(smcp_node_t)) &pairing_node_dealloc;
	return ret;
}

pairing_node_t
pairing_node_init(
	pairing_node_t self,
	smcp_node_t parent,
	const char* name,
	const char* path
) {

	require(name != NULL, bail);


	require(self || (self = pairing_node_alloc()), bail);
	require(smcp_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	self->node.has_link_content = 1;

	smcp_pairing_mgr_init(&self->pairing_mgr, smcp_get_current_instance());

	((smcp_node_t)&self->node)->request_handler = (void*)&smcp_pairing_mgr_request_handler;
	((smcp_node_t)&self->node)->context = (void*)&self->pairing_mgr;

//	self->node.is_observable = 1;


bail:

	return self;
}

smcp_status_t
pairing_node_update_fdset(
	pairing_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	smcp_cms_t *timeout
) {
	return SMCP_STATUS_OK;
}

smcp_status_t
pairing_node_process(pairing_node_t self)
{
	return SMCP_STATUS_OK;
}



smcp_status_t
SMCPD_module__pairing_node_process(pairing_node_t self) {
	return pairing_node_process(self);
}

smcp_status_t
SMCPD_module__pairing_node_update_fdset(
	pairing_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	smcp_cms_t *timeout
) {
	return pairing_node_update_fdset(self, read_fd_set, write_fd_set, error_fd_set, fd_count, timeout);
}

pairing_node_t
SMCPD_module__pairing_node_init(
	pairing_node_t	self,
	smcp_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	return pairing_node_init(self, parent, name, cmd);
}
