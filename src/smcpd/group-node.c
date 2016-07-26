/*	@file group-node.c
**	@brief Group Management Node
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

#include "smcp/assert-macros.h"

#include <stdio.h>
#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>
#include <smcp/smcp-group.h>
#include <smcp/smcp-missing.h>

#include "group-node.h"

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <missing/fgetln.h>

#define SMCP_ADDR_NTOP(str, len, addr) inet_ntop(SMCP_BSD_SOCKETS_NET_FAMILY, addr , str, len-1)

struct group_node_s {
	struct smcp_node_s node;
	struct smcp_group_mgr_s group_mgr;
	smcp_timestamp_t next_observer_refresh;
	smcp_t interface;
};

extern char* get_next_arg(char *buf, char **rest);
#define strcaseequal(x,y)	(strcasecmp(x,y)==0)

void
group_node_commit_stable(const char* path, smcp_group_mgr_t mgr)
{
	FILE* file = fopen(path, "w");
	smcp_group_t iter = smcp_group_mgr_groups_begin(mgr);
    time_t current_time = time(NULL);

	require(file != NULL, bail);

	fprintf(file, "# Stable Groups Storage\n");
	fprintf(file, "# Automatically generated at %s\n", ctime(&current_time));

	for (; iter != NULL; iter = smcp_group_mgr_groups_next(mgr, iter)) {
		char addr_cstr[40];
		SMCP_ADDR_NTOP(addr_cstr, sizeof(addr_cstr), smcp_group_get_addr(iter));
		if (!smcp_group_get_stable(iter)) {
			continue;
		}
		fprintf(
			file,
			"Group %d \"%s\" \"%s\" %d\n",
			smcp_group_get_id(iter),
			smcp_group_get_fqdn(iter),
			addr_cstr,
			smcp_group_get_enabled(iter)
		);
	}

bail:
	if (file) {
		fclose(file);
	}
}

void
group_node_dealloc(group_node_t self) {

	if (self->group_mgr.context) {
		free(self->group_mgr.context);
	}

	// TODO: Tear down group manager properly!

	free(self);
}

group_node_t
group_node_alloc() {
	group_node_t ret = (group_node_t)calloc(sizeof(struct group_node_s), 1);
	ret->node.finalize = (void (*)(smcp_node_t)) &group_node_dealloc;
	return ret;
}

group_node_t
group_node_init(
	group_node_t self,
	smcp_node_t parent,
	const char* name,
	const char* path
) {
	FILE* file = fopen(path, "r");
	char* line = NULL;
	size_t line_len = 0;

	require(name != NULL, bail);

	require(self || (self = group_node_alloc()), bail);
	require(smcp_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	self->node.has_link_content = 1;
//	self->node.is_observable = 1;
	self->interface = smcp_get_current_instance();

	smcp_group_mgr_init(&self->group_mgr, self->interface);

	((smcp_node_t)&self->node)->request_handler = (void*)&smcp_group_mgr_request_handler;
	((smcp_node_t)&self->node)->context = (void*)&self->group_mgr;

	self->next_observer_refresh = smcp_plat_cms_to_timestamp(MSEC_PER_SEC*60*10);

	require(file != NULL,bail);

	while(!feof(file) && (line=fgetln(file,&line_len))) {
		char *cmd = get_next_arg(line, &line);
		if(!cmd) {
			continue;
		} else if(strcaseequal(cmd,"Group")) {
			char* group_id_str = get_next_arg(line, &line);
			char* group_fqdn_str = get_next_arg(line, &line);
			char* group_addr_str = get_next_arg(line, &line);
			char* group_enabled_str = get_next_arg(line, &line);
			smcp_addr_t addr = {};

			if ( (group_id_str == NULL)
			  || (group_fqdn_str == NULL)
			  || (group_addr_str == NULL)
			  || (group_enabled_str == NULL)
			) {
				break;
			}

			inet_pton(SMCP_BSD_SOCKETS_NET_FAMILY, group_addr_str, &addr);

			smcp_group_t group = smcp_group_mgr_new_group(
				&self->group_mgr,
				group_fqdn_str,
				&addr,
				(uint8_t)atoi(group_id_str)
			);

			if (atoi(group_enabled_str) != 0) {
				smcp_group_set_enabled(group, true);
			}

			smcp_group_set_stable(group, true);
		}
	}

bail:
	if (self && path && (path[0] != 0)) {
		self->group_mgr.commit_stable_groups = (void*)&group_node_commit_stable;
		self->group_mgr.context = strdup(path);
	}

	if (file) {
		fclose(file);
	}

	return self;
}

smcp_status_t
group_node_update_fdset(
	group_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	smcp_cms_t *timeout
) {
	if (timeout) {
		*timeout = smcp_plat_timestamp_to_cms(self->next_observer_refresh);
	}
	return SMCP_STATUS_OK;
}

smcp_status_t
group_node_process(group_node_t self)
{
	if (smcp_plat_timestamp_to_cms(self->next_observer_refresh) < 0) {
		self->next_observer_refresh = smcp_plat_cms_to_timestamp(MSEC_PER_SEC*60*10);
		smcp_refresh_observers(self->interface);
	}
	return SMCP_STATUS_OK;
}



smcp_status_t
SMCPD_module__group_node_process(group_node_t self) {
	return group_node_process(self);
}

smcp_status_t
SMCPD_module__group_node_update_fdset(
	group_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	smcp_cms_t *timeout
) {
	return group_node_update_fdset(self, read_fd_set, write_fd_set, error_fd_set, fd_count, timeout);
}

group_node_t
SMCPD_module__group_node_init(
	group_node_t	self,
	smcp_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	return group_node_init(self, parent, name, cmd);
}
