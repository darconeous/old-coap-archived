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

#include "smcp/assert-macros.h"

#include <stdio.h>
#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>
#include <smcp/smcp-pairing.h>
#include <smcp/smcp-missing.h>

#include "pairing-node.h"

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <missing/fgetln.h>

struct pairing_node_s {
	struct smcp_node_s node;
	struct smcp_pairing_mgr_s pairing_mgr;
	smcp_timestamp_t next_observer_refresh;
	smcp_t interface;
};

extern char* get_next_arg(char *buf, char **rest);
#define strcaseequal(x,y)	(strcasecmp(x,y)==0)

void
pairing_node_commit_stable(const char* path, smcp_pairing_mgr_t mgr)
{
	FILE* file = fopen(path, "w");
	smcp_pairing_t iter = smcp_pairing_mgr_pairing_begin(mgr);
    time_t current_time = time(NULL);

	require(file != NULL, bail);

	fprintf(file, "# Stable Pairings Storage\n");
	fprintf(file, "# Automatically generated at %s\n", ctime(&current_time));

	for (; iter != NULL; iter = smcp_pairing_mgr_pairing_next(mgr, iter)) {
		if (!smcp_pairing_get_stable(iter)) {
			continue;
		}
		fprintf(
			file,
			"Pairing %d \"%s\" \"%s\" %d %d\n",
			smcp_pairing_get_id(iter),
			smcp_pairing_get_local_path(iter),
			smcp_pairing_get_remote_url(iter),
			smcp_pairing_get_enabled(iter),
			smcp_pairing_get_content_type(iter)
		);
	}

bail:
	if (file) {
		fclose(file);
	}
}

void
pairing_node_dealloc(pairing_node_t self) {

	if (self->pairing_mgr.context) {
		free(self->pairing_mgr.context);
	}

	// TODO: Tear down pairing manager properly!

	free(self);
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
	FILE* file = fopen(path, "r");
	char* line = NULL;
	size_t line_len = 0;

	require(name != NULL, bail);

	require(self || (self = pairing_node_alloc()), bail);
	require(smcp_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	self->node.has_link_content = 1;
//	self->node.is_observable = 1;
	self->interface = smcp_get_current_instance();

	smcp_pairing_mgr_init(&self->pairing_mgr, self->interface);

	((smcp_node_t)&self->node)->request_handler = (void*)&smcp_pairing_mgr_request_handler;
	((smcp_node_t)&self->node)->context = (void*)&self->pairing_mgr;

	self->next_observer_refresh = smcp_plat_cms_to_timestamp(MSEC_PER_SEC*60*10);

	require(file != NULL,bail);

	while(!feof(file) && (line=fgetln(file,&line_len))) {
		char *cmd = get_next_arg(line, &line);
		if(!cmd) {
			continue;
		} else if(strcaseequal(cmd,"Pairing")) {
			char* pairing_id_str = get_next_arg(line, &line);
			char* pairing_local_path_str = get_next_arg(line, &line);
			char* pairing_remote_url_str = get_next_arg(line, &line);
			char* pairing_enabled_str = get_next_arg(line, &line);
			char* pairing_content_type_str = get_next_arg(line, &line);
			if ( (pairing_id_str == NULL)
			  || (pairing_local_path_str == NULL)
			  || (pairing_remote_url_str == NULL)
			  || (pairing_enabled_str == NULL)
			  || (pairing_content_type_str == NULL)
			) {
				break;
			}
			smcp_pairing_t pairing = smcp_pairing_mgr_new_pairing(
				&self->pairing_mgr,
				pairing_local_path_str,
				pairing_remote_url_str,
				(uint8_t)atoi(pairing_id_str)
			);

			smcp_pairing_set_content_type(pairing, (coap_content_type_t)atoi(pairing_content_type_str));

			if (atoi(pairing_enabled_str) != 0) {
				smcp_pairing_set_enabled(pairing, true);
			}

			smcp_pairing_set_stable(pairing, true);
		}
	}

bail:
	if (path && (path[0] != 0)) {
		self->pairing_mgr.commit_stable_pairings = (void*)&pairing_node_commit_stable;
		self->pairing_mgr.context = strdup(path);
	}

	if (file) {
		fclose(file);
	}

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
	if (timeout) {
		*timeout = smcp_plat_timestamp_to_cms(self->next_observer_refresh);
	}
	return SMCP_STATUS_OK;
}

smcp_status_t
pairing_node_process(pairing_node_t self)
{
	if (smcp_plat_timestamp_to_cms(self->next_observer_refresh) < 0) {
		self->next_observer_refresh = smcp_plat_cms_to_timestamp(MSEC_PER_SEC*60*10);
		smcp_refresh_observers(self->interface);
	}
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
