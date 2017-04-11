/*	@file system-node.c
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

#define _BSD_SOURCE

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include "smcp/assert-macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <libnyoci/libnyoci.h>
#include <libnyociextra/libnyociextra.h>
#include <libnyociextra/libnyociextra.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include "system-node.h"

enum {
	SYS_NODE_PATH_UPTIME=0,
	SYS_NODE_PATH_PID,

#if HAVE_GETLOADAVG
	SYS_NODE_PATH_LOADAVG_1,
	SYS_NODE_PATH_LOADAVG_5,
	SYS_NODE_PATH_LOADAVG_15,
#endif

	SYS_NODE_PATH_COUNT
};

#if __linux__
#include <sys/sysinfo.h>
static time_t uptime() {
	struct sysinfo info;
	sysinfo(&info);
	return info.uptime;
}
#else
#include <sys/sysctl.h>
static time_t uptime() {
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if( sysctl(mib, 2, &boottime, &len, NULL, 0) < 0 )
        return -1;
    time_t bsec = boottime.tv_sec, csec = time(NULL);

    return csec-bsec;
}
#endif

struct system_node_s {
	struct nyoci_node_s node;
	struct nyoci_var_handler_s variable_handler;
};


static nyoci_status_t device_func(
	nyoci_var_handler_t node,
	uint8_t action,
	uint8_t path,
	char* value
) {
	nyoci_status_t ret = 0;
	if(path>=SYS_NODE_PATH_COUNT) {
		ret = NYOCI_STATUS_NOT_FOUND;
	} else if (action == NYOCI_VAR_GET_KEY) {
		static const char* path_names[] = {
			[SYS_NODE_PATH_UPTIME]="uptime",
			[SYS_NODE_PATH_PID]="pid",
#if HAVE_GETLOADAVG
			[SYS_NODE_PATH_LOADAVG_1]="loadavg-1",
			[SYS_NODE_PATH_LOADAVG_5]="loadavg-5",
			[SYS_NODE_PATH_LOADAVG_15]="loadavg-15",
#endif
		};
		strcpy(value,path_names[path]);
	} else if (action == NYOCI_VAR_GET_MAX_AGE) {
		int max_age = 0;
		switch(path) {
#if HAVE_GETLOADAVG
			case SYS_NODE_PATH_LOADAVG_1:
			case SYS_NODE_PATH_LOADAVG_5:
			case SYS_NODE_PATH_LOADAVG_15:
				max_age = 5;
				break;
#endif
			case SYS_NODE_PATH_UPTIME:
				max_age = 1;
				break;
		}
		if(max_age) {
			// TODO: Change this
			sprintf(value,"%d",max_age);
		} else {
			return NYOCI_STATUS_NOT_ALLOWED;
		}
	} else if (action == NYOCI_VAR_GET_OBSERVABLE) {
		static const bool observable[] = {
			[SYS_NODE_PATH_UPTIME] = 0,
#if HAVE_GETLOADAVG
			[SYS_NODE_PATH_LOADAVG_1] = 0,
			[SYS_NODE_PATH_LOADAVG_5] = 0,
			[SYS_NODE_PATH_LOADAVG_15] = 0,
#endif
		};
		if(!observable[path]) {
			return NYOCI_STATUS_NOT_ALLOWED;
		}
	} else if (action == NYOCI_VAR_GET_VALUE) {
		switch(path) {
#if HAVE_GETLOADAVG
			case SYS_NODE_PATH_LOADAVG_1:
			case SYS_NODE_PATH_LOADAVG_5:
			case SYS_NODE_PATH_LOADAVG_15:
				{
					double loadavg[3] = { };
					require_action(
						0 < getloadavg(loadavg, sizeof(loadavg) / sizeof(*loadavg)),
						bail,
						ret = NYOCI_STATUS_FAILURE
					);

					require_action(
						(size_t)snprintf(
							value,
							NYOCI_VARIABLE_MAX_VALUE_LENGTH,
							"%0.2f",
							loadavg[path]
						) <= NYOCI_VARIABLE_MAX_VALUE_LENGTH,
						bail,
						ret = NYOCI_STATUS_FAILURE
					);
				}
				break;
#endif // HAVE_GETLOADAVG

			case SYS_NODE_PATH_UPTIME:
				require_action(
					(size_t)snprintf(
						value,
						NYOCI_VARIABLE_MAX_VALUE_LENGTH,
						"%d",
						(int)uptime()
					) <= NYOCI_VARIABLE_MAX_VALUE_LENGTH,
					bail,
					ret = NYOCI_STATUS_FAILURE
				);
				break;

			case SYS_NODE_PATH_PID:
				require_action(
					(size_t)snprintf(
						value,
						NYOCI_VARIABLE_MAX_VALUE_LENGTH,
						"%d",
						(int)getpid()
					) <= NYOCI_VARIABLE_MAX_VALUE_LENGTH,
					bail,
					ret = NYOCI_STATUS_FAILURE
				);
				break;


			default:
				ret = NYOCI_STATUS_NOT_ALLOWED;
				break;
		}
	} else if(action==NYOCI_VAR_SET_VALUE) {
		ret = NYOCI_STATUS_NOT_ALLOWED;
	} else {
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
	}

bail:
	return ret;
}

static void
system_node_dealloc(system_node_t x) {
	free(x);
}

system_node_t
system_node_alloc()
{
	system_node_t ret =
	    (system_node_t)calloc(sizeof(struct system_node_s), 1);

	ret->node.finalize = (void (*)(nyoci_node_t)) &system_node_dealloc;
	return ret;
}

nyoci_status_t
system_node_request_handler(
	system_node_t		node
) {
	return nyoci_var_handler_request_handler(&node->variable_handler);
}

system_node_t
system_node_init(
	system_node_t self,
	nyoci_node_t parent,
	const char* name,
	const char* other
) {
	NYOCI_LIBRARY_VERSION_CHECK();

	require(self || (self = system_node_alloc()), bail);

	self->variable_handler.func = device_func;

	require(&self->node == nyoci_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	((nyoci_node_t)&self->node)->request_handler = (void*)&system_node_request_handler;

	self->node.has_link_content = 1;


bail:
	return self;
}





nyoci_status_t
SMCPD_module__system_node_process(system_node_t self) {
	return NYOCI_STATUS_OK;
}

nyoci_status_t
SMCPD_module__system_node_update_fdset(
	system_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	nyoci_cms_t *timeout
) {
	return NYOCI_STATUS_OK;
}

system_node_t
SMCPD_module__system_node_init(
	system_node_t	self,
	nyoci_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	return system_node_init(self, parent, name, cmd);
}
