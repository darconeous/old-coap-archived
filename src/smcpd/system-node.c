/*	@file system-node.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <smcp/assert_macros.h>
#include <stdio.h>
#include <stdlib.h>
#include <smcp/smcp.h>
#include <smcp/smcp-variable_node.h>
#include <time.h>
#include <errno.h>

enum {
	SYS_NODE_PATH_LOADAVG_1=0,
	SYS_NODE_PATH_LOADAVG_5,
	SYS_NODE_PATH_LOADAVG_15,
	SYS_NODE_PATH_UPTIME,

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

static smcp_status_t device_func(
	smcp_variable_node_t node,
	uint8_t action,
	uint8_t path,
	char* value
) {
	smcp_status_t ret = 0;
	if(path>=SYS_NODE_PATH_COUNT) {
		ret = SMCP_STATUS_NOT_FOUND;
	} else if(action==SMCP_VAR_GET_KEY) {
		static const char* path_names[] = {
			[SYS_NODE_PATH_LOADAVG_1]="loadavg-1",
			[SYS_NODE_PATH_LOADAVG_5]="loadavg-5",
			[SYS_NODE_PATH_LOADAVG_15]="loadavg-15",
			[SYS_NODE_PATH_UPTIME]="uptime",
		};
		strcpy(value,path_names[path]);
	} else if(action==SMCP_VAR_GET_MAX_AGE) {
		int max_age = 0;
		switch(path) {
			case SYS_NODE_PATH_LOADAVG_1:
			case SYS_NODE_PATH_LOADAVG_5:
			case SYS_NODE_PATH_LOADAVG_15:
				max_age = 5;
				break;
			case SYS_NODE_PATH_UPTIME:
				max_age = 1;
				break;
		}
		if(max_age) {
			sprintf(value,"%d",max_age);
		} else {
			return SMCP_STATUS_FAILURE;
		}
	} else if(action==SMCP_VAR_GET_OBSERVABLE) {
		static const bool observable[] = {
			[SYS_NODE_PATH_LOADAVG_1] = 0,
			[SYS_NODE_PATH_LOADAVG_5] = 0,
			[SYS_NODE_PATH_LOADAVG_15] = 0,
			[SYS_NODE_PATH_UPTIME] = 0,
		};
		if(!observable)
			return SMCP_STATUS_NOT_ALLOWED;
	} else if(action==SMCP_VAR_GET_VALUE) {
		switch(path) {
			case SYS_NODE_PATH_LOADAVG_1:
			case SYS_NODE_PATH_LOADAVG_5:
			case SYS_NODE_PATH_LOADAVG_15:
				{
					double loadavg[3] = { };
					require_action(
						0 < getloadavg(loadavg, sizeof(loadavg) / sizeof(*loadavg)),
						bail,
						ret = SMCP_STATUS_FAILURE
					);

					require_action(
						(size_t)snprintf(
							value,
							SMCP_VARIABLE_MAX_VALUE_LENGTH,
							"%0.2f",
							loadavg[path]
						) <= SMCP_VARIABLE_MAX_VALUE_LENGTH,
						bail,
						ret = SMCP_STATUS_FAILURE
					);
				}
				break;

			case SYS_NODE_PATH_UPTIME:
				require_action(
					(size_t)snprintf(
						value,
						SMCP_VARIABLE_MAX_VALUE_LENGTH,
						"%d",
						(int)uptime()
					) <= SMCP_VARIABLE_MAX_VALUE_LENGTH,
					bail,
					ret = SMCP_STATUS_FAILURE
				);
				break;

			default:
				ret = SMCP_STATUS_NOT_ALLOWED;
				break;
		}
	} else if(action==SMCP_VAR_SET_VALUE) {
		ret = SMCP_STATUS_NOT_ALLOWED;
	} else {
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
	}

bail:
	return ret;
}

static void
system_node_dealloc(smcp_variable_node_t x) {
	free(x);
}

smcp_variable_node_t
system_node_alloc() {
	smcp_variable_node_t ret =
	    (smcp_variable_node_t)calloc(sizeof(struct smcp_variable_node_s), 1);

	ret->node.finalize = (void (*)(smcp_node_t)) &system_node_dealloc;
	return ret;
}


smcp_variable_node_t
smcp_system_node_init(
	smcp_variable_node_t self,
	smcp_node_t parent,
	const char* name
) {
	require(self || (self = system_node_alloc()), bail);

	require(smcp_variable_node_init(
		self,
		(void*)parent,
		name
	), bail);

	self->func = device_func;

bail:
	return self;
}




