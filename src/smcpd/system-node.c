//
//  system-node.c
//  SMCP
//
//  Created by Robert Quattlebaum on 11/8/12.
//  Copyright (c) 2012 deepdarc. All rights reserved.
//

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

					smcp_outbound_add_option(COAP_HEADER_MAX_AGE,"\x0F", 1);

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
				smcp_outbound_add_option(COAP_HEADER_MAX_AGE,"\x01", 1);
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




