#ifndef __SMCP_TASK_H__
#define __SMCP_TASK_H__

#include "contiki.h"
#include <smcp/smcp.h>

PROCESS_NAME(smcp_task);

CCIF extern struct smcp_daemon_s smcp_daemon_global_instance;
#define smcp_daemon		&smcp_daemon_global_instance

#endif