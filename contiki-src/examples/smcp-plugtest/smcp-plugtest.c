
#include "smcp-task.h"
#include "watchdog.h"
#include "net/resolv.h"

#include <smcp/smcp.h>
#include <smcp/smcp-node.h>

#include <plugtest/plugtest-server.h>

PROCESS_NAME(smcp_plugtest);
PROCESS(smcp_plugtest, "SMCP Plugtest");

AUTOSTART_PROCESSES(
	&resolv_process,
	&smcp_task,
	&smcp_plugtest,
	NULL
);

PROCESS_THREAD(smcp_plugtest, ev, data)
{
	static struct plugtest_server_s plugtest_server;

	PROCESS_BEGIN();

	plugtest_server_init(&plugtest_server,smcp_get_root_node(smcp));

	PROCESS_END();
}
