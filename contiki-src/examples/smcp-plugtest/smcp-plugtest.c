
#include "smcp-task.h"
#include "watchdog.h"
#include "net/resolv.h"

#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>

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
	static struct smcp_node_s root_node;

	// Set up the root node.
	smcp_node_init(&root_node,NULL,NULL);

	// Set up the node router.
	smcp_set_default_request_handler(smcp, &smcp_node_router_handler, &root_node);

	PROCESS_BEGIN();

	plugtest_server_init(&plugtest_server,&root_node);

	PROCESS_END();
}
