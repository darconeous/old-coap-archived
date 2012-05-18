
#include "smcp-task.h"
#include "watchdog.h"
#include "net/resolv.h"

PROCESS_NAME(smcp_simple);
PROCESS(smcp_simple, "SMCP Simple Demo");

/*---------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(
	&resolv_process,
	&smcp_task,
	&smcp_simple,
	NULL
);
/*---------------------------------------------------------------------------*/

#if !HAS_SNPRINTF
#warning SNPRINTF NOT IMPLEMENTED, SPRINTF COULD OVERFLOW!
#define snprintf(dest,n,fmt,...) sprintf(dest,fmt,__VA_ARGS__)
#endif

#include <smcp/smcp.h>
#include <smcp/smcp_node.h>
#include <smcp/smcp_timer_node.h>
#include <smcp/smcp_variable_node.h>

//////////////////////////////////
// ELAPSED TIME NODE

smcp_status_t
elapsed_time_get_func(
	smcp_variable_node_t node,
	char* content,
	size_t* content_length,
	coap_content_type_t* content_type
) {
	int ret = 0;

	if(content_type)
		*content_type = SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;
	if(content) {
		snprintf(content,*content_length,"v=%lu",clock_seconds());
		*content_length = strlen(content);
	}

	return ret;
}

smcp_variable_node_t
create_elapsed_time_variable_node(
	smcp_variable_node_t ret,
	smcp_node_t parent,
	const char* name
) {
	ret = smcp_node_init_variable(ret,(void*)parent, name);

	ret->get_func = elapsed_time_get_func;

	return ret;
}

//////////////////////////////////
// PROCESS LIST NODE

smcp_status_t
processes_value_get_func(smcp_variable_node_t node, char* content, size_t* content_length, coap_content_type_t* content_type) {
	int ret = 0;
	struct process* iter;
	int size=0;

	if(content_type)
		*content_type = COAP_CONTENT_TYPE_TEXT_CSV;

	if(!content || !content_length)
		goto bail;

	if(*content_length<3) {
		ret = SMCP_STATUS_FAILURE;
		*content_length = 0;
		goto bail;
	}

	iter = process_list;

	while(iter) {
		size+=snprintf(content+size,*content_length-size,"%p, %u, %s\n",iter,iter->state,PROCESS_NAME_STRING(iter));
		iter = iter->next;
	}

	*content_length = size;

bail:
	return ret;
}

smcp_variable_node_t
create_process_list_variable_node(smcp_variable_node_t node,smcp_node_t parent,const char* name) {

	node = smcp_node_init_variable(node,(void*)parent, name);

	node->get_func = processes_value_get_func;

	return node;
}

//////////////////////////////////
// MAIN THREAD

PROCESS_THREAD(smcp_simple, ev, data)
{
	static struct smcp_variable_node_s reset_node;
	static struct smcp_variable_node_s uptime_node;
	static struct smcp_timer_node_s timer_node;
	static struct smcp_variable_node_s processes_node;

	PROCESS_BEGIN();

	// Create the "reset" node.
	smcp_node_init_variable(
		&reset_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"reset"
	);
	reset_node.post_func = (void*)&watchdog_reboot;

	// Create the "uptime" node.
	create_elapsed_time_variable_node(
		&uptime_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"uptime"
	);

	// Create the "timer" node.
	smcp_timer_node_init(
		&timer_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"timer"
	);

	// Create the "processes" node.
	create_process_list_variable_node(
		&processes_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"processes"
	);

	PROCESS_END();
}
