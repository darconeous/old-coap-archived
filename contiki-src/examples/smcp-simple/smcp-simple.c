
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

#if !defined(__SDCC) && defined(SDCC_REVISION)
#define __SDCC  1
#endif

#if __SDCC && !defined(snprintf)
#warning SNPRINTF NOT IMPLEMENTED, SPRINTF COULD OVERFLOW!
#define snprintf(dest,n,fmt,...) sprintf(dest,fmt,__VA_ARGS__)
#endif

#include <smcp/smcp.h>
#include <smcp/smcp-node.h>
#include <smcp/smcp-timer_node.h>
#include <smcp/smcp-variable_node.h>

//////////////////////////////////
// ELAPSED TIME NODE

smcp_status_t
elapsed_time_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	if(method==COAP_METHOD_GET) {
		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

		smcp_outbound_set_content_type(SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED);

		ret = smcp_outbound_set_var_content_unsigned_long_int(clock_seconds());
		if(ret) goto bail;

		ret = smcp_outbound_send();
	}
bail:
	return ret;
}

smcp_node_t
create_elapsed_time_node(
	smcp_node_t ret,
	smcp_node_t parent,
	const char* name
) {
	ret = smcp_node_init(ret,(void*)parent, name);

	ret->request_handler = elapsed_time_request_handler;

	return ret;
}

//////////////////////////////////
// PROCESS LIST NODE

smcp_status_t
processes_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	if(method==COAP_METHOD_GET) {
		struct process* iter;
		int size=0;
		char* content;
		size_t content_len=0;

		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

		smcp_outbound_set_content_type(COAP_CONTENT_TYPE_TEXT_CSV);

		content = smcp_outbound_get_content_ptr(&content_len);
		if(!content) goto bail;
		
		iter = process_list;

		while(iter) {
			size+=snprintf(content+size,content_len-size,"%p, %u, %s\n",iter,iter->state,PROCESS_NAME_STRING(iter));
			iter = iter->next;
		}
		
		ret = smcp_outbound_set_content_len(size);
		if(ret) goto bail;

		ret = smcp_outbound_send();
	}
bail:
	return ret;
}

smcp_node_t
create_process_list_node(smcp_node_t node,smcp_node_t parent,const char* name) {

	node = smcp_node_init(node,(void*)parent, name);

	node->request_handler = processes_request_handler;

	return node;
}

//////////////////////////////////
// RESET NODE

smcp_status_t
reset_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	if(method==COAP_METHOD_POST) {
		watchdog_reboot();
	}

	return ret;
}

smcp_node_t
create_reset_node(smcp_node_t node,smcp_node_t parent,const char* name) {

	node = smcp_node_init(node,(void*)parent, name);

	node->request_handler = reset_request_handler;

	return node;
}

//////////////////////////////////
// MAIN THREAD

PROCESS_THREAD(smcp_simple, ev, data)
{
	static struct smcp_node_s reset_node;
	static struct smcp_node_s uptime_node;
	static struct smcp_timer_node_s timer_node;
	static struct smcp_node_s processes_node;

	PROCESS_BEGIN();

	// Create the "reset" node.
	create_reset_node(
		&reset_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"reset"
	);

	// Create the "uptime" node.
	create_elapsed_time_node(
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
	create_process_list_node(
		&processes_node,
		smcp_daemon_get_root_node(smcp_daemon),
		"processes"
	);

	PROCESS_END();
}
