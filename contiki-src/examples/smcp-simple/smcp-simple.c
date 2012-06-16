
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

#if defined(__SDCC) && !defined(snprintf)
#warning SNPRINTF NOT IMPLEMENTED, SPRINTF COULD OVERFLOW!
#define snprintf(dest,n,fmt,...) sprintf(dest,fmt,__VA_ARGS__)
#endif

#include <smcp/smcp.h>
#include <smcp/smcp-node.h>
#include <smcp/smcp-timer_node.h>
#include <smcp/smcp-variable_node.h>
#include "led-node.h"

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
// HOSTNAME NODE
#if RESOLV_CONF_MDNS_RESPONDER
smcp_status_t
hostname_request_handler(
	smcp_node_t		node,
	smcp_method_t	method
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;

	if(method==COAP_METHOD_GET) {
		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

		ret = smcp_outbound_append_content(resolv_get_hostname(),-1);
		if(ret) goto bail;

		ret = smcp_outbound_send();
	} else if(method==COAP_METHOD_POST) {
		if(smcp_inbound_get_content_len())
			resolv_set_hostname(smcp_inbound_get_content_ptr());
		ret = 0;
	}
bail:
	return ret;
}

smcp_node_t
create_hostname_node(smcp_node_t node,smcp_node_t parent,const char* name) {

	node = smcp_node_init(node,(void*)parent, name);

	node->request_handler = hostname_request_handler;

	return node;
}
#endif // #if RESOLV_CONF_MDNS_RESPONDER

//////////////////////////////////
// MAIN THREAD

PROCESS_THREAD(smcp_simple, ev, data)
{
	static struct smcp_node_s reset_node;
	static struct smcp_node_s uptime_node;
	static struct smcp_timer_node_s timer_node;
	static struct smcp_node_s processes_node;
	static struct smcp_node_s hostname_node;

	PROCESS_BEGIN();

	smcp_init_led_node(smcp_get_root_node(smcp),"leds");

#if !CONTIKI_TARGET_MINIMAL_NET
	smcp_init_sensor_node(smcp_get_root_node(smcp),"sensors");
#endif

	// Create the "reset" node.
	create_reset_node(
		&reset_node,
		smcp_get_root_node(smcp),
		"reset"
	);

	// Create the "uptime" node.
	create_elapsed_time_node(
		&uptime_node,
		smcp_get_root_node(smcp),
		"uptime"
	);

	// Create the "timer" node.
	smcp_timer_node_init(
		&timer_node,
		smcp_get_root_node(smcp),
		"timer"
	);

	// Create the "processes" node.
	create_process_list_node(
		&processes_node,
		smcp_get_root_node(smcp),
		"processes"
	);

#if RESOLV_CONF_MDNS_RESPONDER
	// Create the "hostname" node.
	create_hostname_node(
		&hostname_node,
		smcp_get_root_node(smcp),
		"hostname"
	);
#endif // RESOLV_CONF_MDNS_RESPONDER

	PROCESS_END();
}
