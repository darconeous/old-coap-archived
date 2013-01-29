
#include "smcp-task.h"
#include "watchdog.h"
#include "net/resolv.h"
#if WEBSERVER
#include "webserver-nogui.h"
#endif

PROCESS_NAME(smcp_simple);
PROCESS(smcp_simple, "SMCP Simple Demo");

/*---------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(
	&resolv_process,
	&smcp_task,
	&smcp_simple,
#if WEBSERVER
	&webserver_nogui_process,
#endif
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
#include <smcp/smcp-node-router.h>
#include <smcp/smcp-variable_node.h>
#include "led-node.h"

#if RAVEN_LCD_INTERFACE
#include "raven-lcd.h"
#endif

#ifndef DISPLAY_MESSAGE
#if RAVEN_LCD_INTERFACE
#define DISPLAY_MESSAGE(content,content_length)		raven_lcd_display_messagen(content,content_length)
#else
#define DISPLAY_MESSAGE(content,content_length)		printf("MSG: %s\n",content)
#endif
#endif

//////////////////////////////////
// ELAPSED TIME NODE

smcp_status_t
elapsed_time_request_handler(
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	const smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

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
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	const smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		struct process* iter;
		int size=0;
		char* content;
		size_t content_len=0;

		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

		smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_CSV);

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
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	const smcp_method_t method = smcp_inbound_get_code();

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
// BEEP NODE

smcp_status_t
beep_request_handler(
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	const smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_POST) {
#if RAVEN_LCD_INTERFACE
		raven_lcd_beep();
#else
		printf("BEEP!\n\a");
#endif
		ret = SMCP_STATUS_OK;
	}

	return ret;
}

smcp_node_t
create_beep_node(smcp_node_t node,smcp_node_t parent,const char* name) {

	node = smcp_node_init(node,(void*)parent, name);

	node->request_handler = beep_request_handler;

	return node;
}

//////////////////////////////////
// RPL NODE

#if UIP_CONF_IPV6_RPL
#include "net/uip-ds6.h"
#include "rpl.h"
extern uip_ds6_nbr_t uip_ds6_nbr_cache[];
extern uip_ds6_route_t uip_ds6_routing_table[];
extern uip_ds6_netif_t uip_ds6_if;

smcp_status_t
rpl_request_handler(
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	const smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		int size=0,i,j;
		char* content;
		size_t content_len=0;

		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

		smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);

		content = smcp_outbound_get_content_ptr(&content_len);
		if(!content) goto bail;

#define ADD_6ADDR(addr) size+=snprintf(content+size,content_len-size,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])

		size+=snprintf(content+size,content_len-size,"Addresses [%u max]\n",UIP_DS6_ADDR_NB);
		for (i=0;i<UIP_DS6_ADDR_NB;i++) {
			if (uip_ds6_if.addr_list[i].isused) {
				size+=snprintf(content+size,content_len-size,"\t");
				ADD_6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
				size+=snprintf(content+size,content_len-size,"\n");
			}
		}

		size+=snprintf(content+size,content_len-size,"\nNeighbors [%u max]\n",UIP_DS6_NBR_NB);
		for(i = 0,j=1; i < UIP_DS6_NBR_NB; i++) {
			if(uip_ds6_nbr_cache[i].isused) {
				size+=snprintf(content+size,content_len-size,"\t");
				ADD_6ADDR(&uip_ds6_nbr_cache[i].ipaddr);
				size+=snprintf(content+size,content_len-size,"\n");
				j=0;
			}
		}
		if (j) 	size+=snprintf(content+size,content_len-size,"\t<NONE>\n");

//		size+=snprintf(content+size,content_len-size,"\nRoutes [%u max]\n",UIP_DS6_ROUTE_NB);
//		for(i = 0,j=1; i < UIP_DS6_ROUTE_NB; i++) {
//			if(uip_ds6_routing_table[i].isused) {
//				size+=snprintf(content+size,content_len-size,"\t");
//				ADD_6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
//				size+=snprintf(content+size,content_len-size,"/%u (via ", uip_ds6_routing_table[i].length);
//				ADD_6ADDR(&uip_ds6_routing_table[i].nexthop);
//				if(uip_ds6_routing_table[i].state.lifetime < 600) {
//					size+=snprintf(content+size,content_len-size,") %lus\n", uip_ds6_routing_table[i].state.lifetime);
//				} else {
//					size+=snprintf(content+size,content_len-size,")\n");
//				}
//				j=0;
//			}
//		}
//		if (j) 	size+=snprintf(content+size,content_len-size,"\t<NONE>\n");

		ret = smcp_outbound_set_content_len(size);
		if(ret) goto bail;

		ret = smcp_outbound_send();
	}
bail:
	return ret;

}

smcp_node_t
create_rpl_node(smcp_node_t node,smcp_node_t parent,const char* name) {

	node = smcp_node_init(node,(void*)parent, name);

	node->request_handler = rpl_request_handler;

	return node;
}

#endif




//////////////////////////////////
// HOSTNAME NODE
#if RESOLV_CONF_MDNS_RESPONDER
smcp_status_t
hostname_request_handler(
	smcp_node_t		node
) {
	smcp_status_t ret = SMCP_STATUS_NOT_ALLOWED;
	const smcp_method_t method = smcp_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
		if(ret) goto bail;

		ret = smcp_outbound_append_content(resolv_get_hostname(),-1);
		if(ret) goto bail;

		ret = smcp_outbound_send();
	} else if(method==COAP_METHOD_PUT) {
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
	static struct smcp_node_s root_node = {};

	static struct smcp_node_s reset_node;
	static struct smcp_node_s uptime_node;
	static struct smcp_node_s processes_node;
	static struct smcp_node_s hostname_node;
	static struct smcp_node_s beep_node;
	static struct smcp_node_s rpl_node;

	PROCESS_BEGIN();

	// Set up the root node.
	smcp_node_init(&root_node,NULL,NULL);

	// Set up the node router.
	smcp_set_default_request_handler(smcp, &smcp_node_router_handler, &root_node);

	smcp_init_led_node(&root_node,"leds");

#if !CONTIKI_TARGET_MINIMAL_NET
	smcp_init_sensor_node(&root_node,"sensors");
#endif

	// Create the "reset" node.
	create_reset_node(
		&reset_node,
		&root_node,
		"reset"
	);

	// Create the "uptime" node.
	create_elapsed_time_node(
		&uptime_node,
		&root_node,
		"uptime"
	);

	// Create the "processes" node.
	create_process_list_node(
		&processes_node,
		&root_node,
		"processes"
	);

	// Create the "beep" node.
	create_beep_node(
		&beep_node,
		&root_node,
		"beep"
	);

#if RESOLV_CONF_MDNS_RESPONDER
	// Create the "hostname" node.
	create_hostname_node(
		&hostname_node,
		&root_node,
		"hostname"
	);
#endif // RESOLV_CONF_MDNS_RESPONDER

#if UIP_CONF_IPV6_RPL
	// Create the "hostname" node.
	create_rpl_node(
		&rpl_node,
		&root_node,
		"rpl"
	);
#endif // UIP_CONF_IPV6_RPL

	PROCESS_END();
}
