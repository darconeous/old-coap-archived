
#include "smcp-task.h"
#include "net/resolv.h"
#if WEBSERVER
#include "webserver-nogui.h"
#endif

#include "watchdog.h"

PROCESS_NAME(smcp_demo);
PROCESS(smcp_demo, "SMCP Demo");

/*---------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(
	&resolv_process,
	&smcp_task,
	&smcp_demo,
#if WEBSERVER
	&webserver_nogui_process,
#endif
	NULL
);
/*---------------------------------------------------------------------------*/

#include <smcp/smcp.h>
#include <smcp/smcp-node.h>
#include <smcp/smcp-timer_node.h>
#include <smcp/smcp-pairing.h>
#include <smcp/smcp-variable_node.h>
#include <smcp/url-helpers.h>
#include "lib/sensors.h"

#if RAVEN_LCD_INTERFACE
#include "raven-lcd.h"
#endif

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

#ifndef DISPLAY_MESSAGE
#if RAVEN_LCD_INTERFACE
#define DISPLAY_MESSAGE(content,content_length)		raven_lcd_display_messagen(content,content_length)
#else
#define DISPLAY_MESSAGE(content,content_length)		printf("MSG: %s\n",content)
#endif
#endif

smcp_status_t
action_beep_func(smcp_variable_node_t node,  char* content, size_t content_length,coap_content_type_t content_type) {
	PRINTF(" *** Received BEEP Action!\n");

#if RAVEN_LCD_INTERFACE
	raven_lcd_beep();
#else
	printf("BEEP!\n\a");
#endif

	return 0;
}

smcp_status_t
action_msg_func(smcp_variable_node_t node, char* content, size_t content_length,coap_content_type_t content_type) {
	PRINTF(" *** Received MSG Action! content_length = %d ",(int)content_length);
	PRINTF("content = \"%s\"\n",content);

	if(content_type==SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED) {
		char *key;
		char *value;

		// Look for the 'v' key, so we can display it's value
		while(url_form_next_value((char**)&content,&key,&value)) {
			//if(strcmp(key,"v")==0)
			if(key[0]=='v' && key[1]==0)
				break;
		}

		if(!value)
			value = "(null)";

		content = value;
		content_length = strlen(value);
	}

	DISPLAY_MESSAGE(content,content_length);
	return 0;
}

smcp_status_t
elapsed_time_get_func(smcp_variable_node_t node, char* content, size_t* content_length, coap_content_type_t* content_type) {
	int ret = 0;

	if(content_type)
		*content_type = SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;
	if(content) {
		snprintf(content,*content_length,"v=%lu",clock_seconds());
		*content_length = strlen(content);
		PRINTF("Uptime queried.\n");
	}

	return ret;
}

smcp_variable_node_t
create_elapsed_time_variable_node(smcp_variable_node_t ret,smcp_node_t parent,const char* name) {
	ret = smcp_node_init_variable(ret,(void*)parent, name);

	ret->get_func = elapsed_time_get_func;

	return ret;
}

smcp_status_t
string_value_get_func(smcp_variable_node_t node, char* content, size_t* content_length, coap_content_type_t* content_type) {
	int ret = 0;

	if(content_type)
		*content_type = SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;
	if(content && content_length) {
		if(*content_length<3) {
			ret = SMCP_STATUS_FAILURE;
			*content_length = 0;
			goto bail;
		}

		content[0] = 'v';
		content[1] = '=';
		url_encode_cstr(content+2,(const char*)node->node.context,*content_length-2);

		*content_length = strlen(content);

		PRINTF("string_value_get_func queried.\n");
	}


bail:
	return ret;
}

smcp_status_t
processes_value_get_func(smcp_variable_node_t node, char* content, size_t* content_length, coap_content_type_t* content_type) {
	int ret = 0;

	if(content_type)
		*content_type = COAP_CONTENT_TYPE_TEXT_CSV;

	if(!content || !content_length)
		goto bail;

	if(*content_length<3) {
		ret = SMCP_STATUS_FAILURE;
		*content_length = 0;
		goto bail;
	}

	struct process* iter = process_list;
	int size=0;

	while(iter) {
		size+=snprintf(content+size,*content_length-size,"%p, %u, %s\n",iter,iter->state,iter->name);
		iter = iter->next;
	}

	*content_length = size;

bail:
	return ret;
}

smcp_status_t
etimer_list_get_func(smcp_variable_node_t node, char* content, size_t* content_length, coap_content_type_t* content_type) {
	int ret = 0;
	extern struct etimer *timerlist;

	if(content_type)
		*content_type = COAP_CONTENT_TYPE_TEXT_CSV;

	if(!content || !content_length)
		goto bail;

	if(*content_length<3) {
		ret = SMCP_STATUS_FAILURE;
		*content_length = 0;
		goto bail;
	}

	struct etimer* iter = timerlist;
	int size=0;

	while(iter) {
		size+=snprintf(content+size,*content_length-size,"%p, %u, %u, %s\n",iter,iter->timer.start,iter->timer.interval,iter->p->name);
		iter = iter->next;
	}

	*content_length = size;

bail:
	return ret;
}

#if USE_CONTIKI_SENSOR_API
smcp_status_t
sensor_list_get_func(smcp_variable_node_t node, char* content, size_t* content_length, coap_content_type_t* content_type) {
	int ret = 0;

	if(content_type)
		*content_type = COAP_CONTENT_TYPE_TEXT_CSV;

	if(!content || !content_length)
		goto bail;

	if(*content_length<3) {
		ret = SMCP_STATUS_FAILURE;
		*content_length = 0;
		goto bail;
	}

	struct sensors_sensor* iter = sensors_first();
	int size=0;

	while(iter) {
		size+=snprintf(content+size,*content_length-size,"0x%04x, %s, %d\n",iter,iter->type,iter->value(0));
		iter = sensors_next(iter);
	}

	*content_length = size;
	*content_type = COAP_CONTENT_TYPE_TEXT_CSV;

bail:
	return ret;
}
smcp_variable_node_t create_sensor_list_variable_node(smcp_node_t parent,const char* name) {
	smcp_variable_node_t ret = NULL;

	ret = smcp_node_init_variable(NULL,(void*)parent, name);

	ret->get_func = sensor_list_get_func;

	return ret;
}
#endif //USE_CONTIKI_SENSOR_API

smcp_variable_node_t create_etimer_list_variable_node(smcp_node_t parent,const char* name) {
	smcp_variable_node_t ret = NULL;

	ret = smcp_node_init_variable(NULL,(void*)parent, name);

	ret->get_func = etimer_list_get_func;

	return ret;
}

smcp_variable_node_t create_process_list_variable_node(smcp_node_t parent,const char* name) {
	smcp_variable_node_t ret = NULL;

	ret = smcp_node_init_variable(NULL,(void*)parent, name);

	ret->get_func = processes_value_get_func;

	return ret;
}


smcp_variable_node_t create_temp_variable_node(smcp_variable_node_t ret,smcp_node_t parent,const char* name) {
#if RAVEN_LCD_INTERFACE && WEBSERVER
	extern char sensor_temperature[12];
#else
	static const char* sensor_temperature = "N/A";
#endif

	ret = smcp_node_init_variable(ret,(void*)parent, name);

	ret->node.context = sensor_temperature;
	ret->get_func = string_value_get_func;

	return ret;
}

smcp_variable_node_t create_extvoltage_variable_node(smcp_variable_node_t ret,smcp_node_t parent,const char* name) {
#if RAVEN_LCD_INTERFACE && WEBSERVER
	extern char sensor_extvoltage[12];
#else
	static const char* sensor_extvoltage = "N/A";
#endif

	ret = smcp_node_init_variable(ret,(void*)parent, name);

	ret->node.context = sensor_extvoltage;
	ret->get_func = string_value_get_func;

	return ret;
}

#if USE_RELAY
smcp_variable_node_t create_relay_variable_node(smcp_node_t parent,const char* name) {
	smcp_variable_node_t ret = NULL;
	smcp_action_node_t set_action = NULL;
	smcp_action_node_t on_action = NULL;
	smcp_action_node_t off_action = NULL;
	smcp_action_node_t toggle_action = NULL;

	ret = smcp_node_init_variable(NULL,(void*)parent, name);

	smcp_node_init_event(NULL,(void*)ret, "changed");
	set_action = smcp_node_init_action(NULL,(void*)ret, "set");
	on_action = smcp_node_init_action(NULL,(void*)ret, "set=1");
	off_action = smcp_node_init_action(NULL,(void*)ret, "set=0");
	toggle_action = smcp_node_init_action(NULL,(void*)ret, "toggle");

	//ret->get_func = string_value_get_func;

	return ret;
}
#endif


PROCESS_THREAD(smcp_demo, ev, data)
{
	static struct smcp_variable_node_s uptime_var;
	static struct smcp_variable_node_s temp_var;
	static struct smcp_variable_node_s extvoltage_var;

	PROCESS_BEGIN();

	{
		static struct smcp_variable_node_s node;
		smcp_node_init_variable(&node,smcp_get_root_node(smcp), "beep");
		node.post_func = &action_beep_func;
	}

	{
		static struct smcp_variable_node_s node;
		smcp_node_init_variable(&node,smcp_get_root_node(smcp), "reset");
		node.post_func = (void*)&watchdog_reboot;
	}

	{
		static struct smcp_variable_node_s node;
		smcp_node_init_variable(&node,smcp_get_root_node(smcp), "lcd-msg");
		node.post_func = &action_msg_func;
	}

	create_temp_variable_node(
		&temp_var,
		smcp_get_root_node(smcp),
		"temp"
	);

	create_extvoltage_variable_node(
		&extvoltage_var,
		smcp_get_root_node(smcp),
		"extvoltage"
	);

	create_elapsed_time_variable_node(
		&uptime_var,
		smcp_get_root_node(smcp),
		"uptime"
	);

	create_process_list_variable_node(
		smcp_get_root_node(smcp),
		"processes"
	);

	create_etimer_list_variable_node(
		smcp_get_root_node(smcp),
		"etimers"
	);

#if USE_CONTIKI_SENSOR_API
	create_sensor_list_variable_node(
		smcp_get_root_node(smcp),
		"sensors"
	);
#endif

	{
		static struct smcp_timer_node_s timer_node;
		smcp_timer_node_init(
			&timer_node,
			smcp_get_root_node(smcp),
			"timer01"
		);
	}

	do {
		PROCESS_WAIT_EVENT();

#if RAVEN_LCD_INTERFACE
		if(ev == raven_lcd_updated_temp) {
			smcp_trigger_event_with_node(
				smcp,
				&temp_var,
				NULL
			);
		} else if(ev == raven_lcd_updated_extvoltage) {
			smcp_trigger_event_with_node(
				smcp,
				&extvoltage_var,
				NULL
			);
		} else if(ev == raven_lcd_updated_batvoltage) {
/*
			char content[16] = "v=";
			size_t content_len = url_encode_cstr(content+2,(const char*)data,sizeof(content)-2)+2;

			if(content_len>sizeof(content))
				content_len = sizeof(content);

			PRINTF("Bat Voltage event (%s)\n",(const char*)content);

			smcp_trigger_custom_event(
				smcp,
				"batvoltage",
				content,
				content_len,
				SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED
			);
*/
		}
#endif // RAVEN_LCD_INTERFACE

	} while(ev != PROCESS_EVENT_EXIT);

	PROCESS_END();
}
