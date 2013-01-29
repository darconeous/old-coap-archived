/*!	@page smcp-example-4 example-4.c: Making observable resources
**
**	This example shows how to make resources observable.
**
**	@include example-4.c
**
**	## Results ##
**
**	    $ smcpctl
**	    Listening on port 61617.
**	    coap://localhost/> ls
**	    hello-world
**	    coap://localhost/> obs -i hello-world
**	    CoAP/1.0 2.05 CONTENT tt=ACK(2) msgid=0x1E80
**	    Token: 1E 80
**	    Observe: 0
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**
**	    CoAP/1.0 2.05 CONTENT tt=NON(1) msgid=0x0961
**	    Token: 1E 80
**	    Observe: 1
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**
**	    CoAP/1.0 2.05 CONTENT tt=NON(1) msgid=0x0A61
**	    Token: 1E 80
**	    Observe: 2
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**
**	    ^Ccoap://localhost/>
**
**
**	@sa @ref smcp-observable
*/

#include <stdio.h>
#include <smcp/smcp.h>
#include <smcp/smcp-node.h>
#include <smcp/smcp-observable.h>

#define ARBITRARY_OBSERVABLE_KEY			(23)
#define TRIGGER_FREQUENCY					(5)

static smcp_status_t
request_handler(void* context) {
	smcp_observable_t observable = context;

	printf("Got a request!\n");

	// Only handle GET requests for now.
	if(smcp_inbound_get_code() != COAP_METHOD_GET)
		return SMCP_STATUS_NOT_IMPLEMENTED;

	// Begin describing the response.
	smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);

	smcp_observable_update(observable, ARBITRARY_OBSERVABLE_KEY);

	smcp_outbound_add_option_uint(
		COAP_OPTION_CONTENT_TYPE,
		COAP_CONTENT_TYPE_TEXT_PLAIN
	);

	smcp_outbound_append_content("Hello world!", SMCP_CSTR_LEN);

	return smcp_outbound_send();
}

int
main(void) {
	smcp_node_t root_node = smcp_node_init(NULL,NULL,NULL);
	time_t next_trigger = time(NULL)+TRIGGER_FREQUENCY;
	struct smcp_observable_s observable = { NULL };

	smcp_t instance = smcp_create(0);
	if(!instance) {
		perror("Unable to create SMCP instance");
		abort();
	}

	smcp_set_default_request_handler(instance, &smcp_node_router_handler, (void*)root_node);

	smcp_node_t hello_node = smcp_node_init(NULL,root_node,"hello-world");
	hello_node->request_handler = &request_handler;
	hello_node->context = &observable;

	printf("Listening on port %d\n",smcp_get_port(instance));

	while(1) {
		smcp_process(instance, (next_trigger-time(NULL))*MSEC_PER_SEC);
		if((next_trigger-time(NULL))<=0) {
			smcp_observable_trigger(&observable,ARBITRARY_OBSERVABLE_KEY);
			next_trigger = time(NULL)+TRIGGER_FREQUENCY;
		}
	}

	smcp_release(instance);

	return 0;
}
