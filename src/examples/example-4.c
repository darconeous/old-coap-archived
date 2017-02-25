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
#include <smcp/smcp-node-router.h>
#include <smcp/smcp-observable.h>

#define ARBITRARY_OBSERVABLE_KEY			23
#define TRIGGER_FREQUENCY					5		// In Seconds

static smcp_status_t
request_handler(void* context)
{
	smcp_observable_t observable = context;

	if (!smcp_inbound_is_fake()) {
		printf("Got a request!\n");
	}

	// Only handle GET requests for now.
	if (smcp_inbound_get_code() != COAP_METHOD_GET) {
		return SMCP_STATUS_NOT_IMPLEMENTED;
	}

	// Begin describing the response.
	smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);

	// This is the key line to making a resource observable.
	// It must be placed after smcp_outbound_begin_response()
	// and before smcp_outbound_send(). When this resource changes,
	// a simple call to smcp_observable_trigger() with the given
	// smcp_observable object and observable key will trigger the
	// observers to be updated. Really --- that's it...!
	smcp_observable_update(observable, ARBITRARY_OBSERVABLE_KEY);

	smcp_outbound_add_option_uint(
		COAP_OPTION_CONTENT_TYPE,
		COAP_CONTENT_TYPE_TEXT_PLAIN
	);

	smcp_outbound_append_content("Hello world!", SMCP_CSTR_LEN);

	return smcp_outbound_send();
}

int
main(void)
{
	smcp_t instance;
	smcp_node_t root_node;
	struct smcp_observable_s observable = { 0 };
	time_t next_trigger;

	SMCP_LIBRARY_VERSION_CHECK();

	instance = smcp_create();

	if (!instance) {
		perror("Unable to create SMCP instance");
		exit(EXIT_FAILURE);
	}

	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, COAP_DEFAULT_PORT);

	root_node = smcp_node_init(NULL, NULL, NULL);

	next_trigger = time(NULL) + TRIGGER_FREQUENCY;

	smcp_set_default_request_handler(
		instance,
		&smcp_node_router_handler,
		(void*)root_node
	);

	smcp_node_t hello_node = smcp_node_init(NULL,root_node,"hello-world");
	hello_node->request_handler = &request_handler;
	hello_node->context = &observable;

	printf("Listening on port %d\n", smcp_plat_get_port(instance));

	while (1) {
		smcp_plat_wait(instance, (next_trigger - time(NULL)) * MSEC_PER_SEC);
		smcp_plat_process(instance);

		// Occasionally trigger this resource as having changed.
		if ((next_trigger - time(NULL))<=0) {
			printf("%d observers registered\n", smcp_observable_observer_count(&observable, ARBITRARY_OBSERVABLE_KEY));
			smcp_observable_trigger(&observable, ARBITRARY_OBSERVABLE_KEY ,0);
			next_trigger = time(NULL) + TRIGGER_FREQUENCY;
		}
	}

	smcp_release(instance);

	return EXIT_SUCCESS;
}
