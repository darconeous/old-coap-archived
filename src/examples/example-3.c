/*!	@page smcp-example-3 example-3.c: Using the node router
**
**	This example shows how to respond to a request for specific resources
**	using the node router.
**
**	@include example-3.c
**
**	## Results ##
**
**	    $ smcpctl
**	    Listening on port 61617.
**	    coap://localhost/> ls
**	    hello-world
**	    coap://localhost/> cat hello-world
**	    Hello world!
**	    coap://localhost/> cat hello-world -i
**	    CoAP/1.0 2.05 CONTENT tt=ACK(2) msgid=0xCBE1
**	    Token: CB E1
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**	    coap://localhost/>
**
**	@sa @ref smcp-node-router
**
*/

#include <stdio.h>
#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>

static smcp_status_t
request_handler(void* context)
{
	printf("Got a request!\n");

	// Only handle GET requests for now.
	if(smcp_inbound_get_code() != COAP_METHOD_GET) {
		return SMCP_STATUS_NOT_IMPLEMENTED;
	}

	// Begin describing the response.
	smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);

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

	SMCP_LIBRARY_VERSION_CHECK();

	// Create our instance on the default CoAP port. If the port
	// is already in use, we will pick the next available port number.
	instance = smcp_create();

	if (!instance) {
		perror("Unable to create SMCP instance");
		exit(EXIT_FAILURE);
	}

	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, 0);

	root_node = smcp_node_init(NULL, NULL, NULL);

	// SMCP will always respond to requests with METHOD_NOT_IMPLEMENTED
	// unless a request handler is set. Unless your program is only
	// making CoAP requests, you'll need a line like the following
	// in your program. The request handler may either handle the
	// request itself or route the request to the appropriate handler.
	// In this case, we are going to use the node router.
	smcp_set_default_request_handler(instance, &smcp_node_router_handler, (void*)root_node);

	smcp_node_t hello_node = smcp_node_init(NULL, root_node, "hello-world");
	hello_node->request_handler = &request_handler;
	hello_node->context = NULL;

	printf("Listening on port %d\n", smcp_plat_get_port(instance));

	// Loop forever. This is the most simple kind of main loop you
	// can haave with SMCP. It is appropriate for simple CoAP servers
	// and clients which do not need asynchronous I/O.
	while (1) {
		smcp_plat_wait(instance, CMS_DISTANT_FUTURE);
		smcp_plat_process(instance);
	}

	// We won't actually get to this line with the above loop, but it
	// is always a good idea to clean up when you are done. If you
	// provide a way to gracefully exit from your own main loop, you
	// can tear down the SMCP instance using the following command.
	smcp_release(instance);

	return EXIT_SUCCESS;
}
