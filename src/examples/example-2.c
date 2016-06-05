/*!	@page smcp-example-2 example-2.c: Responding to a specific request
**
**	This example shows how to respond to a request for a specific resource.
**
**	@include example-2.c
**
**	@sa @ref smcp-instance, @ref smcp-inbound, @ref smcp-outbound
*/

#include <stdio.h>
#include <smcp/smcp.h>

static smcp_status_t
request_handler(void* context)
{
	/*	This will respond to every GET request to `/hello-world' with
	**	"Hello world!". Everyone else gets a 4.04 Not Found. */

	printf("Got a request!\n");

	// Only handle GET requests for now. Returning SMCP_STATUS_NOT_IMPLEMENTED
	// here without sending a response will cause us to automatically
	// send a METHOD_NOT_IMPLEMENTED response.
	if (smcp_inbound_get_code() != COAP_METHOD_GET) {
		return SMCP_STATUS_NOT_IMPLEMENTED;
	}

	// Skip to the URI path option
	while (smcp_inbound_peek_option(NULL, NULL) != COAP_OPTION_URI_PATH) {
		if (smcp_inbound_next_option(NULL, NULL) == COAP_OPTION_INVALID) {
			break;
		}
	}

	// If our URI path matches what we are looking for...
	if (smcp_inbound_option_strequal(COAP_OPTION_URI_PATH, "hello-world")) {

		// Begin describing the response message. (2.05 CONTENT,
		// in this case)
		smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);

		// Add an option describing the content type as plaintext.
		smcp_outbound_add_option_uint(
			COAP_OPTION_CONTENT_TYPE,
			COAP_CONTENT_TYPE_TEXT_PLAIN
		);

		// Set the content of our response to be "Hello world!".
		smcp_outbound_append_content("Hello world!", SMCP_CSTR_LEN);

		// Send the response we hae created, passing the return value
		// to our caller.
		return smcp_outbound_send();
	}

	return SMCP_STATUS_NOT_FOUND;
}

int
main(void)
{
	smcp_t instance;

	SMCP_LIBRARY_VERSION_CHECK();

	// Create our instance on the default CoAP port. If the port
	// is already in use, we will pick the next available port number.
	instance = smcp_create();

	if (!instance) {
		perror("Unable to create SMCP instance");
		exit(EXIT_FAILURE);
	}

	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, 0);

	printf("Listening on port %d\n",smcp_plat_get_port(instance));

	// SMCP will always respond to requests with METHOD_NOT_IMPLEMENTED
	// unless a request handler is set. Unless your program is only
	// making CoAP requests, you'll need a line like the following
	// in your program. The request handler may either handle the
	// request itself or route the request to the appropriate handler.
	smcp_set_default_request_handler(instance, &request_handler, NULL);

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
