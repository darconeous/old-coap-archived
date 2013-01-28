/*!	@page smcp-example-2 example-3.c: Responding to a specific request
**
**	src/examples/example-2.c
**
**	This example shows how to respond to a request for a specific resource.
**
**	@sa @ref smcp-instance, @ref smcp-inbound, @ref smcp-outbound
*/

#include <stdio.h>
#include <smcp/smcp.h>

static smcp_status_t
request_handler(void* context) {
	/*	This will respond to every GET request to `/hello-world' with
	**	"Hello world!". Everyone else gets a 4.04 Not Found. */

	printf("Got a request!\n");

	if(smcp_inbound_get_code() != COAP_METHOD_GET) {
		return SMCP_STATUS_NOT_IMPLEMENTED;
	}

	while(smcp_inbound_peek_option(NULL, NULL) != COAP_OPTION_URI_PATH)
		if(smcp_inbound_next_option(NULL, NULL) == COAP_OPTION_INVALID)
			break;

	if(smcp_inbound_option_strequal(COAP_OPTION_URI_PATH, "hello-world")) {

		smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);

		smcp_outbound_add_option_uint(
			COAP_OPTION_CONTENT_TYPE,
			COAP_CONTENT_TYPE_TEXT_PLAIN
		);

		smcp_outbound_append_content("Hello world!", SMCP_CSTR_LEN);

		return smcp_outbound_send();
	}

	return SMCP_STATUS_NOT_FOUND;
}

int
main(void) {
	smcp_t instance = smcp_create(0);

	if(!instance) {
		perror("Unable to create SMCP instance");
		abort();
	}

	printf("Listening on port %d\n",smcp_get_port(instance));

	smcp_set_default_request_handler(instance, &request_handler, NULL);

	while(1) {
		smcp_process(instance, CMS_DISTANT_FUTURE);
	}

	smcp_release(instance);

	return 0;
}
