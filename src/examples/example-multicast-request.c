/*!	@page smcp-example-multicast-request example-multicast-request.c: Sending multicast request
**
**	This example shows how to send a (multicast) request and receive multiple responses.
**
**	@include example-multicast-request.c
**
*/

#include <smcp/smcp.h>
#include <smcp/smcp-transaction.h>

/* data passed between transactions*/
typedef struct{
	const char * url;
	smcp_transaction_t tr;
} transaction_context_t;

smcp_transaction_t do_request(transaction_context_t * ctx, smcp_t instance, int flags);
char * make_url(const char * host, const char * port);

int main(int argc, char ** argv){
	SMCP_LIBRARY_VERSION_CHECK();

	smcp_t instance = smcp_create();
	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, 0);

	const char * host = argc > 1 ? argv[1] : "[ff02::fd]";
	const char * port = argc > 2 ? argv[2] : "5683";
	char * url = make_url(host, port);

	/* Enable 'SMCP_TRANSACTION_NO_AUTO_END' flag to receive responses from multiple servers.
	 *
	 * This flag prevents the request to be automatically finished after receive a response,
	 * but requires the transaction to be finished manually (see on_receive_response_callback below)
	*/
	int flags = SMCP_TRANSACTION_ALWAYS_INVALIDATE
				| SMCP_TRANSACTION_NO_AUTO_END;

	transaction_context_t ctx = {url, NULL};
	do_request(&ctx, instance, flags);

	/* Process messages and wait until request is done */
	do {
		smcp_plat_wait(instance, CMS_DISTANT_FUTURE);
		smcp_plat_process(instance);
	}while(ctx.tr->active);

	free(url);
	smcp_release(instance);

	return 0;
}

//callbacks
smcp_status_t send_transaction_callback(void * context);
smcp_status_t on_receive_response_callback(int statuscode, void * context);

#define DEFAULT_TIMEOUT 10000 /* in milliseconds */

#define CHECK_STATUS(status)\
	if(status != SMCP_STATUS_OK){\
		printf("Error(%d) : '%s' at %s:%d\n", status, smcp_status_to_cstr(status), __FILE__, __LINE__);\
		exit(status);\
	}

smcp_transaction_t do_request(transaction_context_t * ctx, smcp_t instance, int flags) {
	smcp_transaction_t tr = smcp_transaction_init(
		NULL,
		flags,
		send_transaction_callback,
		on_receive_response_callback,
		ctx
	);

	ctx->tr = tr;

	CHECK_STATUS(smcp_transaction_begin(instance, tr, DEFAULT_TIMEOUT));

	return tr;
}

smcp_status_t
send_transaction_callback(void * context){
	printf("\nSend message\n");

	transaction_context_t * ctx = (transaction_context_t *)context;

	smcp_t smcp = smcp_get_current_instance();

	smcp_status_t status = smcp_outbound_begin(
		smcp,
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_NONCONFIRMABLE); //multicast requests should be non confirmable

	CHECK_STATUS(status);

	status = smcp_outbound_set_uri(ctx->url, 0);
	CHECK_STATUS(status);

	return smcp_outbound_send();
}

smcp_status_t
on_receive_response_callback(int statuscode, void * context) {
	if(statuscode < SMCP_STATUS_OK){
		printf("Status (%d): %s\n", statuscode, smcp_status_to_cstr(statuscode));
	}
	else if(statuscode >= COAP_RESULT_100){
		printf("Got %d(%s) response\n", COAP_TO_HTTP_CODE(statuscode), coap_code_to_cstr(statuscode));

		coap_size_t len = smcp_inbound_get_content_len();
		const char * content = smcp_inbound_get_content_ptr();
		if(len > 0 && content != NULL){
			printf("%.*s\n", len, content);
		}
	}

	if(statuscode < SMCP_STATUS_OK){
		/* Finish the transaction if got an error statuscode (ex: when timeout). */
		if(context != NULL){
			printf("finish transaction\n");

			transaction_context_t * ctx = (transaction_context_t *)context;

			smcp_transaction_t t = ctx->tr;
			t->context = NULL;

			smcp_transaction_end(smcp_get_current_instance(), t);
		}
	}

	return SMCP_STATUS_OK;
}

char * make_url(const char * host, const char * port){
	const char * format = "coap://%s:%s";
	size_t size = snprintf(NULL, 0, format, host, port);

	char * url = malloc(size + 1);
	snprintf(url, size + 1, format, host, port);

	return url;
}
