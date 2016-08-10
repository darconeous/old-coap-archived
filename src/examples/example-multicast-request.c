/*!	@page smcp-example-multicast-request example-multicast-request.c: Sending multicast request
**
**	This example shows how to send a (multicast) request and receive multiple responses.
**
**	@include example-multicast-request.c
**
*/

#include <smcp/smcp.h>
#include <smcp/smcp-transaction.h>

typedef struct{
	const char * url;
	smcp_transaction_t transaction;
} transaction_context_t;

#define DEFAULT_TIMEOUT 10000 /* in milliseconds */

smcp_status_t
send_transaction_callback(void * context) {
	smcp_status_t status;

	transaction_context_t * ctx = (transaction_context_t *)context;

	smcp_t smcp = smcp_get_current_instance();

	printf("\nsend_transaction_callback(): Sending request\n");

	status = smcp_outbound_begin(
		smcp,
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_NONCONFIRMABLE  //multicast requests should be non confirmable
	);

	if (status != SMCP_STATUS_OK) {
		goto bail;
	}

	status = smcp_outbound_set_uri(ctx->url, 0);

	if (status != SMCP_STATUS_OK) {
		goto bail;
	}

	status = smcp_outbound_send();

bail:
	return status;
}

smcp_status_t
on_receive_response_callback(int statuscode, void * context)
{
	if (statuscode >= COAP_RESULT_100) {
		coap_size_t len = smcp_inbound_get_content_len();
		const char * content = smcp_inbound_get_content_ptr();

		printf("on_receive_response_callback(): statuscode=%d\n", statuscode);

		if (smcp_inbound_is_dupe()) {
			printf(" --> Duplicate %d(%s) response\n", COAP_TO_HTTP_CODE(statuscode), coap_code_to_cstr(statuscode));
		} else {
			printf(" --> Got %d(%s) response\n", COAP_TO_HTTP_CODE(statuscode), coap_code_to_cstr(statuscode));

			if (len > 0 && content != NULL) {
				printf("%.*s\n", len, content);
			}
		}
	}

	if (statuscode < SMCP_STATUS_OK) {
		printf("on_receive_response_callback(): statuscode=%d (%s)\n", statuscode, smcp_status_to_cstr(statuscode));

		/* Finish the transaction if got an error statuscode (ex: when timeout). */
		if (context != NULL) {
			transaction_context_t * ctx = (transaction_context_t *)context;

			smcp_transaction_t transaction = ctx->transaction;

			printf(" --> Transaction complete\n");

			transaction->context = NULL;

			smcp_transaction_end(smcp_get_current_instance(), transaction);
		}
	}

	return SMCP_STATUS_OK;
}

int
main(int argc, char ** argv)
{
	smcp_t instance;
	smcp_transaction_t transaction;
	char * url = argc > 1 ? argv[1] : "coap://[ff02::fd]/";
	transaction_context_t ctx = {url, NULL};

	SMCP_LIBRARY_VERSION_CHECK();

	instance = smcp_create();

	if (!instance) {
		perror("Unable to create SMCP instance");
		exit(EXIT_FAILURE);
	}

	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, 0);

	/* Enable 'SMCP_TRANSACTION_NO_AUTO_END' flag to receive responses
	 * from multiple servers.
	 *
	 * This flag prevents the request to be automatically finished after
	 * receiving the first response, but requires the transaction to be
	 * invalidated manually (see on_receive_response_callback below)
	 *
	 * `SMCP_TRANSACTION_BURST_MULTICAST` causes a burst of packets
	 * to be sent instead of just a single packet for retransmit attempts.
	 * This can help make multicast POSTs take effect more simultaneously.
	 */

	transaction = smcp_transaction_init(
		NULL,
		SMCP_TRANSACTION_ALWAYS_INVALIDATE
		| SMCP_TRANSACTION_NO_AUTO_END
		| SMCP_TRANSACTION_BURST_MULTICAST,
		send_transaction_callback,
		on_receive_response_callback,
		&ctx
	);

	if (!transaction) {
		printf("Unable to create transaction\n");
		exit(EXIT_FAILURE);
	}

	ctx.transaction = transaction;

	smcp_transaction_begin(instance, transaction, DEFAULT_TIMEOUT);

	/* Process messages and wait until request is done */
	do {
		smcp_plat_wait(instance, CMS_DISTANT_FUTURE);
		smcp_plat_process(instance);
	} while(ctx.transaction->active);

	smcp_release(instance);

	return 0;
}
