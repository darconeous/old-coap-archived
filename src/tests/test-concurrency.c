/*!	@page test-concurrency test-concurrency.c: Concurrency test.
**
**	This test exercises using two separate SMCP instances on different
**  threads.
**
**	@include test-concurrency.c
**
*/

#include <stdio.h>
#include <pthread.h>
#include <smcp/assert-macros.h>
#include <smcp/smcp.h>

#define NUMBER_OF_THREADS			(10)
#define TRANSACTIONS_PER_THREAD		(10)

//#define VERBOSE_DEBUG		1

#if !VERBOSE_DEBUG
#define printf(...)		do { } while(0)
#endif

static smcp_status_t
request_handler(void* context) {
	/* This request handler will respond to every GET request with "Hello world!".
	 * It isn't usually a good idea to (almost) completely ignore the actual
	 * request, but since this is just an example we can get away with it.
	 * We do more processing on the request in the other examples. */

	printf("MAIN: Got a request!\n");

	// Only handle GET requests for now. Returning SMCP_STATUS_NOT_IMPLEMENTED
	// here without sending a response will cause us to automatically
	// send a METHOD_NOT_IMPLEMENTED response.
	if(smcp_inbound_get_code() != COAP_METHOD_GET)
		return SMCP_STATUS_NOT_IMPLEMENTED;

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

char* gMainThreadURL;

struct test_concurrency_thread_s {
	pthread_t pt;
	smcp_transaction_t transaction;
	int remaining;
	int index;
};

smcp_status_t
test_concurrency_thread_resend(void* context)
{
	struct test_concurrency_thread_s* obj = (struct test_concurrency_thread_s*)context;
	smcp_status_t status = 0;

	status = smcp_outbound_begin(
		smcp_get_current_instance(),
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE
	);
	require_noerr(status,bail);

	status = smcp_outbound_set_uri(gMainThreadURL, 0);
	require_noerr(status,bail);

	status = smcp_outbound_send();

	if(status) {
		check_noerr(status);
		fprintf(
			stderr,
			"smcp_outbound_send() returned error %d(%s).\n",
			status,
			smcp_status_to_cstr(status)
		);
		goto bail;
	}

bail:
	if(status == 0) {
		printf("%d: Sent Request.\n",obj->index);
	} else {
		printf("%d: Request Delayed: %d (%s)\n",obj->index, status, smcp_status_to_cstr(status));
		if(status == SMCP_STATUS_HOST_LOOKUP_FAILURE) {
			status = SMCP_STATUS_WAIT_FOR_DNS;
		}
	}

	return status;
}

smcp_status_t
test_concurrency_thread_response(int statuscode, void* context)
{
	struct test_concurrency_thread_s* obj = (struct test_concurrency_thread_s*)context;

	if (statuscode == SMCP_STATUS_TRANSACTION_INVALIDATED) {
		printf("%d: Transaction invalidated\n", obj->index);
		obj->remaining--;
		obj->transaction = NULL;
	} else if (statuscode == COAP_RESULT_205_CONTENT) {
		printf("%d: Got content: %s\n", obj->index, smcp_inbound_get_content_ptr());
	} else {
		printf("%d: ERROR: Got unexpected status code %d (%s)\n", obj->index,statuscode,smcp_status_to_cstr(statuscode));
		exit(EXIT_FAILURE);
	}
	return 0;
}

void*
thread_main(void* context) {
	struct test_concurrency_thread_s* obj = (struct test_concurrency_thread_s*)context;
	smcp_t instance;

	obj->remaining = TRANSACTIONS_PER_THREAD;
	obj->transaction = NULL;

	// Create our instance on the default CoAP port. If the port
	// is already in use, we will pick the next available port number.
	instance = smcp_create();

	if(!instance) {
		perror("Unable to create second SMCP instance");
		exit(EXIT_FAILURE);
	}

	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, 0);

	printf("%d: Thread Listening on port %d\n",obj->index,smcp_plat_get_port(instance));

	while(obj->remaining > 0) {
		if(obj->transaction == NULL) {
			printf("%d: Starting transaction #%d\n",obj->index, TRANSACTIONS_PER_THREAD-obj->remaining+1);
			obj->transaction = smcp_transaction_init(
				NULL,
				SMCP_TRANSACTION_ALWAYS_INVALIDATE,
				&test_concurrency_thread_resend,
				&test_concurrency_thread_response,
				(void*)obj
			);
			smcp_transaction_begin(
				instance,
				obj->transaction,
				3*MSEC_PER_SEC
			);
		}
		smcp_plat_wait(instance, 5000);
		smcp_plat_process(instance);
	}

	obj->remaining = 0;

	return NULL;
}

int
main(void) {
	smcp_t instance;
	struct test_concurrency_thread_s threads[NUMBER_OF_THREADS] = { };
	int i;
	bool is_finished = false;
	smcp_timestamp_t start_time = smcp_plat_cms_to_timestamp(0);


	SMCP_LIBRARY_VERSION_CHECK();

	instance = smcp_create();

	if(!instance) {
		perror("Unable to create first SMCP instance");
		exit(EXIT_FAILURE);
	}

	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, 0);

	printf("Main Listening on port %d\n", smcp_plat_get_port(instance));

	asprintf(&gMainThreadURL, "coap://localhost:%d/", smcp_plat_get_port(instance));

	smcp_set_default_request_handler(instance, &request_handler, NULL);

	for (i = 0; i < sizeof(threads)/sizeof(*threads); i++) {
		threads[i].index = i;
		pthread_create(
			&threads[i].pt,
			NULL,
			(void*(*)(void*))&thread_main,
			(void*)&threads[i]
		);
	}

	while (!is_finished) {
		if (-smcp_plat_cms_to_timestamp(start_time) > MSEC_PER_SEC*10) {
			fprintf(stderr,"TIMEOUT\n");
			abort();
		}
		smcp_plat_process(instance);
		if (smcp_plat_wait(instance, 1000) == SMCP_STATUS_TIMEOUT) {
			is_finished = true;
			for (i = 0; i < sizeof(threads)/sizeof(*threads); i++) {
				if (threads[i].remaining > 0) {
					is_finished = false;
					break;
				}
			}
		}
	}

	smcp_release(instance);

	return EXIT_SUCCESS;
}
