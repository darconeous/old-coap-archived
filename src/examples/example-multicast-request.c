/*!	@page smcp-example-multicast-request example-multicast-request.c: Sending multicast request
**
**	This example shows how to send a (multicast) request and receive multiple responses.
**
**	@include example-multicast-request.c
**
*/

#include <smcp/smcp.h>
#include <smcp/smcp-transaction.h>

#define DEFAULT_TIMEOUT 10000

typedef struct{
	coap_code_t method ;
	coap_transaction_type_t msg_type;
	const char * uri;
	int flags;
	smcp_response_handler_func response_handler;
	smcp_cms_t timeout;

	smcp_transaction_t transaction;
	bool done;
} request_t;

/** Fills the request structure with default values */
request_t Request(const char * url, smcp_response_handler_func responseHandler){
	request_t r = {
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE,
		url,
		0,
		responseHandler,
		DEFAULT_TIMEOUT,
		NULL,
		false
	};
	return r;
}

/** Create smcp instance */
smcp_t create_instance();

/** Extract uri from command line parameters (or use default) and write into buffer*/
void extract_uri(char * out_buffer, int size, int argc, char** argv);

/** do transaction from request data*/
smcp_status_t start_transaction(smcp_t instance, request_t * req);

/** Force finish transaction */
void finish_transaction(request_t * req);

//callbacks
smcp_status_t send_transaction_callback(void * context);
smcp_status_t on_receive_response_callback(int statuscode, void * context);

/** Handle received response for given request*/
smcp_status_t handle_response(request_t * req, int statuscode);

#define CHECK_AND_RETURN(status)\
	if(status){\
		printf("Error(%d) : %s\n", status, smcp_status_to_cstr(status));\
		return status;\
	}\

int main(int argc, char ** argv){
	SMCP_LIBRARY_VERSION_CHECK();

	smcp_t instance = create_instance();

	char url[256];
	extract_uri(url, 256, argc, argv);

	request_t  req = Request(url, on_receive_response_callback);
	req.flags = SMCP_TRANSACTION_ALWAYS_INVALIDATE;

	/* Enable this flag to not finish the transaction automatically after receive a response.
	 * This allows to keep receive responses from multiple servers, but requires the transaction
	 * to be finished manually (see on_receive_response_callback function below)
	*/
	req.flags |= SMCP_TRANSACTION_NO_AUTO_END;

	CHECK_AND_RETURN(start_transaction(instance, &req))

	// Process messages and wait until request is done
	while (!req.done) {
		smcp_plat_wait(instance, CMS_DISTANT_FUTURE);
		smcp_plat_process(instance);
	}

	smcp_release(instance);

	return 0;
}

smcp_t create_instance(){
	smcp_t instance = smcp_create();

	if (!instance) {
		perror("Unable to create SMCP instance");
		exit(EXIT_FAILURE);
	}

	smcp_plat_bind_to_port(instance, SMCP_SESSION_TYPE_UDP, 0);

	return instance;
}

void extract_uri(char * url, int size, int argc, char** argv)
{
	const char * host = argc > 1 ? argv[1] : "[ff02::fd]";
	const char * port = argc > 2 ? argv[2] : "5683";
	snprintf(url, size, "coap://%s:%s", host, port);
}

smcp_status_t start_transaction(smcp_t instance, request_t * req) {
	if(req == NULL){
		return SMCP_STATUS_FAILURE;
	}

	smcp_transaction_t tr = smcp_transaction_init(
		NULL,
		req->flags,
		send_transaction_callback,
		req->response_handler,
		req
	);

	if(!tr){
		return SMCP_STATUS_FAILURE;
	}

	req->transaction = tr;
	return smcp_transaction_begin(instance, tr, req->timeout);
}

smcp_status_t send_transaction_callback(void * context){
	printf("\nSend message\n");

	request_t * req = (request_t *)context;

	smcp_t smcp = smcp_get_current_instance();

	smcp_status_t status = smcp_outbound_begin(smcp, req->method, req->msg_type);
	CHECK_AND_RETURN(status);

	status = smcp_outbound_set_uri(req->uri, 0);
	CHECK_AND_RETURN(status);

	return smcp_outbound_send();
}

smcp_status_t on_receive_response_callback(int statuscode, void * context) {
	if(statuscode < SMCP_STATUS_OK){
		printf("Status (%d): %s\n", statuscode, smcp_status_to_cstr(statuscode));
	}

	request_t * req = (request_t *)context;

	if(statuscode >= COAP_RESULT_100){
		statuscode = handle_response(req, statuscode);
	}

	if(statuscode < SMCP_STATUS_OK){
		/* Finish the transaction if got an error statuscode (ex: when timeout). */
		finish_transaction(req);
		return SMCP_STATUS_TRANSACTION_INVALIDATED;
	}

	return SMCP_STATUS_OK;
}

smcp_status_t handle_response(request_t * req, int statuscode){
	printf("Got %d(%s) response\n", COAP_TO_HTTP_CODE(statuscode), coap_code_to_cstr(statuscode));

	coap_size_t len = smcp_inbound_get_content_len();
	const char * content = smcp_inbound_get_content_ptr();
	if(len > 0 && content != NULL){
		printf("%.*s\n", len, content);
	}

	return SMCP_STATUS_OK;
}

void finish_transaction(request_t * req){
	if(req == NULL){
		return;
	}


	smcp_transaction_t t = req->transaction;

	if(t != NULL){
		printf("finish transaction\n");

		req->transaction = NULL;
		req->done = true;

		smcp_transaction_end(smcp_get_current_instance(), t);
	}
}
