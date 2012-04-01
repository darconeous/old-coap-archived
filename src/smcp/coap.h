#ifndef __SMCP_COAP_H__
#define __SMCP_COAP_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#if __CONTIKI__
#include "net/uip.h"
#define htons(x)    uip_htons(x)
#define ntohs(x)    uip_ntohs(x)
#define HTONS(x)    UIP_HTONS(x)
#define NTOHS(x)    UIP_NTOHS(x)
#endif

#define COAP_RESPONSE_TIMEOUT   (1000)  // In ms, defined in http://tools.ietf.org/html/draft-ietf-core-coap-03#section-4.2
#define COAP_MAX_RETRANSMIT     (5)     // Defined in http://tools.ietf.org/html/draft-ietf-core-coap-03#section-4.2

#define COAP_DEFAULT_PORT   (61616)     // Not yet defined. Just guessing here.

#define COAP_VERSION    (1)
#define COAP_TRANS_TYPE_CONFIRMABLE     (0)
#define COAP_TRANS_TYPE_NONCONFIRMABLE  (1)
#define COAP_TRANS_TYPE_ACK             (2)
#define COAP_TRANS_TYPE_RESET           (3)

#define COAP_HEADER_CSTR_LEN        ((size_t)-1)

typedef char coap_transaction_type_t;
typedef uint16_t coap_transaction_id_t;

typedef uint16_t coap_code_t;

#define COAP_TO_HTTP_CODE(code)     ((code) / 40 * 100 + (code) % 40)
static inline uint16_t coap_to_http_code(uint8_t code) {
	return
	    COAP_TO_HTTP_CODE(
		code);
}

#define HTTP_TO_COAP_CODE(code)     ((code) / 100 * 40 + (code) % 100)
static inline uint8_t http_to_coap_code(uint16_t code) {
	return
	    HTTP_TO_COAP_CODE(
		code);
}

#define COAP_CODE_IS_REQUEST(code) \
        (((code)) > 0 && \
            ((code) < HTTP_TO_COAP_CODE(100)))
#define COAP_CODE_IS_RESULT(code)   ((code) >= HTTP_TO_COAP_CODE(100))

enum {
	COAP_METHOD_GET = 1,
	COAP_METHOD_POST = 2,
	COAP_METHOD_PUT = 3,    //!< @note UNUSED IN SMCP
	COAP_METHOD_DELETE = 4, //!< @note UNUSED IN SMCP

	// Experimental after this point

	COAP_METHOD_PAIR = 11,
	COAP_METHOD_UNPAIR = 12,
};

enum {
	HTTP_RESULT_CODE_CONTINUE = 100,

	HTTP_RESULT_CODE_OK = 200,
	HTTP_RESULT_CODE_CREATED = 201,

	HTTP_RESULT_CODE_NOT_MODIFIED = 304,

	HTTP_RESULT_CODE_BAD_REQUEST = 400,
	HTTP_RESULT_CODE_NOT_FOUND = 404,
	HTTP_RESULT_CODE_METHOD_NOT_ALLOWED = 405,
	HTTP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE = 415,

	HTTP_RESULT_CODE_INTERNAL_SERVER_ERROR = 500,
	HTTP_RESULT_CODE_BAD_GATEWAY = 502,
	HTTP_RESULT_CODE_SERVICE_UNAVAILABLE = 503,
	HTTP_RESULT_CODE_GATEWAY_TIMEOUT = 504,

	HTTP_RESULT_CODE_TOKEN_REQUIRED = COAP_TO_HTTP_CODE(240),
	HTTP_RESULT_CODE_URI_AUTHORITY_REQUIRED = COAP_TO_HTTP_CODE(241),
	HTTP_RESULT_CODE_UNSUPPORTED_CRITICAL_OPTION = COAP_TO_HTTP_CODE(242),

	// Unofficial result codes, taken from HTTP
	HTTP_RESULT_CODE_NO_CONTENT = 204,
	HTTP_RESULT_CODE_SEE_OTHER = 303,
	HTTP_RESULT_CODE_TEMPORARY_REDIRECT = 307,
	HTTP_RESULT_CODE_PARTIAL_CONTENT = 206,
	HTTP_RESULT_CODE_UNAUTHORIZED = 401,
	HTTP_RESULT_CODE_FORBIDDEN = 403,
	HTTP_RESULT_CODE_CONFLICT = 409,
	HTTP_RESULT_CODE_GONE = 410,
	HTTP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	HTTP_RESULT_CODE_NOT_IMPLEMENTED = 501,
	HTTP_RESULT_CODE_PROTOCOL_VERSION_NOT_SUPPORTED = 505,
};


typedef enum {
	COAP_HEADER_TERI = 0,           //!< draft-bormann-coap-misc-06, reserved in draft-ietf-core-coap-03
	COAP_HEADER_CONTENT_TYPE = 1,
	COAP_HEADER_MAX_AGE = 2,
	COAP_HEADER_URI_SCHEME = 3,     //!< draft-bormann-coap-misc-06, reserved in draft-ietf-core-coap-03
	COAP_HEADER_ETAG = 4,
	COAP_HEADER_URI_AUTHORITY = 5,
	COAP_HEADER_LOCATION = 6,
	COAP_HEADER_URI_AUTHORITY_BINARY = 7,   //!< draft-bormann-coap-misc-06, reserved in draft-ietf-core-coap-03
	COAP_HEADER_ACCEPT = 8,                 //!< draft-bormann-coap-misc-06
	COAP_HEADER_URI_PATH = 9,
	COAP_HEADER_SUBSCRIPTION_LIFETIME = 10, //!< draft-ietf-core-observe
	COAP_HEADER_TOKEN = 11,
	COAP_HEADER_URI_QUERY = 15,

	COAP_HEADER_FENCEPOST_1 = 14,
	COAP_HEADER_FENCEPOST_2 = 28,

	COAP_HEADER_BLOCK = 13,         //!< draft-bormann-core-coap-block-00

#define USE_DRAFT_BORMANN_CORE_COAP_BLOCK_01_ALT    0

#if USE_DRAFT_BORMANN_CORE_COAP_BLOCK_01_ALT
	COAP_HEADER_MESSAGE_SIZE = 16,
	COAP_HEADER_CONTINUATION_REQUEST = 17,
	COAP_HEADER_SIZE_REQUEST = 16,
	COAP_HEADER_CONTINUATION_RESPONSE = 17,

	COAP_HEADER_NEXT = 17,                          //!< Experimental alternative to draft-bormann-core-coap-block-00
#else
	COAP_HEADER_MESSAGE_SIZE = 16,                  //!< draft-bormann-core-coap-block-01
	COAP_HEADER_CONTINUATION_REQUEST = 17,          //!< draft-bormann-core-coap-block-01
	COAP_HEADER_SIZE_REQUEST = 18,                  //!< draft-bormann-core-coap-block-01
	COAP_HEADER_CONTINUATION_RESPONSE = 19,         //!< draft-bormann-core-coap-block-01
	COAP_HEADER_CONTINUATION_REQUIRED = 21,         //!< draft-bormann-core-coap-block-01

	COAP_HEADER_NEXT = COAP_HEADER_FENCEPOST_2 + 3, //!< Experimental alternative to draft-bormann-core-coap-block-00
#endif

	COAP_HEADER_RANGE = COAP_HEADER_FENCEPOST_2 + 2, //!< Experimental alternative to draft-bormann-core-coap-block-00

	// Experimental after this point

	COAP_HEADER_CASCADE_COUNT = COAP_HEADER_FENCEPOST_2 + 1,    //!< Used for preventing pairing loops.
	SMCP_HEADER_ORIGIN = COAP_HEADER_FENCEPOST_2 + 4,           //!< Used for SMCP Pairing.
	SMCP_HEADER_CSEQ = COAP_HEADER_FENCEPOST_2 + 6,             //!< Used for SMCP Pairing.
	COAP_HEADER_ALLOW = COAP_HEADER_FENCEPOST_2 + 8,
	SMCP_HEADER_AUTHENTICATE = COAP_HEADER_FENCEPOST_2 + 10,    //!< Used for SMCP Pairing.
} coap_header_key_t;


typedef struct {
	coap_header_key_t	key;
	char*				value;
	size_t				value_len;
} coap_header_item_t;

enum {
	COAP_CONTENT_TYPE_TEXT_PLAIN=0,
	COAP_CONTENT_TYPE_TEXT_XML=1,
	COAP_CONTENT_TYPE_TEXT_CSV=2,
	COAP_CONTENT_TYPE_TEXT_HTML=3,

	COAP_CONTENT_TYPE_IMAGE_GIF=21,
	COAP_CONTENT_TYPE_IMAGE_JPEG=22,
	COAP_CONTENT_TYPE_IMAGE_PNG=23,
	COAP_CONTENT_TYPE_IMAGE_TIFF=24,

	COAP_CONTENT_TYPE_AUDIO_RAW=25,
	COAP_CONTENT_TYPE_VIDEO_RAW=26,

	COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT=40,   //!< draft-shelby-core-link-format
	COAP_CONTENT_TYPE_APPLICATION_XML=41,
	COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM=42,
	COAP_CONTENT_TYPE_APPLICATION_RDF_XML=43,
	COAP_CONTENT_TYPE_APPLICATION_SOAP_XML=44,
	COAP_CONTENT_TYPE_APPLICATION_ATOM_XML=45,
	COAP_CONTENT_TYPE_APPLICATION_XMPP_XML=46,
	COAP_CONTENT_TYPE_APPLICATION_EXI=47,
	COAP_CONTENT_TYPE_APPLICATION_X_BXML=48,
	COAP_CONTENT_TYPE_APPLICATION_FASTINFOSET=49,
	COAP_CONTENT_TYPE_APPLICATION_SOAP_FASTINFOSET=50,
	COAP_CONTENT_TYPE_APPLICATION_JSON=51,

	// Experimental after this point. Experimentals start at 201.

	SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED=205,  //!< SMCP Specific

	COAP_CONTENT_TYPE_UNKNOWN = 255,
};

typedef unsigned char coap_content_type_t;

extern size_t coap_encode_header(
	unsigned char*			buffer,
	size_t					buffer_len,
	coap_transaction_type_t tt,
	coap_code_t				code,
	coap_transaction_id_t	tid,
	coap_header_item_t		headers[],
	uint8_t					header_count
);

extern size_t coap_decode_header(
	unsigned char*				buffer,
	size_t						buffer_len,
	coap_transaction_type_t*	tt,
	coap_code_t*				code,
	coap_transaction_id_t*		tid,
	coap_header_item_t*			headers,
	uint8_t*					header_count
);

extern const char* coap_content_type_to_cstr(
	coap_content_type_t content_type);
extern coap_content_type_t coap_content_type_from_cstr(const char* x);
extern const char* coap_header_key_to_cstr(
	coap_header_key_t key, bool for_response);
extern coap_header_key_t coap_header_key_from_cstr(const char* key);
extern const char* http_code_to_cstr(int x);
extern void coap_dump_headers(
	FILE*						outstream,
	const char*					prefix,
	int							statuscode,
	const coap_header_item_t*	headers,
	size_t						header_count);

#endif // __SMCP_COAP_H__
