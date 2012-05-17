#ifndef __SMCP_COAP_H__
#define __SMCP_COAP_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#if CONTIKI
#include "net/uip.h"
#define htons(x)    uip_htons(x)
#define ntohs(x)    uip_ntohs(x)
#define HTONS(x)    UIP_HTONS(x)
#define NTOHS(x)    UIP_NTOHS(x)
#endif

#define COAP_RESPONSE_TIMEOUT   (1000)  // In ms, defined in http://tools.ietf.org/html/draft-ietf-core-coap-03#section-4.2
#define COAP_MAX_RETRANSMIT     (5)     // Defined in http://tools.ietf.org/html/draft-ietf-core-coap-03#section-4.2


#define COAP_DEFAULT_PORT			(5683)
#define COAP_DEFAULT_PROXY_PORT		(COAP_DEFAULT_PORT)

#define COAP_VERSION    (1)
#define COAP_TRANS_TYPE_CONFIRMABLE     (0)
#define COAP_TRANS_TYPE_NONCONFIRMABLE  (1)
#define COAP_TRANS_TYPE_ACK             (2)
#define COAP_TRANS_TYPE_RESET           (3)

#define COAP_MAX_TOKEN_SIZE		(8)

#define COAP_HEADER_CSTR_LEN        ((size_t)-1)

typedef char coap_transaction_type_t;
typedef uint16_t coap_transaction_id_t;

typedef uint16_t coap_code_t;

#define COAP_TO_HTTP_CODE(code)     ((code) / 32 * 100 + (code) % 32)
static inline uint16_t coap_to_http_code(uint8_t code) {
	return
	    COAP_TO_HTTP_CODE(
		code);
}

#define HTTP_TO_COAP_CODE(code)     ((code) / 100 * 32 + (code) % 100)
static inline uint8_t http_to_coap_code(uint16_t code) {
	return
	    HTTP_TO_COAP_CODE(
		code);
}

enum {
	COAP_CODE_EMPTY = 0,
	COAP_METHOD_GET = 1,
	COAP_METHOD_POST = 2,
	COAP_METHOD_PUT = 3,    //!< @note UNUSED IN SMCP
	COAP_METHOD_DELETE = 4, //!< @note UNUSED IN SMCP

	// Experimental after this point
};

enum {
	COAP_RESULT_100 = HTTP_TO_COAP_CODE(100),
	COAP_RESULT_200 = HTTP_TO_COAP_CODE(200),
	COAP_RESULT_300 = HTTP_TO_COAP_CODE(300),
	COAP_RESULT_400 = HTTP_TO_COAP_CODE(400),
	COAP_RESULT_500 = HTTP_TO_COAP_CODE(500),

	COAP_RESULT_201_CREATED = HTTP_TO_COAP_CODE(201),
	COAP_RESULT_202_DELETED = HTTP_TO_COAP_CODE(202),
	COAP_RESULT_203_VALID = HTTP_TO_COAP_CODE(203),
	COAP_RESULT_204_CHANGED = HTTP_TO_COAP_CODE(204),
	COAP_RESULT_205_CONTENT = HTTP_TO_COAP_CODE(205),

	COAP_RESULT_400_BAD_REQUEST = HTTP_TO_COAP_CODE(400),
	COAP_RESULT_401_UNAUTHORIZED = HTTP_TO_COAP_CODE(401),
	COAP_RESULT_402_BAD_OPTION = HTTP_TO_COAP_CODE(402),
	COAP_RESULT_403_FORBIDDEN = HTTP_TO_COAP_CODE(403),
	COAP_RESULT_404_NOT_FOUND = HTTP_TO_COAP_CODE(404),
	COAP_RESULT_405_METHOD_NOT_ALLOWED = HTTP_TO_COAP_CODE(405),
	COAP_RESULT_406_NOT_ACCEPTABLE = HTTP_TO_COAP_CODE(406),
	COAP_RESULT_412_PRECONDITION_FAILED = HTTP_TO_COAP_CODE(412),
	COAP_RESULT_413_REQUEST_ENTITY_TOO_LARGE = HTTP_TO_COAP_CODE(413),
	COAP_RESULT_415_UNSUPPORTED_MEDIA_TYPE = HTTP_TO_COAP_CODE(415),

	COAP_RESULT_500_INTERNAL_SERVER_ERROR = HTTP_TO_COAP_CODE(500),
	COAP_RESULT_501_NOT_IMPLEMENTED = HTTP_TO_COAP_CODE(501),
	COAP_RESULT_502_BAD_GATEWAY = HTTP_TO_COAP_CODE(502),
	COAP_RESULT_503_SERVICE_UNAVAILABLE = HTTP_TO_COAP_CODE(503),
	COAP_RESULT_504_GATEWAY_TIMEOUT = HTTP_TO_COAP_CODE(504),
	COAP_RESULT_505_PROXYING_NOT_SUPPORTED = HTTP_TO_COAP_CODE(505),
};

#define COAP_CODE_IS_REQUEST(code) \
        (((code)) > 0 && \
            ((code) < COAP_RESULT_100))
#define COAP_CODE_IS_RESULT(code)   (!(code) || (code) >= COAP_RESULT_100)

enum {

	HTTP_RESULT_CODE_CREATED = 201,
	HTTP_RESULT_CODE_DELETED = 202,
	HTTP_RESULT_CODE_VALID = 203,
	HTTP_RESULT_CODE_CHANGED = 204,
	HTTP_RESULT_CODE_CONTENT = 205,

	HTTP_RESULT_CODE_NOT_MODIFIED = 304,

	HTTP_RESULT_CODE_BAD_REQUEST = 400,
	HTTP_RESULT_CODE_UNAUTHORIZED = 401,
	HTTP_RESULT_CODE_BAD_OPTION = 402,
	HTTP_RESULT_CODE_FORBIDDEN = 403,
	HTTP_RESULT_CODE_NOT_FOUND = 404,
	HTTP_RESULT_CODE_METHOD_NOT_ALLOWED = 405,
	HTTP_RESULT_CODE_NOT_ACCEPTABLE = 406,
	HTTP_RESULT_CODE_PRECONDITION_FAILED = 412,
	HTTP_RESULT_CODE_REQUEST_ENTITY_TOO_LARGE = 413,
	HTTP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE = 415,

	HTTP_RESULT_CODE_INTERNAL_SERVER_ERROR = 500,
	HTTP_RESULT_CODE_NOT_IMPLEMENTED = 501,
	HTTP_RESULT_CODE_BAD_GATEWAY = 502,
	HTTP_RESULT_CODE_SERVICE_UNAVAILABLE = 503,
	HTTP_RESULT_CODE_GATEWAY_TIMEOUT = 504,
	HTTP_RESULT_CODE_PROXYING_NOT_SUPPORTED = 505,

	HTTP_RESULT_CODE_TOKEN_REQUIRED = COAP_TO_HTTP_CODE(240),
	HTTP_RESULT_CODE_URI_AUTHORITY_REQUIRED = COAP_TO_HTTP_CODE(241),
	HTTP_RESULT_CODE_UNSUPPORTED_CRITICAL_OPTION = COAP_TO_HTTP_CODE(242),

	// Unofficial result codes, taken from HTTP
	HTTP_RESULT_CODE_CONTINUE = 100,
	HTTP_RESULT_CODE_OK = 200,			// Not valid in recent CoAP versions
	HTTP_RESULT_CODE_SEE_OTHER = 303,
	HTTP_RESULT_CODE_TEMPORARY_REDIRECT = 307,
	HTTP_RESULT_CODE_PARTIAL_CONTENT = 206,
	HTTP_RESULT_CODE_CONFLICT = 409,
	HTTP_RESULT_CODE_GONE = 410,
	HTTP_RESULT_CODE_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
};

#define COAP_HEADER_IS_REQUIRED(x)		((x)&1)

typedef enum {
	COAP_HEADER_INVALID = 255,


	COAP_HEADER_TERI = 0,           //!< draft-bormann-coap-misc-06, reserved in draft-ietf-core-coap-03
	COAP_HEADER_CONTENT_TYPE = 1,
	COAP_HEADER_MAX_AGE = 2,
	COAP_HEADER_PROXY_URI = 3,     //!< draft-bormann-coap-misc-06, reserved in draft-ietf-core-coap-03
	COAP_HEADER_ETAG = 4,
	COAP_HEADER_URI_HOST = 5,
	COAP_HEADER_LOCATION_PATH = 6,
	COAP_HEADER_URI_PORT = 7,   //!< draft-bormann-coap-misc-06, reserved in draft-ietf-core-coap-03
	COAP_HEADER_LOCATION_QUERY = 8,                 //!< draft-bormann-coap-misc-06
	COAP_HEADER_URI_PATH = 9,


	COAP_HEADER_SUBSCRIPTION_LIFETIME = 10, //!< draft-ietf-core-observe

	COAP_HEADER_TOKEN = 11,
	COAP_HEADER_ACCEPT = 12,
	COAP_HEADER_IF_MATCH = 13,
	COAP_HEADER_URI_QUERY = 15,
	COAP_HEADER_IF_NONE_MATCH = 21,

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
} coap_option_key_t;


enum {
	COAP_CONTENT_TYPE_TEXT_PLAIN=0,
	COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT=40,   //!< draft-shelby-core-link-format
	COAP_CONTENT_TYPE_APPLICATION_XML=41,
	COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM=42,
	COAP_CONTENT_TYPE_APPLICATION_EXI=47,
	COAP_CONTENT_TYPE_APPLICATION_JSON=51,

	// UNOFFICIAL AFTER THIS POINT.

	COAP_CONTENT_TYPE_TEXT_XML=1,
	COAP_CONTENT_TYPE_TEXT_CSV=2,
	COAP_CONTENT_TYPE_TEXT_HTML=3,

	COAP_CONTENT_TYPE_IMAGE_GIF=21,
	COAP_CONTENT_TYPE_IMAGE_JPEG=22,
	COAP_CONTENT_TYPE_IMAGE_PNG=23,
	COAP_CONTENT_TYPE_IMAGE_TIFF=24,

	COAP_CONTENT_TYPE_AUDIO_RAW=25,
	COAP_CONTENT_TYPE_VIDEO_RAW=26,

	COAP_CONTENT_TYPE_APPLICATION_RDF_XML=43,
	COAP_CONTENT_TYPE_APPLICATION_SOAP_XML=44,
	COAP_CONTENT_TYPE_APPLICATION_ATOM_XML=45,
	COAP_CONTENT_TYPE_APPLICATION_XMPP_XML=46,
	COAP_CONTENT_TYPE_APPLICATION_X_BXML=48,
	COAP_CONTENT_TYPE_APPLICATION_FASTINFOSET=49,
	COAP_CONTENT_TYPE_APPLICATION_SOAP_FASTINFOSET=50,

	// Experimental after this point. Experimentals start at 201.

	SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED=205,  //!< SMCP Specific

	COAP_CONTENT_TYPE_UNKNOWN = 255,
};

typedef unsigned char coap_content_type_t;

struct coap_header_s {
	uint8_t
		option_count:4,
		tt:2,
		version:2;
	coap_code_t code:8;
	coap_transaction_id_t tid; // Always in network order.
	uint8_t options[0];
};

extern const uint8_t* coap_decode_option(
	const uint8_t* buffer,
	coap_option_key_t* key,
	const uint8_t** value,
	size_t* lenP
);

extern uint8_t* coap_encode_option(
	uint8_t* buffer,
	uint8_t* option_count,
	coap_option_key_t prev_key,
	coap_option_key_t key,
	const uint8_t* value,
	size_t len
);

extern bool coap_option_value_is_string(coap_option_key_t key);

inline static bool
coap_option_strequal(const char* optionptr,const char* cstr) {
	const char* value;
	size_t value_len;
	coap_decode_option((const uint8_t*)optionptr, NULL, (const uint8_t**)&value, &value_len);

	size_t i;
	for(i=0;i<value_len;i++) {
		if(!cstr[i] || (value[i]!=cstr[i]))
			return false;
	}
	return cstr[i]==0;
}

#define coap_option_strequal_const(item,cstr)	coap_option_strequal(item,cstr)

extern const char* coap_content_type_to_cstr(coap_content_type_t ct);
extern coap_content_type_t coap_content_type_from_cstr(const char* x);
extern const char* coap_option_key_to_cstr(
	coap_option_key_t key, bool for_response);
extern coap_option_key_t coap_option_key_from_cstr(const char* key);
extern const char* http_code_to_cstr(int x);
extern const char* coap_code_to_cstr(int x);

//extern const char* coap_option_
extern void coap_dump_header(
	FILE*			outstream,
	const char*		prefix,
	const struct coap_header_s* header,
	size_t packet_size
);

#endif // __SMCP_COAP_H__
