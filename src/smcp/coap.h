#ifndef __SMCP_COAP_H__
#define __SMCP_COAP_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
//#include <sys/types.h>

#if __CONTIKI__
#include "net/uip.h"
#define htons(x)    uip_htons(x)
#define ntohs(x)    uip_ntohs(x)
#define HTONS(x)    UIP_HTONS(x)
#define NTOHS(x)    UIP_NTOHS(x)
#endif

#define COAP_DEFAULT_PORT   (61616)

#define COAP_VERSION    (1)
#define COAP_TRANS_TYPE_CONFIRMABLE     (0)
#define COAP_TRANS_TYPE_NONCONFIRMABLE  (1)
#define COAP_TRANS_TYPE_ACK             (2)
#define COAP_TRANS_TYPE_RESET           (3)

#define COAP_HEADER_CSTR_LEN        ((size_t)-1)

typedef char coap_transaction_type_t;
typedef uint16_t coap_transaction_id_t;

typedef uint16_t coap_code_t;

static inline uint16_t
coap_to_http_code(uint8_t code) {
	return code / 40 * 100 + code % 40;
}

static inline uint8_t
http_to_coap_code(uint16_t code) {
	return code / 100 * 40 + code % 100;
}

typedef enum {
	COAP_HEADER_TERI = 0,           //!< draft-bormann-coap-misc-06
	COAP_HEADER_CONTENT_TYPE = 1,
	COAP_HEADER_MAX_AGE = 2,
	COAP_HEADER_URI_SCHEME = 3,     //!< draft-bormann-coap-misc-06
	COAP_HEADER_ETAG = 4,
	COAP_HEADER_URI_AUTHORITY = 5,
	COAP_HEADER_LOCATION = 6,
	COAP_HEADER_URI_AUTHORITY_BINARY = 7,   //!< draft-bormann-coap-misc-06
	COAP_HEADER_ACCEPT = 8,                 //!< draft-bormann-coap-misc-06
	COAP_HEADER_URI_PATH = 9,
	COAP_HEADER_DATE = 10,                  //!< draft-bormann-coap-misc-06
	COAP_HEADER_TOKEN = 11,                 //!< draft-bormann-coap-misc-06
	COAP_HEADER_BLOCK = 13,                 //!< draft-bormann-core-coap-block-00
	COAP_HEADER_PAYLOAD_LENGTH = 15,        //!< draft-bormann-coap-misc-06

	COAP_HEADER_FENCEPOST_1 = 14,
	COAP_HEADER_FENCEPOST_2 = 28,

	// Experimental after this point

	COAP_HEADER_CASCADE_COUNT = COAP_HEADER_FENCEPOST_2 + 1,    //!< Used for preventing pairing loops.
	COAP_HEADER_RANGE = COAP_HEADER_FENCEPOST_2 + 2,            //!< Experimental alternative to draft-bormann-core-coap-block-00
	COAP_HEADER_NEXT = COAP_HEADER_FENCEPOST_2 + 3,             //!< Experimental alternative to draft-bormann-core-coap-block-00
	COAP_HEADER_ORIGIN = COAP_HEADER_FENCEPOST_2 + 4,           //!< Used for SMCP Pairing.
	COAP_HEADER_CSEQ = COAP_HEADER_FENCEPOST_2 + 6,             //!< Used for SMCP Pairing.
	COAP_HEADER_ALLOW = COAP_HEADER_FENCEPOST_2 + 8,
} coap_header_key_t;

typedef struct {
	coap_header_key_t	key;
	char*				value;
	size_t				value_len;
} coap_header_item_t;

typedef enum {
	COAP_CONTENT_TYPE_TEXT_PLAIN = 0,
	COAP_CONTENT_TYPE_TEXT_XML = 1,
	COAP_CONTENT_TYPE_TEXT_CSV = 2,
	COAP_CONTENT_TYPE_TEXT_HTML = 3,

	COAP_CONTENT_TYPE_IMAGE_GIF = 21,
	COAP_CONTENT_TYPE_IMAGE_JPEG = 22,
	COAP_CONTENT_TYPE_IMAGE_PNG = 23,
	COAP_CONTENT_TYPE_IMAGE_TIFF = 24,

	COAP_CONTENT_TYPE_AUDIO_RAW = 25,
	COAP_CONTENT_TYPE_VIDEO_RAW = 26,

	COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT = 40, //!< draft-shelby-core-link-format
	COAP_CONTENT_TYPE_APPLICATION_XML = 41,
	COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM = 42,
	COAP_CONTENT_TYPE_APPLICATION_RDF_XML = 43,
	COAP_CONTENT_TYPE_APPLICATION_SOAP_XML = 44,
	COAP_CONTENT_TYPE_APPLICATION_ATOM_XML = 45,
	COAP_CONTENT_TYPE_APPLICATION_XMPP_XML = 46,
	COAP_CONTENT_TYPE_APPLICATION_EXI = 47,
	COAP_CONTENT_TYPE_APPLICATION_X_BXML = 48,
	COAP_CONTENT_TYPE_APPLICATION_FASTINFOSET = 49,
	COAP_CONTENT_TYPE_APPLICATION_SOAP_FASTINFOSET = 50,
	COAP_CONTENT_TYPE_APPLICATION_JSON = 51,

	// Experimental after this point. Experimentals start at 201.

	SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED = 205, //!< SMCP Specific

	COAP_CONTENT_TYPE_UNKNOWN = 255,
} coap_content_type_t;

extern size_t coap_encode_header(
	unsigned char*			buffer,
	size_t					buffer_len,
	coap_transaction_type_t tt,
	coap_code_t				code,
	coap_transaction_id_t	tid,
	coap_header_item_t		headers[],
	size_t					header_count
);

extern size_t coap_decode_header(
	unsigned char*				buffer,
	size_t						buffer_len,
	coap_transaction_type_t*	tt,
	coap_code_t*				code,
	coap_transaction_id_t*		tid,
	coap_header_item_t*			headers,
	size_t*						header_count
);

extern const char* coap_content_type_to_cstr(
	coap_content_type_t content_type);


#endif // __SMCP_COAP_H__
