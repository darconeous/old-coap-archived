#ifndef __SMCP_COAP_H__
#define __SMCP_COAP_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

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

	COAP_HEADER_CSEQ = COAP_HEADER_FENCEPOST_2 + 1,
	COAP_HEADER_NEXT = COAP_HEADER_FENCEPOST_2 + 3,
	COAP_HEADER_ORIGIN = COAP_HEADER_FENCEPOST_2 + 4,
	COAP_HEADER_ALLOW = COAP_HEADER_FENCEPOST_2 + 5,

	/*! The Range option allows you to specify
	**	to the server that you want to request
	**	a maximum of a certain number of bytes
	**	from a resource, starting at a specific
	**	byte. Its value is formed by two
	**	unsigned integers using for format described
	**	in <http://www.w3.org/TR/exi/#encodingUnsignedInteger>.
	**	The first unsigned integer represents the requested
	**	maximum returned content size. The second unsigned
	**	integer is optional and contains the byte offset
	**	into the requested content. If the second
	**	integer is omitted, the offset is implied to be zero.
	**
	**	When used in concert with the Next option,
	**	the value of the range header in the client
	**	requests MUST be the same for each request.
	**	Otherwise the behavior is undefined.
	*/
	COAP_HEADER_RANGE = COAP_HEADER_FENCEPOST_2 + 2,
} coap_header_key_t;

typedef struct {
	coap_header_key_t	key;
	char*				value;
	size_t				value_len;
} coap_header_item_t;

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


#endif // __SMCP_COAP_H__
