#ifndef __SMCP_COAP_H__
#define __SMCP_COAP_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

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
	COAP_HEADER_CONTENT_TYPE = 1,
	COAP_HEADER_MAX_AGE = 2,
	COAP_HEADER_ETAG = 4,           //!< @note UNUSED IN SMCP
	COAP_HEADER_URI_AUTHORITY = 5,  //!< @note UNUSED IN SMCP
	COAP_HEADER_LOCATION = 6,       //!< @note UNUSED IN SMCP
	COAP_HEADER_URI_PATH = 9,       //!< @note UNUSED IN SMCP
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
