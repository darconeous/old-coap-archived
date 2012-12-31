/*	@file coap.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef __SMCP_COAP_H__
#define __SMCP_COAP_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#if CONTIKI
#include "contiki.h"
#include "net/uip.h"
#define htons(x)    uip_htons(x)
#define ntohs(x)    uip_ntohs(x)
#define HTONS(x)    UIP_HTONS(x)
#define NTOHS(x)    UIP_NTOHS(x)
#endif

#define COAP_VERSION    (1)

// Port numbers
#define COAP_DEFAULT_PORT			(5683)
#define COAP_DEFAULT_TLSPORT		(COAP_DEFAULT_PORT+100)	// Guess
#define COAP_DEFAULT_PROXY_PORT		(COAP_DEFAULT_PORT+1)	// Guess
#define COAP_DEFAULT_PROXY_TLS_PORT	(COAP_DEFAULT_PORT+101)	// Guess

// General limits.
#define COAP_MAX_MESSAGE_SIZE				(1280-40)
#define COAP_MAX_TOKEN_SIZE					(8)
#define COAP_MAX_OPTION_VALUE_SIZE			(1034)
#define COAP_MAX_ACK_RETRANSMIT_DURATION	(14)		// Seconds
#define COAP_DEFAULT_MAX_AGE				(60)

// The following constants are defined by
// <http://tools.ietf.org/html/draft-ietf-core-coap-13#section-4.8>
#define COAP_ACK_TIMEOUT		(1.5f)	//!^ Seconds (spec says to set to `2`)
#define COAP_ACK_RANDOM_FACTOR	(1.5f)
#define COAP_MAX_RETRANSMIT     (5)		//!^ Attempts (spec says to set to `4`)
#define COAP_NSTART				(1)
#define COAP_DEFAULT_LEASURE    (5)		//!^ Seconds
#define COAP_PROBING_RATE       (1)		//!^ Bytes/Second

#define COAP_MAX_LATENCY		(100)	//!^ Seconds

// Derived constants
#define COAP_MAX_TRANSMIT_SPAN	(COAP_ACK_TIMEOUT * ((1<<COAP_MAX_RETRANSMIT) - 1) * COAP_ACK_RANDOM_FACTOR)
#define COAP_MAX_TRANSMIT_WAIT	(COAP_ACK_TIMEOUT * ((1<<(COAP_MAX_RETRANSMIT + 1)) - 1) * COAP_ACK_RANDOM_FACTOR)
#define COAP_PROCESSING_DELAY	(COAP_ACK_TIMEOUT)
#define COAP_MAX_RTT			(2*COAP_MAX_LATENCY+COAP_PROCESSING_DELAY)
#define COAP_EXCHANGE_LIFETIME	((COAP_ACK_TIMEOUT * ((1<<COAP_MAX_RETRANSMIT) - 1) * COAP_ACK_RANDOM_FACTOR) + (2 * COAP_MAX_LATENCY) + COAP_PROCESSING_DELAY)
#define COAP_NON_LIFETIME		(COAP_MAX_TRANSMIT_SPAN + COAP_MAX_LATENCY)

typedef char coap_transaction_type_t;
typedef uint16_t coap_msg_id_t;
typedef uint16_t coap_code_t;

#define COAP_TO_HTTP_CODE(x)     ((x) / 32 * 100 + (x) % 32)
extern uint16_t coap_to_http_code(uint8_t x);

#define HTTP_TO_COAP_CODE(x)     ((x) / 100 * 32 + (x) % 100)
extern uint8_t http_to_coap_code(uint16_t x);

enum {
	COAP_CODE_EMPTY = 0,
	COAP_METHOD_GET = 1,
	COAP_METHOD_POST = 2,
	COAP_METHOD_PUT = 3,
	COAP_METHOD_DELETE = 4,
};

enum {
	COAP_TRANS_TYPE_CONFIRMABLE = 0,
	COAP_TRANS_TYPE_NONCONFIRMABLE = 1,
	COAP_TRANS_TYPE_ACK = 2,
	COAP_TRANS_TYPE_RESET = 3,
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
	COAP_RESULT_408_REQUEST_INCOMPLETE = HTTP_TO_COAP_CODE(408),
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

#define COAP_CODE_IS_REQUEST(code)	(((code)) > 0 && ((code) < COAP_RESULT_100))
#define COAP_CODE_IS_RESULT(code)	(!(code) || (code) >= COAP_RESULT_100)

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
	HTTP_RESULT_CODE_REQUEST_TIMEOUT= 408,
	HTTP_RESULT_CODE_PRECONDITION_FAILED = 412,
	HTTP_RESULT_CODE_REQUEST_ENTITY_TOO_LARGE = 413,
	HTTP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE = 415,

	HTTP_RESULT_CODE_INTERNAL_SERVER_ERROR = 500,
	HTTP_RESULT_CODE_NOT_IMPLEMENTED = 501,
	HTTP_RESULT_CODE_BAD_GATEWAY = 502,
	HTTP_RESULT_CODE_SERVICE_UNAVAILABLE = 503,
	HTTP_RESULT_CODE_GATEWAY_TIMEOUT = 504,
	HTTP_RESULT_CODE_PROXYING_NOT_SUPPORTED = 505,

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

#define COAP_OPTION_IS_CRITICAL(x)		((x)&1)
#define COAP_OPTION_IS_UNSAFE(x)		((x)&2)
#define COAP_OPTION_IS_NOCACHEKEY(x)	(((x)&0x1e)==0x1c)

typedef enum {
	COAP_OPTION_INVALID				= 65535,	//!< Somewhat arbitrary value.

	COAP_OPTION_IF_MATCH			= 1,
	COAP_OPTION_URI_HOST			= 3,
	COAP_OPTION_ETAG				= 4,
	COAP_OPTION_IF_NONE_MATCH		= 5,
	COAP_OPTION_OBSERVE				= 6,
	COAP_OPTION_URI_PORT			= 7,
	COAP_OPTION_LOCATION_PATH		= 8,
	COAP_OPTION_URI_PATH			= 11,
	COAP_OPTION_CONTENT_TYPE		= 12,
	COAP_OPTION_MAX_AGE				= 14,
	COAP_OPTION_URI_QUERY			= 15,
	COAP_OPTION_ACCEPT				= 16,
	COAP_OPTION_LOCATION_QUERY		= 20,
	COAP_OPTION_BLOCK2				= 23,	/* draft-ietf-core-block-10 */
	COAP_OPTION_BLOCK1				= 27,	/* draft-ietf-core-block-10 */
	COAP_OPTION_SIZE				= 28,	/* draft-ietf-core-block-10 */
	COAP_OPTION_PROXY_URI			= 35,

	//////////////////////////////////////////////////////////////////////
	// Experimental after this point. Experimentals start at 65000.

	COAP_OPTION_CASCADE_COUNT = 65100 + 1,    //!< Used for preventing pairing loops.
	COAP_OPTION_AUTHENTICATE = 65100 + 2,

	SMCP_OPTION_ORIGIN = 65100 + 4,           //!< Used for SMCP Pairing.
	SMCP_OPTION_CSEQ = 65100 + 6,             //!< Used for SMCP Pairing.
} coap_option_key_t;


enum {
	COAP_CONTENT_TYPE_TEXT_PLAIN=0,
	COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT=40,   //!< draft-shelby-core-link-format
	COAP_CONTENT_TYPE_APPLICATION_XML=41,
	COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM=42,
	COAP_CONTENT_TYPE_APPLICATION_EXI=47,
	COAP_CONTENT_TYPE_APPLICATION_JSON=50,

	//////////////////////////////////////////////////////////////////////
	// Unofficial after this point

	COAP_CONTENT_TYPE_TEXT_XML=1,
	COAP_CONTENT_TYPE_TEXT_CSV=2,
	COAP_CONTENT_TYPE_TEXT_HTML=3,

	COAP_CONTENT_TYPE_IMAGE_GIF=21,
	COAP_CONTENT_TYPE_IMAGE_JPEG=22,
	COAP_CONTENT_TYPE_IMAGE_PNG=23,
	COAP_CONTENT_TYPE_IMAGE_TIFF=24,

	COAP_CONTENT_TYPE_AUDIO_RAW=25,
	COAP_CONTENT_TYPE_VIDEO_RAW=26,

	//////////////////////////////////////////////////////////////////////
	// Experimental after this point. Experimentals start at 65000.

	SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED=65005,  //!< SMCP Specific

	COAP_CONTENT_TYPE_UNKNOWN = 65535,
};

typedef uint16_t coap_content_type_t;

struct coap_header_s {
#if __BIG_ENDIAN__
	uint8_t
		version:2,
		tt:2,
		token_len:4;
#else
	uint8_t
		token_len:4,
		tt:2,
		version:2;
#endif
	coap_code_t code:8;
	coap_msg_id_t msg_id; // Always in network order.
	uint8_t token[0];
};

extern uint8_t* coap_decode_option(
	const uint8_t* buffer,
	coap_option_key_t* key,
	const uint8_t** value,
	size_t* lenP
);

extern uint8_t* coap_encode_option(
	uint8_t* buffer,
	coap_option_key_t prev_key,
	coap_option_key_t key,
	const uint8_t* value,
	size_t len
);

// Correctly inserts an option maintining order.
// Returns the number of bytes inserted into the options.
extern size_t coap_insert_option(
	uint8_t* start_of_options,
	uint8_t* end_of_options,
	coap_option_key_t key,
	const uint8_t* value,
	size_t len
);

extern bool coap_option_value_is_string(coap_option_key_t key);

extern bool coap_option_strequal(const char* optionptr,const char* cstr);

#define coap_option_strequal_const(item,cstr)	coap_option_strequal(item,cstr)

// The following functions are not recommended on embedded platforms.

extern const char* coap_content_type_to_cstr(coap_content_type_t ct);
extern coap_content_type_t coap_content_type_from_cstr(const char* x);
extern const char* coap_option_key_to_cstr(coap_option_key_t key, bool for_response);
extern coap_option_key_t coap_option_key_from_cstr(const char* key);
extern const char* http_code_to_cstr(int x);
extern const char* coap_code_to_cstr(int x);

extern bool coap_verify_packet(const char* packet,size_t packet_size);

#if !CONTIKI
#include <stdio.h>
extern void coap_dump_header(
	FILE*			outstream,
	const char*		prefix,
	const struct coap_header_s* header,
	size_t packet_size
);
#endif

#endif // __SMCP_COAP_H__
