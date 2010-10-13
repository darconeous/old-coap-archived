#include "assert_macros.h"
#include "coap.h"
#include <stdlib.h>

// Used by qsort
static int
header_compare(
	coap_header_item_t*rhs, coap_header_item_t*lhs
) {
	if(rhs->key < lhs->key)
		return -1;
	else if(rhs->key > lhs->key)
		return 1;
	return 0;
}

size_t
coap_encode_header(
	unsigned char*			buffer,
	size_t					buffer_len,
	coap_transaction_type_t tt,
	coap_code_t				code,
	coap_transaction_id_t	tid,
	coap_header_item_t		headers[],
	size_t					header_count
) {
	size_t ret = 0;

	require(buffer, bail);
	require(buffer_len >= 4, bail);

	buffer[0] = (COAP_VERSION << 6) + (tt << 4);
	buffer[1] = code;

	tid = htons(tid);
	buffer[2] = ((const unsigned char*)&tid)[0];
	buffer[3] = ((const unsigned char*)&tid)[1];

	ret = 4;

	if(headers && header_count) {
		unsigned char* header_ptr = buffer + 4;
		unsigned char last_option = 0;
		unsigned char option_delta;

		// Headers must be in order.
		qsort(
			headers,
			header_count,
			sizeof(*headers),
			    (int (*)(const void*, const void*)) & header_compare
		);

		for(; header_count; header_count--, headers++) {
			option_delta = headers->key - last_option;

			// Add "fenceposts" as necessary.
			while(option_delta >= 15) {
				option_delta = (last_option / 14 * 14 + 14) - last_option;
				*header_ptr++ = (option_delta << 4);
				ret++;
				buffer[0]++;    // Increase the total header count.

				last_option = (last_option / 14 * 14 + 14);
				option_delta = headers->key - last_option;
			}

			// Increase the total header count.
			buffer[0]++;

			last_option = headers->key;

			if(headers->value_len > 270)
				headers->value_len = strlen(headers->value);

			if(headers->value_len > 14) {
				check(headers->value_len < (255 + 15));
				*header_ptr++ = (option_delta << 4) | 0xF;
				*header_ptr++ = headers->value_len - 15;
				memcpy(header_ptr, headers->value, headers->value_len);
				ret += 2 + headers->value_len;
				header_ptr += headers->value_len;
			} else {
				*header_ptr++ = (option_delta << 4) | headers->value_len;
				memcpy(header_ptr, headers->value, headers->value_len);
				ret += 1 + headers->value_len;
				header_ptr += headers->value_len;
			}
		}
	}

bail:
	return ret;
}

size_t
coap_decode_header(
	unsigned char*				buffer,
	size_t						buffer_len,
	coap_transaction_type_t*	tt,
	coap_code_t*				code,
	coap_transaction_id_t*		tid,
	coap_header_item_t*			headers,
	size_t*						header_count
) {
	size_t ret = 0;
	unsigned char remaining_headers = 0;
	unsigned char last_header = 0;
	unsigned char max_headers = 0;

	require(buffer, bail);
	require(buffer_len >= 4, bail);

	require((buffer[0] >> 6) == COAP_VERSION, bail);

	if(tt)
		*tt = ((buffer[0] >> 4) & 3);

	remaining_headers = (buffer[0] & 0xF);

	if(code)
		*code = buffer[1];

	if(tid)
		*tid = (buffer[2] << 8) + buffer[3];

	ret += 4;
	buffer += 4;

	if(header_count && headers) {
		max_headers = *header_count;
		*header_count = 0;
	}

	while(remaining_headers--) {
		uint16_t len = (*buffer & 0xF);
		last_header += (*buffer++ >> 4);

		if(len == 0xF) {
			len += *buffer++;
			ret += 2;
		} else {
			ret++;
		}

		if(max_headers && (last_header % 14)) {
			headers->key = last_header;
			headers->value = (char*)buffer;
			headers->value_len = len;
			headers++;
			    (*header_count)++;
			max_headers--;
		}

		buffer += len;
		ret += len;
	}

bail:
	return ret;
}
