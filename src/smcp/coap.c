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


const char*
coap_content_type_to_cstr(coap_content_type_t content_type) {
	const char* content_type_string = NULL;

	if((content_type > 255) || (content_type < 0))
		content_type = COAP_CONTENT_TYPE_UNKNOWN;

	switch(content_type) {
	case COAP_CONTENT_TYPE_UNKNOWN: content_type_string = "unknown"; break;

	case COAP_CONTENT_TYPE_TEXT_PLAIN: content_type_string = "text/plain";
		break;
	case COAP_CONTENT_TYPE_TEXT_XML: content_type_string = "text/xml";
		break;
	case COAP_CONTENT_TYPE_TEXT_CSV: content_type_string = "text/csv";
		break;
	case COAP_CONTENT_TYPE_TEXT_HTML: content_type_string = "text/html";
		break;

	case COAP_CONTENT_TYPE_IMAGE_GIF: content_type_string = "image/gif";
		break;
	case COAP_CONTENT_TYPE_IMAGE_JPEG: content_type_string = "image/jpeg";
		break;
	case COAP_CONTENT_TYPE_IMAGE_PNG: content_type_string = "image/png";
		break;
	case COAP_CONTENT_TYPE_IMAGE_TIFF: content_type_string = "image/tiff";
		break;

	case COAP_CONTENT_TYPE_AUDIO_RAW: content_type_string = "audio/raw";
		break;
	case COAP_CONTENT_TYPE_VIDEO_RAW: content_type_string = "video/raw";
		break;

	case COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT: content_type_string =
		    "application/link-format"; break;
	case COAP_CONTENT_TYPE_APPLICATION_XML: content_type_string =
		    "application/xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM: content_type_string =
		    "application/octet-stream"; break;
	case COAP_CONTENT_TYPE_APPLICATION_RDF_XML: content_type_string =
		    "application/rdf+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_SOAP_XML: content_type_string =
		    "application/soap+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_ATOM_XML: content_type_string =
		    "application/atom+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_XMPP_XML: content_type_string =
		    "application/xmpp+xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_EXI: content_type_string =
		    "application/exi"; break;

	case COAP_CONTENT_TYPE_APPLICATION_X_BXML: content_type_string =
		    "application/x-bxml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_FASTINFOSET: content_type_string =
		    "application/fastinfoset"; break;
	case COAP_CONTENT_TYPE_APPLICATION_SOAP_FASTINFOSET:
		content_type_string = "application/soap+fastinfoset"; break;
	case COAP_CONTENT_TYPE_APPLICATION_JSON: content_type_string =
		    "application/json"; break;

	case SMCP_CONTENT_TYPE_APPLICATION_FORM_URLENCODED:
		content_type_string = "application/x-www-form-urlencoded"; break;

	default: break;
	}
	if(!content_type_string) {
		// TODO: Make thread safe!
		static char ret[40];
		if(content_type < 20) {
			snprintf(ret,
				sizeof(ret),
				"text/x-coap-%02x",
				    (unsigned char)content_type);
		} else if(content_type < 40) {
			snprintf(ret,
				sizeof(ret),
				"image/x-coap-%02x",
				    (unsigned char)content_type);
		} else if(content_type < 60) {
			snprintf(ret, sizeof(ret), "application/x-coap-%02x",
				    (unsigned char)content_type);
		} else if(content_type < 201) {
			snprintf(ret, sizeof(ret), "application/x-coap-%02x",
				    (unsigned char)content_type);
		} else {
			// Experimental
			snprintf(ret, sizeof(ret), "application/x-coap-%02x",
				    (unsigned char)content_type);
		}
		content_type_string = ret;
	}
	return content_type_string;
}
