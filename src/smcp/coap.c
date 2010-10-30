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
	uint8_t					header_count
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
	uint8_t*					header_count
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

#if 1
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
		if(content_type < 20)
			snprintf(ret,
				sizeof(ret),
				"text/x-coap-%02x",
				    (unsigned char)content_type);
		else if(content_type < 40)
			snprintf(ret,
				sizeof(ret),
				"image/x-coap-%02x",
				    (unsigned char)content_type);
		else if(content_type < 60)
			snprintf(ret, sizeof(ret), "application/x-coap-%02x",
				    (unsigned char)content_type);
		else if(content_type < 201)
			snprintf(ret, sizeof(ret), "application/x-coap-%02x",
				    (unsigned char)content_type);
		else
			// Experimental
			snprintf(ret, sizeof(ret), "application/x-coap-%02x",
				    (unsigned char)content_type);
		content_type_string = ret;
	}
	return content_type_string;
}

const char*
coap_header_key_to_cstr(coap_header_key_t key) {
	const char* ret = NULL;

	switch(key) {
	case COAP_HEADER_CONTENT_TYPE: ret = "Content-type"; break;
	case COAP_HEADER_MAX_AGE: ret = "Max-age"; break;
	case COAP_HEADER_ETAG: ret = "Etag"; break;
	case COAP_HEADER_URI_AUTHORITY: ret = "URI-authority"; break;
	case COAP_HEADER_LOCATION: ret = "Location"; break;
	case COAP_HEADER_URI_PATH: ret = "URI-path"; break;

	case COAP_HEADER_URI_SCHEME: ret = "URI-scheme"; break;
	case COAP_HEADER_URI_AUTHORITY_BINARY: ret = "URI-authority-binary";
		break;
	case COAP_HEADER_ACCEPT: ret = "Accept"; break;
	case COAP_HEADER_SUBSCRIPTION_LIFETIME: ret = "Subscription-lifetime";
		break;
//		case COAP_HEADER_DATE: ret = "Date"; break;
	case COAP_HEADER_TOKEN: ret = "Token"; break;
	case COAP_HEADER_BLOCK: ret = "Block"; break;
	case COAP_HEADER_URI_QUERY: ret = "URI-query"; break;
//		case COAP_HEADER_PAYLOAD_LENGTH: ret = "Payload-length"; break;

	case SMCP_HEADER_CSEQ: ret = "Cseq"; break;
	case COAP_HEADER_NEXT: ret = "Next"; break;
	case SMCP_HEADER_ORIGIN: ret = "Origin"; break;
	case COAP_HEADER_ALLOW: ret = "Allow"; break;

	case COAP_HEADER_RANGE: ret = "Range"; break;
	case COAP_HEADER_CASCADE_COUNT: ret = "Cascade-count"; break;

	default:
	{
		static char x[30];
		if(key % 14) {
			if(key & 1)
				sprintf(x, "X-Critical-CoAP-%u", key);
			else
				sprintf(x, "X-Elective-CoAP-%u", key);
		} else {
			sprintf(x, "Ignore-%u", key);
		}
		ret = x;
	}
	break;
	}
	return ret;
}

coap_header_key_t
coap_header_key_from_cstr(const char* key) {
	if(strcasecmp(key, "Content-type") == 0)
		return COAP_HEADER_CONTENT_TYPE;
	else if(strcasecmp(key, "Max-age") == 0)
		return COAP_HEADER_MAX_AGE;
	else if(strcasecmp(key, "Etag") == 0)
		return COAP_HEADER_ETAG;
	else if(strcasecmp(key, "URI-authority") == 0)
		return COAP_HEADER_URI_AUTHORITY;
	else if(strcasecmp(key, "Location") == 0)
		return COAP_HEADER_LOCATION;
	else if(strcasecmp(key, "URI-path") == 0)
		return COAP_HEADER_URI_PATH;
	else if(strcasecmp(key, "Cseq") == 0)
		return SMCP_HEADER_CSEQ;
	else if(strcasecmp(key, "Next") == 0)
		return COAP_HEADER_NEXT;
	else if(strcasecmp(key, "Range") == 0)
		return COAP_HEADER_RANGE;
	else if(strcasecmp(key, "Block") == 0)
		return COAP_HEADER_BLOCK;
	else if(strcasecmp(key, "Origin") == 0)
		return SMCP_HEADER_ORIGIN;
	else if(strcasecmp(key, "Allow") == 0)
		return COAP_HEADER_ALLOW;

	return 0;
}


const char*
coap_code_to_cstr(int x) {
	switch(x) {
	case COAP_METHOD_GET: return "GET"; break;
	case COAP_METHOD_POST: return "POST"; break;
	case COAP_METHOD_PUT: return "PUT"; break;
	case COAP_METHOD_DELETE: return "DELETE"; break;

	case COAP_METHOD_PAIR: return "PAIR"; break;
	case COAP_METHOD_UNPAIR: return "UNPAIR"; break;

	case COAP_RESULT_CODE_CONTINUE: return "CONTINUE"; break;
	case COAP_RESULT_CODE_OK: return "OK"; break;
	case COAP_RESULT_CODE_CREATED: return "CREATED"; break;
	case COAP_RESULT_CODE_NO_CONTENT: return "NO_CONTENT"; break;
	case COAP_RESULT_CODE_PARTIAL_CONTENT: return "PARTIAL_CONTENT"; break;

	case COAP_RESULT_CODE_NOT_MODIFIED: return "NOT_MODIFIED"; break;

	case COAP_RESULT_CODE_BAD_REQUEST: return "BAD_REQUEST"; break;
	case COAP_RESULT_CODE_UNAUTHORIZED: return "UNAUTHORIZED"; break;
	case COAP_RESULT_CODE_FORBIDDEN: return "FORBIDDEN"; break;
	case COAP_RESULT_CODE_NOT_FOUND: return "NOT_FOUND"; break;
	case COAP_RESULT_CODE_METHOD_NOT_ALLOWED: return "METHOD_NOT_ALLOWED";
		break;
	case COAP_RESULT_CODE_CONFLICT: return "CONFLICT"; break;
	case COAP_RESULT_CODE_GONE: return "GONE"; break;
	case COAP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE: return
		    "UNSUPPORTED_MEDIA_TYPE"; break;

	case COAP_RESULT_CODE_INTERNAL_SERVER_ERROR: return
		    "INTERNAL_SERVER_ERROR"; break;
	case COAP_RESULT_CODE_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED"; break;
	case COAP_RESULT_CODE_BAD_GATEWAY: return "BAD_GATEWAY"; break;
	case COAP_RESULT_CODE_SERVICE_UNAVAILABLE: return "UNAVAILABLE"; break;
	case COAP_RESULT_CODE_GATEWAY_TIMEOUT: return "TIMEOUT"; break;
	case COAP_RESULT_CODE_PROTOCOL_VERSION_NOT_SUPPORTED: return
		    "PROTOCOL_VERSION_NOT_SUPPORTED"; break;

	case COAP_RESULT_CODE_TOKEN_REQUIRED: return "TOKEN_REQUIRED"; break;
	case COAP_RESULT_CODE_URI_AUTHORITY_REQUIRED: return
		    "URI_AUTHORITY_REQUIRED"; break;
	case COAP_RESULT_CODE_UNSUPPORTED_CRITICAL_OPTION: return
		    "UNSUPPORTED_CRITICAL_OPTION"; break;

	default:  break;
	}
	return "UNKNOWN";
}
#endif
