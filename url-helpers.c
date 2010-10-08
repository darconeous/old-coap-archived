#include "assert_macros.h"
#include "url-helpers.h"
#include "ctype.h"

static bool
isurlchar(int src_char) {
	return isalnum(src_char)
	       || (src_char == '$')
	       || (src_char == '-')
	       || (src_char == '_')
	       || (src_char == '.')
	       || (src_char == '+')
	       || (src_char == '!')
	       || (src_char == '*')
	       || (src_char == '\'')
	       || (src_char == '(')
	       || (src_char == ')')
	       || (src_char == ',');
}

size_t
url_encode_cstr(
	char *dest, const char*src, size_t max_size
) {
	size_t ret = 0;

	max_size--;

	while(true) {
		const char src_char = *src++;
		if(!src_char)
			break;

		if(!max_size) {
			ret++;
			break;
		}

		if(isurlchar(src_char)) {
			*dest++ = src_char;
			ret++;
			max_size--;
		} else {
			if(max_size < 3) {
				// Too small for the next character.
				ret++;
				break;
			}

			*dest++ = '%';
			*dest++ = "0123456789abcdef"[src_char >> 4];
			*dest++ = "0123456789abcdef"[src_char & 0xF];
			ret += 3;
			max_size -= 3;
		}
	}

	*dest = 0;

	return ret;
}

static char
hex_digit_to_int(char c) {
	switch(c) {
	case '0': return 0; break;
	case '1': return 1; break;
	case '2': return 2; break;
	case '3': return 3; break;
	case '4': return 4; break;
	case '5': return 5; break;
	case '6': return 6; break;
	case '7': return 7; break;
	case '8': return 8; break;
	case '9': return 9; break;
	case 'A':
	case 'a': return 10; break;
	case 'B':
	case 'b': return 11; break;
	case 'C':
	case 'c': return 12; break;
	case 'D':
	case 'd': return 13; break;
	case 'E':
	case 'e': return 14; break;
	case 'F':
	case 'f': return 15; break;
	}
	return 0;
}

size_t
url_decode_cstr(
	char *dest, const char*src, size_t max_size
) {
	size_t ret = 0;

	max_size--;

	while(true) {
		const char src_char = *src++;
		if(!src_char)
			break;

		if(!max_size) {
			ret++;
			break;
		}

		if((src_char == '%') && src[0] && src[1]) {
			*dest++ = (hex_digit_to_int(src[0]) << 4) + hex_digit_to_int(
				src[1]);
			src += 2;
		} else {
			*dest++ = src_char;
		}

		ret++;
		max_size--;
	}

	*dest = 0;

	return ret;
}

void
url_decode_cstr_inplace(char *str) {
	url_decode_cstr(str, str, 0);
}

size_t
url_form_next_value(
	char** form_string, char** key, char** value
) {
	size_t bytes_parsed;
	char c = **form_string;

	if(!c) {
		*key = NULL;
		*value = NULL;
		goto bail;
	}

	*key = *form_string;

	while(true) {
		c = **form_string;

		if(!c) {
			*value = NULL;
			goto bail;
		}

		if(c == '=')
			break;

		bytes_parsed++;

		if((c == ';') || (c == '&')) {
			*(*form_string)++ = 0;
			    (*form_string)++;
			*value = NULL;
			goto bail;
		}

		    (*form_string)++;
	}

	// Zero terminate the key.
	*(*form_string)++ = 0;
	bytes_parsed++;

	*value = *form_string;

	while(true) {
		c = **form_string;

		if(!c || (c == ';') || (c == '&'))
			break;

		bytes_parsed++;
		    (*form_string)++;
	}

	// Zero terminate the value
	*(*form_string)++ = 0;
	bytes_parsed++;

bail:
	if(*value)
		url_decode_cstr_inplace(*value);

	return bytes_parsed;
}


int
url_parse(
	char* uri, char** protocol, char** host, char** port, char** path
) {
	int bytes_parsed = 0;

	require_string(uri, bail, "NULL uri parameter");

	if(protocol)
		*protocol = uri;

	while(*uri != ':') {
		require_string(*uri, bail, "unexpected end of string");
		uri++;
		bytes_parsed++;
	}

	// Zero terminate the protocol;
	*uri++ = 0;
	bytes_parsed++;

	require_string(*uri, bail, "unexpected end of string");

	if(uri[0] == '/' && uri[1] == '/') {
		char* addr_end;
		char* addr_begin;
		bool got_port = false;

		// Contains a hostname. Parse it.
		uri += 2;
		bytes_parsed += 2;

		addr_begin = uri;

		while((isurlchar(*uri) || (*uri == '[') || (*uri == ']') ||
		            (*uri == ':') || (*uri == '@')) && (*uri != '/')) {
			uri++;
			bytes_parsed++;
		}

		addr_end = uri - 1;

		if(*uri) {
			*uri++ = 0;
			bytes_parsed++;
		}

		for(;
		        (addr_end >= addr_begin) && (*addr_end != '@') &&
		        (*addr_end != '[');
		    addr_end--) {
			if((*addr_end == ']')) {
				*addr_end = 0;
			} else if(!got_port && (*addr_end == ':')) {
				if(port)
					*port = addr_end + 1;
				*addr_end = 0;
				got_port = true;
			}
		}
		if(host)
			*host = addr_end + 1;
	}

	if(path)
		*path = uri;

	// Move to the end of the path.
	while((isurlchar(*uri) || (*uri == '/') ||
	            (*uri == '?')) && (*uri != '#')) {
		uri++;
		bytes_parsed++;
	}

	// Zero terminate the path
	if(*uri) {
		*uri++ = 0;
		bytes_parsed++;
	}

bail:
	return bytes_parsed;
}
