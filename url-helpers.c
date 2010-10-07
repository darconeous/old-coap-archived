#include "url-helpers.h"
#include "ctype.h"

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

		if(isalnum(src_char)
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
		    || (src_char == ',')
		) {
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
