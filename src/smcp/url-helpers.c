#include "assert_macros.h"
#include "url-helpers.h"
#include "ctype.h"
#include <string.h>

//#define VERBOSE_DEBUG 1

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

#if __AVR__
#include <avr/pgmspace.h>
static char int_to_hex_digit(uint8_t x) {
	return pgm_read_byte_near(PSTR(
			"0123456789ABCDEF") + (x & 0xF));
}
#else
static char int_to_hex_digit(uint8_t x) {
	return "0123456789ABCDEF"[x &
	    0xF];
}
#endif

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
			*dest++ = int_to_hex_digit(src_char >> 4);
			*dest++ = int_to_hex_digit(src_char & 0xF);
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
	size_t bytes_parsed = 0;
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
	char*	uri,
	char**	protocol,
	char**	username,
	char**	password,
	char**	host,
	char**	port,
	char**	path,
	char**	query
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
				got_port = true;
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
	while((isurlchar(*uri) || (*uri == '/') || (*uri == '=') ||
	            (*uri == '&') ||
	            (*uri == '%')) && (*uri != '#') && (*uri != '?')) {
		uri++;
		bytes_parsed++;
	}

	// Handle query component
	if(*uri == '?') {
		*uri++ = 0;
		bytes_parsed++;

		if(query)
			*query = uri;

		// Move to the end of the query.
		while((isurlchar(*uri) || (*uri == '/') || (*uri == '=') ||
		            (*uri == '&') || (*uri == ';') ||
		            (*uri == '%')) && (*uri != '#')) {
			uri++;
			bytes_parsed++;
		}
	}

	// Zero terminate
	if(*uri) {
		*uri = 0;
		bytes_parsed++;
	}

bail:
	return bytes_parsed;
}

extern bool url_is_absolute(const char* uri) {
	bool ret = false;
	int bytes_parsed = 0;

	require(uri, bail);

	while(*uri && isalpha(*uri) && (*uri != ':')) {
		require(*uri, bail);
		uri++;
		bytes_parsed++;
	}

	if(bytes_parsed && *uri == ':')
		ret = true;

bail:
	return ret;
}

//!< Used to identify IPv6 address strings
bool
string_contains_colons(const char* str) {
	if(!str)
		return false;
	for(; (*str != ':') && *str; str++) ;
	return *str == ':';
}

extern bool url_change(
	char* url, const char* new_url_
) {
	bool ret = false;

	if(url_is_absolute(new_url_)) {
		strcpy(url, new_url_);
		ret = true;
		goto bail;
	}

	{
		char new_url[strlen(new_url_) + 1];
		strcpy(new_url, new_url_);

		char current_path[MAX_URL_SIZE];
		char* proto_str = NULL;
		char* path_str = NULL;
		char* addr_str = NULL;
		char* port_str = NULL;

		strcpy(current_path, url);

		url_parse(current_path,
			&proto_str,
			NULL,
			NULL,
			&addr_str,
			&port_str,
			&path_str,
			NULL);

#if VERBOSE_DEBUG
		fprintf(
			stderr,
			"url_change: proto=\"%s\", host=\"%s\", port=\"%s\", path=\"%s\"\n",
			proto_str,
			addr_str,
			port_str,
			path_str);
#endif

		if(!proto_str) {
#if VERBOSE_DEBUG
			fprintf(stderr, "Must cd into full URL first\n");
#endif
			ret = false;
			goto bail;
		}

		if(!addr_str) {
#if VERBOSE_DEBUG
			fprintf(stderr, "Bad base URL.\n");
#endif
			ret = false;
			goto bail;
		}

		url[0] = 0;

		if(proto_str) {
			strcat(url, proto_str);
			strcat(url, "://");

			// Path is absolute. Must drop the path from the URL.
			if(string_contains_colons(addr_str)) {
				strcat(url, "[");
				strcat(url, addr_str);
				strcat(url, "]");
			} else {
				strcat(url, addr_str);
			}

			if(port_str) {
				strcat(url, ":");
				strcat(url, port_str);
			}
		}

		{
			char* path_components[URL_HELPERS_MAX_URL_COMPONENTS];
			char** pp = path_components;
			int path_items = 0;

			if(new_url[0] != '/') {
				while((*pp = strsep(&path_str, "/"))) {
					if(strcmp(*pp, "..") == 0) {
						if(path_items) {
							pp--;
							path_items--;
						}
					} else if(strcmp(*pp, ".") == 0) {
					} else if(**pp != '\0') {
						pp++;
						path_items++;
					}
				}
			}

			path_str = new_url;
			while((*pp = strsep(&path_str, "/"))) {
				if(strcmp(*pp, "..") == 0) {
					if(path_items) {
						pp--;
						path_items--;
					}
				} else if(strcmp(*pp, ".") == 0) {
				} else if(**pp != '\0') {
					pp++;
					path_items++;
				}
			}


			for(pp = path_components; path_items; path_items--, pp++) {
				strcat(url, "/");
				strcat(url, *pp);
			}
			//strcat(url,"/");
		}

		ret = true;
	}
bail:
#if VERBOSE_DEBUG
	fprintf(stderr, "url_change: final-url=\"%s\"\n", url);
#endif

	return ret;
}


void
url_shorten_reference(
	const char* current_url, char* new_url
) {
	// TODO: Implement me!
/*

    if(url_is_absolute(new_url)) {
        char temp[256];
        strncpy(temp,current_url,sizeof(temp);
        char* proto1;
        char* proto2;
        url_parse(current_path, NULL,NULL,NULL, NULL, NULL, (char**)&current_url,NULL);
        //url_parse(temp, NULL, NULL, NULL, (char**)&current_url);
    }

    if(path_is_absolute(new_url)) {
        char temp[256];
        strncpy(temp,current_url,sizeof(temp);
        url_parse(temp, NULL, NULL, NULL, (char**)&current_url);
        strncmp(new_url+1,current_url,strlen(current_url))

    }

    char temp[MAX_URL_SIZE];
    int i,j;
    strncpy(temp,current_url,sizeof(temp);

    url_change(temp,new_url);

    if(0!=memcmp(temp,current_url,7)) {
        strcpy(new_url,temp);
        return;
    }

    for(i=7;temp[i]!='/';i++) {	}

    if(0!=memcmp(temp,current_url,i)) {
        strcpy(new_url,temp);
        return;
    }

    j=i;

    for(;temp[i]==current_url[i];i++) {
        if(temp[i]=='/')
            j=i;
    }

    if(!temp[i]temp[i]==current_url[i]))

    for(j=0;temp[i];)
        new_url[j++] = temp[i++];

    new_url[j] = 0;
 */
}
