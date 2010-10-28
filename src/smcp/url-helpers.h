#ifndef __URL_HELPERS_H__
#define __URL_HELPERS_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define URL_HELPERS_MAX_URL_COMPONENTS      (15)
#define MAX_URL_SIZE        (128)

/*!	Perfoms a URL encoding of the given string.
**	@returns	Number of bytes in encoded string
*/
extern size_t url_encode_cstr(
	char *dest, const char*src, size_t max_size);

/*!	Perfoms a URL decoding of the given string.
**	@returns	Number of bytes in decoded string
*/
extern size_t url_decode_cstr(
	char *dest, const char*src, size_t max_size);

extern void url_decode_cstr_inplace(char *str);

extern size_t url_form_next_value(
	char** form_string, char** key, char** value);

extern int url_parse(
	char*	url,
	char**	protocol,
	char**	username,
	char**	password,
	char**	host,
	char**	port,
	char**	path,
	char**	query);

extern bool url_is_absolute(const char* url);

inline static bool path_is_absolute(const char* path) {
	return path[0] ==
	       '/';
}

// Transforms new_url into a shorter, possibly relative, path/url.
extern void url_shorten_reference(
	const char* current_url, char* new_url);

extern bool string_contains_colons(const char* str);

extern bool url_change(
	char* current_url, const char* new_url);

#endif // __URL_HELPERS_H__
