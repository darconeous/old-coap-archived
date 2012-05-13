#ifndef __SMCP_HELPERS_HEADER__
#define __SMCP_HELPERS_HEADER__ 1

#if !defined(__BEGIN_DECLS) || !defined(__END_DECLS)
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS \
	}
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#if defined(linux) || (!defined(__APPLE__) && !defined(__AVR__))
#define strlcat(a, b, len)    strncat(a, b, len)
//#define strlcat(a,b,len)	( a[len-1]=0,strncat(a,b,len-1) )
#endif

#ifndef MIN
#define MIN(a, \
        b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a < \
              _b ? _a : _b; })
#endif

#ifndef MAX
#define MAX(a, \
        b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a > \
              _b ? _a : _b; })
#endif

#include <string.h>

/*
// DEPRECATED.
static inline bool
util_add_header(
	coap_option_item_t* headerList,
	int					maxHeaders,
	coap_option_key_t	key,
	const char*			value,
	size_t				len
) {
	for(; maxHeaders && headerList[0].key; maxHeaders--, headerList++) ;
	if(maxHeaders) {
		headerList[0].key = key;
		headerList[0].value = (char*)value;
		headerList[0].value_len = (len == COAP_HEADER_CSTR_LEN) ? strlen(
			value) : len;
		headerList[1].key = 0;
		return true;
	}
	return false;
}
*/

#if defined(__GCC_VERSION__)
#define SMCP_PURE_FUNC __attribute__((pure))
#else
#define SMCP_PURE_FUNC
#endif

#if __AVR__
#include <avr/pgmspace.h>
#include <alloca.h>
#define strnequal_const(a, const_b, len_a) (strncmp_P(a, PSTR(const_b),len_a) == 0)
#define strequal_const(a, b) (strcmp_P(a, PSTR(b)) == 0)
#define strhasprefix_const(a, \
        b) (strncmp_P(a, PSTR(b), sizeof(b) - 1) == 0)
#else
#define strnequal_const(a, const_b, len_a) (strncmp(a, const_b,len_a) == 0)
#define strequal_const(a, b) (strcmp(a, b) == 0)
#define strhasprefix_const(a, b) (strncmp(a, b, sizeof(b) - 1) == 0)
#endif


#endif
