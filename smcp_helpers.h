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

static inline bool
util_add_header(
	coap_header_item_t	headerList[],
	int					maxHeaders,
	coap_header_key_t	key,
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


#endif
