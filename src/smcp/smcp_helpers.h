#ifndef __SMCP_HELPERS_HEADER__
#define __SMCP_HELPERS_HEADER__ 1

#include <string.h>

#if !defined(__SDCC) && defined(SDCC_REVISION)
#define __SDCC	1
#endif

#if defined(__SDCC)
#include <malloc.h>
#endif

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

#ifndef HAS_STRDUP
#define HAS_STRDUP !defined(__SDCC)
#endif

#ifndef HAS_ALLOCA
#define HAS_ALLOCA !defined(__SDCC)
#endif

#ifndef HAS_STRTOL
#define HAS_STRTOL !defined(__SDCC)
#endif

#ifndef HAS_VSNPRINTF
#define HAS_VSNPRINTF !defined(__SDCC)
#endif

#if !HAS_VSNPRINTF && !defined(vsnprintf)
#warning VSNPRINTF NOT IMPLEMENTED, VSPRINTF COULD OVERFLOW!
#define vsnprintf vsnprintf
static inline int vsnprintf(char *dest, size_t n,const char *fmt, va_list list) {
	return vsprintf(dest,fmt,list);
}
#endif

#if !HAS_STRDUP && !defined(strdup)
#define strdup strdup
static inline char*
strdup(const char* cstr) {
	size_t len = strlen(cstr);
	char* ret = malloc(len+1);
	memcpy(ret,cstr,len);
	ret[len]=0;
	return ret;
}
#endif

#ifndef MIN
#if !defined(__SDCC)
#define MIN(a, \
        b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a < \
              _b ? _a : _b; })
#else
#define MIN(a,b)	((a)<(b)?(a):(b))	// NAUGHTY!...but compiles
#endif
#endif

#ifndef MAX
#if !defined(__SDCC)
#define MAX(a, \
        b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a > \
              _b ? _a : _b; })
#else
#define MAX(a,b)	((a)<(b)?(b):(a))	// NAUGHTY!...but compiles
#endif
#endif

#if defined(__GCC_VERSION__)
#define SMCP_PURE_FUNC __attribute__((pure))
#else
#define SMCP_PURE_FUNC
#endif

static inline char *
uint32_to_hex(char *str,uint32_t v) {
	char *ret = str;
	int i;
	for(i=0;i<8;i++) {
		*str++ = "0123456789ABCDEF"[v>>28];
		v<<=4;
	}
	*str=0;
	return ret;
}

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
