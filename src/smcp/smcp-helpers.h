#ifndef __SMCP_HELPERS_HEADER__
#define __SMCP_HELPERS_HEADER__ 1

#include <string.h>

#if !defined(__SDCC) && defined(SDCC_REVISION)
#define __SDCC	1
#endif

#if defined(__SDCC)
#include <malloc.h>
#endif

#include <stdlib.h>

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

#ifndef HAVE_STRLCAT
#define HAVE_STRLCAT (((defined(__APPLE__) || defined(__AVR__))) && !defined(__SDCC))
#endif

#ifndef HAVE_STPNCPY
#define HAVE_STPNCPY ((defined(linux) || (!defined(__APPLE__) && !defined(__AVR__))) && !defined(__SDCC))
#endif

#ifndef HAVE_STRDUP
#define HAVE_STRDUP (!defined(__SDCC))
#endif

#ifndef HAVE_ALLOCA
#define HAVE_ALLOCA (!defined(__SDCC))
#endif

#ifndef HAVE_STRTOL
#define HAVE_STRTOL (!defined(__SDCC))
#endif

#ifndef HAVE_VSNPRINTF
#define HAVE_VSNPRINTF (!defined(__SDCC))
#endif

#if !HAVE_VSNPRINTF && !defined(vsnprintf)
#warning VSNPRINTF NOT IMPLEMENTED, VSPRINTF COULD OVERFLOW!
#define vsnprintf(d,n,fmt,lst) vsprintf(d,fmt,lst)
#endif

#if !HAVE_STRDUP && !defined(strdup)
#define strdup(...) strdup__(__VA_ARGS__)
static inline char*
strdup(const char* cstr) {
	size_t len = strlen(cstr);
	char* ret = malloc(len+1);
	memcpy(ret,cstr,len);
	ret[len]=0;
	return ret;
}
#endif

#if !HAVE_STRNDUP && !defined(strndup)
#define strndup(...) strndup__(__VA_ARGS__)
static inline char*
strndup(const char* cstr,size_t maxlen) {
	size_t len = strlen(cstr);
	char* ret;
	if(maxlen<len)
		len = maxlen;
	ret = malloc(len+1);
	memcpy(ret,cstr,len);
	ret[len]=0;
	return ret;
}
#endif

#if !HAVE_STPNCPY && !defined(stpncpy)
#define stpncpy(...) stpncpy__(__VA_ARGS__)
static inline char*
stpncpy(char* dest, const char* src, size_t len) {
	return strncpy(dest,src,len)+MIN(len,strlen(src));
}
#endif

#if !HAVE_STRLCAT && !defined(strlcat)
#define strlcat(a, b, len)    strncat(a, b, len-strlen(a)-1)
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

#if CONTIKI && !defined(htonl)
#define htonl(x)		uip_htonl(x)
#define ntohl(x)		uip_ntohl(x)
#define htons(x)		uip_htons(x)
#define ntohs(x)		uip_ntohs(x)
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

#if !defined(HAVE_TIME_H)
#define HAVE_TIME_H		(__DARWIN__ || defined(__SDCC) || !(CONTIKI && !CONTIKI_TARGET_MINIMAL_NET && !CONTIKI_TARGET_COOJA && !CONTIKI_TARGET_NATIVE))
#endif

#if !defined(HAVE_SYS_TIME_H)
#define HAVE_SYS_TIME_H		(__DARWIN__ || !(CONTIKI && !CONTIKI_TARGET_MINIMAL_NET && !CONTIKI_TARGET_COOJA && !CONTIKI_TARGET_NATIVE))
#endif

#if HAVE_TIME_H
#include <time.h>
#define HAVE_TIME_T		1
#endif

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#define HAVE_TIME_T		1
#endif

#if !defined(HAVE_TIMEVAL)
#define HAVE_TIMEVAL		(__DARWIN__ || !(CONTIKI && !CONTIKI_TARGET_MINIMAL_NET && !CONTIKI_TARGET_COOJA && !CONTIKI_TARGET_NATIVE))
#endif

#if !HAVE_TIME_T && !defined(time_t) && !defined(__time_t_defined)
typedef long time_t;
#endif

#if !HAVE_TIMEVAL && !defined(timeval) && !defined(__timeval_defined)
typedef int32_t suseconds_t;
struct timeval {
	time_t		tv_sec;
	suseconds_t tv_usec;
};
#endif

#include "smcp-logging.h"

#endif
