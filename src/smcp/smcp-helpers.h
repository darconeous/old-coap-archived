#ifndef __SMCP_HELPERS_HEADER__
#define __SMCP_HELPERS_HEADER__ 1

#include <string.h>

#if !defined(__SDCC) && defined(SDCC)
#define __SDCC	SDCC
#endif

#if defined(__SDCC)
#include <malloc.h>
#endif

#include <stdlib.h>
#include <stdint.h>

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
#if defined(__GCC_VERSION__)
#define MIN(a, \
        b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a < \
              _b ? _a : _b; })
#else
#define MIN(a,b)	((a)<(b)?(a):(b))	// NAUGHTY!...but compiles
#endif
#endif

#ifndef MAX
#if defined(__GCC_VERSION__)
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

__BEGIN_DECLS
#if !HAVE_TIME_T && !defined(time_t) && !defined(__time_t_defined)
typedef long time_t;
#endif

__END_DECLS

#endif
