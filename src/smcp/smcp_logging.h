#ifndef __SMCP_LOGGING_HEADER__
#define __SMCP_LOGGING_HEADER__ 1

#if !VERBOSE_DEBUG

#define CSTR(x)     (x)
#define DEBUG_PRINTF(...)   do { } while(0)

#elif defined(__AVR__)
#define SMCP_DEBUG_OUT_FILE     stdout

#include <stdio.h>
#include <avr/pgmspace.h>
#define CSTR(x)     PSTR(x)
#define DEBUG_PRINTF(...) \
    do { fprintf_P(stdout, __VA_ARGS__); fputc( \
			'\n', \
			stdout); } while(0)

#else // __AVR__
#define SMCP_DEBUG_OUT_FILE     stderr

#include <stdio.h>
#define CSTR(x)     (x)
#define DEBUG_PRINTF(...) \
    do { fprintf(stderr, __VA_ARGS__); fputc('\n', \
			stderr); } while(0)

#endif

#endif // __SMCP_LOGGING_HEADER__
