#ifndef __SMCP_LOGGING_HEADER__
#define __SMCP_LOGGING_HEADER__ 1

#if !VERBOSE_DEBUG

#define CSTR(x)     (x)
#define DEBUG_PRINTF(...)   do { } while(0)

#elif defined(__AVR__)

#include <stdio.h>
#include <avr/pgmspace.h>
#define CSTR(x)     PSTR(x)
#define DEBUG_PRINTF(...) \
    do { fprintf_P(stderr, __VA_ARGS__); fprintf_P( \
			stderr, \
			CSTR("\n")); } while(0)

#else // __AVR__

#include <stdio.h>
#define CSTR(x)     (x)
#define DEBUG_PRINTF(...) \
    do { fprintf(stderr, __VA_ARGS__); fprintf( \
			stderr, \
			CSTR("\n")); } while(0)

#endif

#endif // __SMCP_LOGGING_HEADER__
