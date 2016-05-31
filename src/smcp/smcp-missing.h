/*!	@file smcp_missing.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Replacements for missing system functions
**
**	Copyright (C) 2014 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef SMCP_smcp_missing_h
#define SMCP_smcp_missing_h

#if HAVE_CONFIG_H
#include <config.h>
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>      // For ssize_t
#include <string.h>

__BEGIN_DECLS

#if !HAVE_CONFIG_H

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

#if !SMCP_AVOID_PRINTF
#ifndef HAVE_VSNPRINTF
#define HAVE_VSNPRINTF (!defined(__SDCC))
#endif

#endif //!HAVE_CONFIG_H

#if defined(HAVE_ALLOCA_H) && !defined(HAVE_ALLOCA)
#define HAVE_ALLOCA HAVE_ALLOCA_H
#endif

#if !HAVE_VSNPRINTF && !defined(vsnprintf)
#warning VSNPRINTF NOT IMPLEMENTED, VSPRINTF COULD OVERFLOW!
#define vsnprintf(d,n,fmt,lst) vsprintf(d,fmt,lst)
#endif
#endif

#if !HAVE_STRDUP && !defined(strdup)
#define strdup(...) ___smcp_strdup(__VA_ARGS__)
char* ___smcp_strdup(const char* cstr);
#endif

#if !HAVE_STRNDUP && !defined(strndup)
#define strndup(...) ___smcp_strndup(__VA_ARGS__)
char* ___smcp_strndup(const char* cstr,size_t maxlen);
#endif

#if !HAVE_STPNCPY && !defined(stpncpy)
#define stpncpy(...) ___smcp_stpncpy(__VA_ARGS__)
char* ___smcp_stpncpy(char* dest, const char* src, size_t len);
#endif

#if !HAVE_STRLCPY && !defined(strlcpy)
#define strlcpy(...) ___smcp_strlcpy(__VA_ARGS__)
size_t ___smcp_strlcpy(char* dest, const char* src, size_t len);
#endif

#if !HAVE_STRLCAT && !defined(strlcat)
#define strlcat(...) ___smcp_strlcat(__VA_ARGS__)
size_t ___smcp_strlcat(char* dest, const char* src, size_t len);
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

__END_DECLS

#endif
