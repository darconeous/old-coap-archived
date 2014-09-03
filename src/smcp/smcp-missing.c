/*!	@file smcp_missing.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "smcp-missing.h"

#include <stdio.h>

#include "smcp-helpers.h"

#if !SMCP_AVOID_MALLOC
#if !HAVE_STRDUP
char*
___smcp_strdup(const char* cstr) {
	size_t len = strlen(cstr);
	char* ret = (char*)malloc(len+1);
	memcpy(ret,cstr,len);
	ret[len]=0;
	return ret;
}
#endif

#if !HAVE_STRNDUP
char*
___smcp_strndup(const char* cstr,size_t maxlen) {
	size_t len = strlen(cstr);
	char* ret;
	if(maxlen<len)
		len = maxlen;
	ret = (char*)malloc(len+1);
	memcpy(ret,cstr,len);
	ret[len]=0;
	return ret;
}
#endif
#endif //!SMCP_AVOID_MALLOC

#if !HAVE_STPNCPY
char*
___smcp_stpncpy(char* dest, const char* src, size_t len) {
	if(strlen(src) < len)
		len = strlen(src);
	if(strncpy(dest,src,len))
		dest += len;
	return dest;
}
#endif

#if !HAVE_STRLCPY
size_t
___smcp_strlcpy(char *dst, const char *src, size_t siz)
{
	size_t n;
	size_t slen = strlen(src);

	if (siz) {
		if ((n = MIN(slen, siz - 1)))
			memcpy(dst, src, n);
		dst[n] = '\0';
	}
	return slen;
}
#endif

#if !HAVE_STRLCAT
size_t
___smcp_strlcat(char *dst, const char *src, size_t siz)
{
	size_t dlen = strlen(dst);

	if (dlen < siz - 1)
		return (dlen + strlcpy(dst + dlen, src, siz-dlen));

	return dlen + strlen(src);
}
#endif
