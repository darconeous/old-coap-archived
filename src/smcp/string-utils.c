/*!	@file string-utils.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Various string utilities
**
**	Originally published 2014-8-29.
**
**	This file was written by Robert Quattlebaum <darco@deepdarc.com>.
**
**	This work is provided as-is. Unless otherwise provided in writing,
**	Robert Quattlebaum makes no representations or warranties of any
**	kind concerning this work, express, implied, statutory or otherwise,
**	including without limitation warranties of title, merchantability,
**	fitness for a particular purpose, non infringement, or the absence
**	of latent or other defects, accuracy, or the present or absence of
**	errors, whether or not discoverable, all to the greatest extent
**	permissible under applicable law.
**
**	To the extent possible under law, Robert Quattlebaum has waived all
**	copyright and related or neighboring rights to this work. This work
**	is published from the United States.
**
**	I, Robert Quattlebaum, dedicate any and all copyright interest in
**	this work to the public domain. I make this dedication for the
**	benefit of the public at large and to the detriment of my heirs and
**	successors. I intend this dedication to be an overt act of
**	relinquishment in perpetuity of all present and future rights to
**	this code under copyright law. In jurisdictions where this is not
**	possible, I hereby release this code under the Creative Commons
**	Zero (CC0) license.
**
**	 * <http://creativecommons.org/publicdomain/zero/1.0/>
*/

#include "string-utils.h"

char *
uint32_to_hex_cstr(char *str,uint32_t v) {
	char *ret = str;
	int i;
	for(i=0;i<8;i++) {
		*str++ = "0123456789ABCDEF"[v>>28];
		v<<=4;
	}
	*str=0;
	return ret;
}

/*!	Adapted from K&R's "The C Programming Language", page 60.
 *	Somewhat naive. Make sure the string has at least 11 bytes available! */
char *
uint32_to_dec_cstr(char s[],uint32_t n) {
	uint8_t i = 0, j;

	do {       /* generate digits in reverse order */
		s[i++] = n % 10 + '0';   /* get next digit */
	} while((n /= 10) > 0);     /* delete it */
	s[i--] = '\0';

	/* Reverse the string */
	for(j = 0; j < i; j++, i--) {
		char x = s[j];
		s[j] = s[i];
		s[i] = x;
	}

	return s;
}

/*! Make sure the string has at least 12 bytes available! */
char *
int32_to_dec_cstr(char s[],int32_t n) {
	if(n < 0) {
		s[0] = '-';
		uint32_to_dec_cstr(s+1, (uint32_t)-n);
		return s;
	}
	return uint32_to_dec_cstr(s, (uint32_t)n);
}

bool
str2bool(const char* value)
{
	if ( value[0] == '1'
	  || value[0] == 't'
	  || value[0] == 'T'
	  || value[0] == 'y'
	  || value[0] == 'T'
	) {
		return true;
	} else if ( value[0] == '0'
	         || value[0] == 'f'
	         || value[0] == 'F'
	         || value[0] == 'n'
	         || value[0] == 'N'
	) {
		return false;
	}

	return false;
}
