/*	@file fgetln.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Originally published 2012-10-24.
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
**
**	-------------------------------------------------------------------
**
**	This is a simple implementation of the BSD function `fgetln()`,
**	for use on operating systems which do not have a copy.
**
**	Man page URL: <http://www.openbsd.org/cgi-bin/man.cgi?query=fgetln>
**
**	NOTE: This implementation is *NOT* thread safe!
*/

#include <stdio.h>

#if !defined(HAVE_FGETLN)
#define HAVE_FGETLN	defined(__DARWIN_C_LEVEL) && (__DARWIN_C_LEVEL>=__DARWIN_C_FULL)
#endif

#if !defined(fgetln) && !HAVE_FGETLN
static char *
fgetln_(FILE *stream, size_t *len) {
	static char* linep = NULL;
	static size_t linecap = 0;
	ssize_t length = getline(&linep,&linecap,stream);
	if(length==-1) {
		free(linep);
		linep = NULL;
		linecap = 0;
		length = 0;
	}
	if(len)
		*len = length;
	return linep;
}
#define fgetln	fgetln_
#endif

