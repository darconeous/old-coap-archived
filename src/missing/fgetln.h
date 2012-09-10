#include <stdio.h>

#if !defined(fgetln) && !HAVE_FGETLN
static char *
fgetln_(FILE *stream, size_t *len) {
	static char* linep = NULL;
	static size_t linecap = 0;
	size_t length = getline(&linep,&linecap,stream);
	if(len)
		*len = length;
	return linep;
}
#define fgetln	fgetln_
#endif

