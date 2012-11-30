/*	@file help.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
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

#include <stdio.h>
#include <string.h>

typedef struct {
	char		shortarg;
	const char* longarg;
	const char* param;
	const char* desc;
} arg_list_item_t;

static inline void
print_arg_list_help(
	const arg_list_item_t	arg_list[],
	const char*				command_name,
	const char*				syntax
) {
	int i;

	printf("Syntax:\n");
	printf("   %s %s\n", command_name, syntax);
	printf("Options:\n");
	for(i = 0; arg_list[i].desc; ++i) {
		if(arg_list[i].shortarg)
			printf("   -%c", arg_list[i].shortarg);
		else
			printf("      ");

		if(arg_list[i].longarg) {
			if(arg_list[i].shortarg)
				printf("/");
			else
				printf(" ");

			printf("--%s%s",
				arg_list[i].longarg,
				"                " + strlen(arg_list[i].longarg));
		} else {
			printf("                   ");
		}

		printf(" %s\n", arg_list[i].desc);
	}
}


#define BEGIN_LONG_ARGUMENTS(ret)   \
    for(i = 1; i < argc; i++) { \
		if(argv[i][0] == '-' && argv[i][1] == '-') {    \
			if(false) { \
			}

#define HANDLE_LONG_ARGUMENT(str)   \
    else if(strcmp(argv[i] + 2, str) == 0)

#define BEGIN_SHORT_ARGUMENTS(ret)  \
    else { \
		fprintf(stderr, \
			"%s: error: Unknown command line argument \"%s\".\n", \
			argv[0], \
			argv[i]); \
		ret = ERRORCODE_BADARG; \
		goto bail; \
	} \
	} else if(argv[i][0] == '-') { \
		int j; \
		int ii = i; \
		for(j = 1; j && argv[ii][j]; j++) { \
			switch(argv[ii][j]) { \
			default: \
				fprintf(stderr, \
					"%s: error: Unknown command line argument \"-%c\".\n", \
					argv[0], \
					argv[ii][j]); \
				ret = ERRORCODE_BADARG; \
				goto bail;

#define HANDLE_SHORT_ARGUMENT(chr)  \
    break; case chr:

#define HANDLE_SHORT_ARGUMENT2(chr, chr2)    \
    break; case chr: case chr2:

#define HANDLE_OTHER_ARGUMENT() \
    break; \
	} \
	} \
	} else

#define END_ARGUMENTS \
	}
