/*
 *  help.h
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>

typedef struct {
	char		shortarg;
	const char* longarg;
	const char* param;
	const char* desc;
} arg_list_item_t;

static void
print_arg_list_help(
	const arg_list_item_t arg_list[], const char* syntax
) {
	int i;

	printf("Syntax:\n");
	printf("   %s\n", syntax);
	printf("Options:\n");
	for(i = 0; arg_list[i].desc; ++i) {
		if(arg_list[i].shortarg)
			printf("   -%c", arg_list[i].shortarg);
		else
			printf("     ");

		if(arg_list[i].longarg)
			printf(" --%s%s",
				arg_list[i].longarg,
				"                " + strlen(arg_list[i].longarg));
		else
			printf("                   ");

		printf(" %s\n", arg_list[i].desc);
	}
}
