/*
 *  dict.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 4/11/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include "dict.h"
#include <stdlib.h>

smcp_dict_t
smcp_dict_create() {
	smcp_dict_t ret = NULL;

bail:
	return ret;
}

void
smcp_dict_release(smcp_dict_t self) {
}

smcp_dict_t
smcp_dict_copy(smcp_dict_t self) {
	smcp_dict_t ret = NULL;

bail:
	return ret;
}

void
smcp_dict_add_value(
	smcp_dict_t self, const char* key, const char* value
) {
bail:
	return;
}

void
smcp_dict_remove_value(
	smcp_dict_t self, const char* key
) {
bail:
	return;
}

const char*
smcp_dict_get_value(
	smcp_dict_t self, const char* key
) {
	const char* ret = NULL;

bail:
	return ret;
}
