/*
 *  dict.h
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 4/11/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#ifndef __SMCP_DICT_HEADER__
#define __SMCP_DICT_HEADER__ 1

#include <sys/cdefs.h>
#include <stdbool.h>

__BEGIN_DECLS
struct smcp_dict_s;
typedef struct smcp_dict_s *smcp_dict_t;

smcp_dict_t smcp_dict_create();
void smcp_dict_release(smcp_dict_t self);
smcp_dict_t smcp_dict_copy(smcp_dict_t self);
void smcp_dict_add_value(
	smcp_dict_t self, const char* key, const char* value);
void smcp_dict_remove_value(
	smcp_dict_t self, const char* key);
const char* smcp_dict_get_value(
	smcp_dict_t self, const char* key);

#endif
