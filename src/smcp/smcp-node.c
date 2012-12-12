/*	@file smcp_node.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include "smcp.h"
#include <string.h>
#include <ctype.h>
#include "ll.h"
#include "url-helpers.h"

#include "smcp.h"
#include "smcp-node.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"

#pragma mark -
#pragma mark Globals

#if SMCP_NO_MALLOC
static struct smcp_node_s smcp_node_pool[SMCP_CONF_MAX_ALLOCED_NODES];
#endif

#pragma mark -
#pragma mark Node Funcs

void
smcp_node_dealloc(smcp_node_t x) {
#if SMCP_NO_MALLOC
	x->finalize = NULL;
#else
	free(x);
#endif
}

smcp_node_t
smcp_node_alloc() {
	smcp_node_t ret;
#if SMCP_NO_MALLOC
	uint8_t i;
	for(i=0;i<SMCP_CONF_MAX_ALLOCED_NODES;i++) {
		ret = &smcp_node_pool[i];
		if(ret->finalize) {
			ret = NULL;
			continue;
		}
		break;
	}
#else
	ret = (smcp_node_t)calloc(sizeof(struct smcp_node_s), 1);
#endif
	if(ret)
		ret->finalize = &smcp_node_dealloc;
	else
		DEBUG_PRINTF("%s: Malloc failure...?",__func__);
	return ret;
}

bt_compare_result_t
smcp_node_compare(
	smcp_node_t lhs, smcp_node_t rhs
) {
	if(lhs->name == rhs->name)
		return 0;
	if(!lhs->name)
		return 1;
	if(!rhs->name)
		return -1;
	return strcmp(lhs->name, rhs->name);
}

static bt_compare_result_t
smcp_node_ncompare_cstr(
	smcp_node_t lhs, const char* rhs, int*len
) {
	bt_compare_result_t ret;

	if(lhs->name == rhs)
		return 0;
	if(!lhs->name)
		return 1;
	if(!rhs)
		return -1;

	ret = strncmp(lhs->name, rhs, *len);

	if(ret == 0) {
		int lhs_len = strlen(lhs->name);
		if(lhs_len > *len)
			ret = 1;
		else if(lhs_len < *len)
			ret = -1;
	}

	return ret;
}

smcp_node_t
smcp_node_init(
	smcp_node_t self, smcp_node_t node, const char* name
) {
	smcp_node_t ret = NULL;

	require(self || (self = smcp_node_alloc()), bail);

	ret = (smcp_node_t)self;

	ret->request_handler = &smcp_default_request_handler;

	if(node) {
		require(name, bail);
		ret->name = name;
		bt_insert(
			    (void**)&((smcp_node_t)node)->children,
			ret,
			    (bt_compare_func_t)smcp_node_compare,
			    (bt_delete_func_t)smcp_node_delete,
			NULL
		);
		ret->parent = node;
	}

	DEBUG_PRINTF("%s: %p",__func__,ret);

bail:
	return ret;
}

void
smcp_node_delete(smcp_node_t node) {
	void** owner = NULL;

	DEBUG_PRINTF("%s: %p",__func__,node);

	if(node->parent)
		owner = (void**)&((smcp_node_t)node->parent)->children;

	// Delete all child objects.
	while(((smcp_node_t)node)->children)
		smcp_node_delete(((smcp_node_t)node)->children);

	if(owner) {
#if DEBUG
		bt_count(owner);
#endif
		bt_remove(owner,
			node,
			(bt_compare_func_t)smcp_node_compare,
			(void*)node->finalize,
			NULL
		);
#if DEBUG
		bt_count(owner);
#endif
	}

bail:
	return;
}

smcp_status_t
smcp_node_get_path(
	smcp_node_t node, char* path, size_t max_path_len
) {
	smcp_status_t ret = 0;

	require(node, bail);
	require(path, bail);

	if(node->parent) {
		// using recursion here just makes this code so much more pretty,
		// but it would be ideal to avoid using recursion at all,
		// to be nice to the stack. Just a topic of future investigation...
		ret = smcp_node_get_path(node->parent, path, max_path_len);
	} else {
		path[0] = 0;
	}

	strlcat(path, "/", max_path_len);

	if(node->name) {
		size_t len = strlen(path);
		if(max_path_len>len)
			url_encode_cstr(path+len, node->name, max_path_len - len);
	}

bail:
	return ret;
}

smcp_node_t
smcp_node_find(
	smcp_node_t node,
	const char* name,	// Unescaped.
	int name_len
) {
	return (smcp_node_t)bt_find(
		(void**)&((smcp_node_t)node)->children,
		name,
		(bt_compare_func_t)smcp_node_ncompare_cstr,
		&name_len
	);
}

int
smcp_node_find_next_with_path(
	smcp_node_t node,
	const char* orig_path,	// Escaped.
	smcp_node_t* next
) {
	const char* path = orig_path;

	require(next, bail);
	require(node, bail);
	require(path, bail);

	// Move past any preceding slashes.
	while(path[0] == '/')
		path++;

	if(path[0] == 0) {
		// Self.
		*next = node;
	} else {
		// Device or Variable.
		int namelen;
		for(namelen = 0; path[namelen]; namelen++) {
			if((path[namelen] == '/') || (path[namelen] == '?') ||
			        (path[namelen] == '!'))
				break;
		}

		// Warning: This could be dangerous!
		// We should evaluate the liklihood of blowing
		// the stack here. TODO: Investigate potential oveflow!
		{
#if HAVE_C99_VLA
			char unescaped_name[namelen+1];
//#elif SMCP_NO_MALLOC
//			static char unescaped_name[SMCP_MAX_PATH_LENGTH+1];
#else
			char *unescaped_name = malloc(namelen+1);
#endif
			size_t escaped_len = url_decode_str(
				unescaped_name,
				namelen+1,
				path,
				namelen
			);
			*next = smcp_node_find(
				node,
				unescaped_name,
				escaped_len
			);
#if !HAVE_C99_VLA // && !SMCP_NO_MALLOC
			free(unescaped_name);
#endif
		}
		if(!*next) {
			DEBUG_PRINTF(CSTR(
					"Unable to find node. node->name=%s, path=%s, namelen=%d"),
				node->name, path, namelen);
			goto bail;
		}
	}

	if(!*next) {
		DEBUG_PRINTF(CSTR(
				"Unable to find node. node->name=%s, path=%s"), node->name,
			path);
		goto bail;
	}

	// Move to next name
	while(path[0] && (path[0] != '/') && (path[0] != '!') &&
	        (path[0] != '?'))
		path++;

	// Move past any preceding slashes.
	while(path[0] == '/')
		path++;

bail:
	return path - orig_path;
}

smcp_node_t
smcp_node_find_with_path(
	smcp_node_t node, const char* path
) {
	smcp_node_t ret = NULL;

again:
	require(node, bail);
	require(path, bail);

	do {
		const char* nextPath = path;
		nextPath += smcp_node_find_next_with_path(node, path, &ret);
		node = ret;
		DEBUG_PRINTF(CSTR("%s: %p (nextPath = %s)"), path, node, nextPath);
		path = nextPath;
	} while(ret && path[0]);

bail:
	return ret;
}

extern int smcp_node_find_closest_with_path(
	smcp_node_t node, const char* path, smcp_node_t* closest
) {
	int ret = 0;

again:
	require(node, bail);
	require(path, bail);

	*closest = node;
	do {
		ret += smcp_node_find_next_with_path(*closest, path + ret, &node);
		if(node)
			*closest = node;
	} while(node && path[ret]);

bail:
	return ret;
}

#if !SMCP_EMBEDDED
smcp_node_t
smcp_node_get_root(smcp_node_t node) {
	if(node && node->parent)
		return smcp_node_get_root(node->parent); // Recursion should be optimized away.
	return node;
}
#endif
