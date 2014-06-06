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

#include "assert-macros.h"
#include "smcp.h"

#if SMCP_CONF_NODE_ROUTER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ll.h"
#include "url-helpers.h"

#include "smcp.h"
#include "smcp-node-router.h"
#include "smcp-helpers.h"
#include "smcp-logging.h"
#include "smcp-internal.h"

#pragma mark -
#pragma mark Globals

#if SMCP_AVOID_MALLOC
static struct smcp_node_s smcp_node_pool[SMCP_CONF_MAX_ALLOCED_NODES];
#endif

#pragma mark -

smcp_status_t
smcp_default_request_handler(smcp_t self, smcp_node_t node) {
   if(smcp_inbound_get_code(self) == COAP_METHOD_GET) {
	   return smcp_handle_list(self, node);
   }
   return SMCP_STATUS_NOT_ALLOWED;
}

smcp_status_t
smcp_node_router_handler(smcp_t self, void* context) {
	smcp_request_handler_func handler = NULL;
	smcp_node_route(self, context, &handler, &context);
	if(!handler)
		return SMCP_STATUS_NOT_IMPLEMENTED;
	return (*handler)(self, context);
}

smcp_status_t
smcp_node_route(smcp_t self, smcp_node_t node, smcp_request_handler_func* func, void** context) {
	smcp_status_t ret = 0;

	smcp_inbound_reset_next_option(self);

	{
		// TODO: Rewrite this to be more efficient.
		const uint8_t* prev_option_ptr = self->inbound.this_option;
		coap_option_key_t prev_key = 0;
		coap_option_key_t key;
		const uint8_t* value;
		coap_size_t value_len;
		while((key=smcp_inbound_next_option(self, &value, &value_len))!=COAP_OPTION_INVALID) {
			if(key>COAP_OPTION_URI_PATH) {
				self->inbound.this_option = prev_option_ptr;
				self->inbound.last_option_key = prev_key;
				break;
			} else if(key==COAP_OPTION_URI_PATH) {
				smcp_node_t next = smcp_node_find(
					node,
					(const char*)value,
					(int)value_len
				);
				if(next) {
					node = next;
				} else {
					self->inbound.this_option = prev_option_ptr;
					self->inbound.last_option_key = prev_key;
					break;
				}
			} else if(key==COAP_OPTION_URI_HOST) {
				// Skip host at the moment,
				// because we don't do virtual hosting yet.
			} else if(key==COAP_OPTION_URI_PORT) {
				// Skip port at the moment,
				// because we don't do virtual hosting yet.
			} else if(key==COAP_OPTION_PROXY_URI) {
				// Skip the proxy URI for now.
			} else if(key==COAP_OPTION_CONTENT_TYPE) {
				// Skip.
			} else {
				if(COAP_OPTION_IS_CRITICAL(key)) {
					ret=SMCP_STATUS_BAD_OPTION;
					assert_printf("Unrecognized option %d, \"%s\"",
						key,
						coap_option_key_to_cstr(key, false)
					);
					goto bail;
				}
			}
			prev_option_ptr = self->inbound.this_option;
			prev_key = self->inbound.last_option_key;
		}
	}

	*func = (void*)node->request_handler;
	if(node->context)
		*context = node->context;
	else
		*context = (void*)node;

bail:
	return ret;
}

#pragma mark -
#pragma mark Node Funcs

void
smcp_node_dealloc(smcp_node_t x) {
#if SMCP_AVOID_MALLOC
	x->finalize = NULL;
#else
	free(x);
#endif
}

smcp_node_t
smcp_node_alloc() {
	smcp_node_t ret;
#if SMCP_AVOID_MALLOC
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

#if SMCP_NODE_ROUTER_USE_BTREE

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
#endif

static bt_compare_result_t
smcp_node_ncompare_cstr(
	smcp_node_t lhs, const char* rhs, intptr_t len
) {
	bt_compare_result_t ret;

	if(lhs->name == rhs)
		return 0;
	if(!lhs->name)
		return 1;
	if(!rhs)
		return -1;

	ret = strncmp(lhs->name, rhs, len);

	if(ret == 0) {
		int lhs_len = (int)strlen(lhs->name);
		if(lhs_len > len)
			ret = 1;
		else if(lhs_len < len)
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

	ret->request_handler = (void*)&smcp_default_request_handler;

	if(node) {
		require(name, bail);
		ret->name = name;
#if SMCP_NODE_ROUTER_USE_BTREE
		bt_insert(
			(void**)&((smcp_node_t)node)->children,
			ret,
		    (bt_compare_func_t)smcp_node_compare,
		    (bt_delete_func_t)smcp_node_delete,
			NULL
		);
#else
		ll_prepend(
			(void**)&((smcp_node_t)node)->children,
			(void*)ret
		);
#endif
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
#if SMCP_NODE_ROUTER_USE_BTREE
		bt_remove(owner,
			node,
			(bt_compare_func_t)smcp_node_compare,
			(void*)node->finalize,
			NULL
		);
#else
		ll_remove(owner,(void*)node);
		if(node->finalize)
			node->finalize(node);
#endif
	}

bail:
	return;
}

smcp_status_t
smcp_node_get_path(
	smcp_node_t node, char* path, coap_size_t max_path_len
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


	if(node->name) {
		size_t len;
		strlcat(path, "/", max_path_len);
		len = strlen(path);
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
#if SMCP_NODE_ROUTER_USE_BTREE
	return (smcp_node_t)bt_find(
		(void*)&((smcp_node_t)node)->children,
		name,
		(bt_compare_func_t)&smcp_node_ncompare_cstr,
		(void*)(intptr_t)name_len
	);
#else
	// Ouch. Linear search.
	smcp_node_t ret = node->children;
	while(ret && smcp_node_ncompare_cstr(ret,name,name_len) != 0)
		ret = ll_next((void*)ret);
	return ret;
#endif
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
		// the stack here. SEC-TODO: Investigate potential oveflow!
		{
#if HAVE_C99_VLA
			char unescaped_name[namelen+1];
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
				(int)escaped_len
			);
#if !HAVE_C99_VLA // && !SMCP_AVOID_MALLOC
			free(unescaped_name);
#endif
		}
		if(!*next) {
			DEBUG_PRINTF(
					"Unable to find node. node->name=%s, path=%s, namelen=%d",
				node->name, path, namelen);
			goto bail;
		}
	}

	if(!*next) {
		DEBUG_PRINTF(
				"Unable to find node. node->name=%s, path=%s", node->name,
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
	return (int)(path - orig_path);
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
		DEBUG_PRINTF("%s: %p (nextPath = %s)", path, node, nextPath);
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

#endif // #if SMCP_CONF_NODE_ROUTER
