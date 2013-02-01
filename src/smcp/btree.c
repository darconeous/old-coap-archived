/*!	@file btree.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Originally published 2010-8-31.
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
**	## Unit Test ##
**
**	This file includes its own unit test. To compile the unit test,
**	simply compile this file with the macro BTREE_SELF_TEST set to 1.
**	For example:
**
**	    cc btree.c -Wall -DBTREE_SELF_TEST=1 -o btree
**
**	## Todo ##
**
**	 * Add some sort of automatic tree-balancing algorithm,
**	   like <http://en.wikipedia.org/wiki/Scapegoat_tree>.
*/

#include "btree.h"
#include <assert.h>

#if CONTIKI
/* Contiki is having problems with asserts. */
#ifdef assert
#undef assert
#endif
#define assert(x)		do { } while (0)
#endif

int
bt_insert(
	void** bt,
	void* item,
	bt_compare_func_t compare_func,
	bt_delete_func_t delete_func,
	void* context
) {
	int depth = 0;
	bt_item_t const item_ = item;
	bt_item_t location_;

again:

	location_ = *bt;

	if(location_) {
		bt_compare_result_t result =
		    (*compare_func)(location_, item_, context);

		if(result) {
			// One more step down the rabit hole...
			item_->parent = location_;
			bt = (result < 0) ?
				(void**)&location_->rhs : (void**)&location_->lhs;
			depth++;
			goto again;
		} else if(item_ != location_) {
			// Item already exists, so we replace.
			item_->parent = location_->parent;
			if(item_->parent) {
				if(location_->parent->rhs == location_)
					location_->parent->rhs = item;
				else
					location_->parent->lhs = item;
			}
			item_->lhs = location_->lhs;
			if(location_->lhs)
				location_->lhs->parent = item_;
			item_->rhs = location_->rhs;
			if(location_->rhs)
				location_->rhs->parent = item_;
			*bt = item_;
			(*delete_func)(location_, context);
		}
	} else {
		// Found ourselves a good spot. Put the item here.
		*bt = item_;
	}

	return depth;
}

void*
bt_find(
	void*const* bt,
	const void* item,
	bt_compare_func_t compare_func,
	void* context
) {
	bt_item_t location_ = *bt;
	bt_compare_result_t result = -1;

	while(location_) {
		result = (*compare_func)(location_, item, context);

		if(result)
			location_ = (result < 0) ? location_->rhs : location_->lhs;
		else
			break;
	}

	return location_;
}

bool
bt_remove(
	void** bt,
	void* item,
	bt_compare_func_t compare_func,
	bt_delete_func_t delete_func,
	void* context
) {
	bt_item_t const item_ = bt_find(bt, item, compare_func, context);

	if(item_) {
		if(item_->parent) {
			bt = (void**)((item_->parent->lhs == item_)?&item_->parent->lhs:&item_->parent->rhs);
		}

		if(item_->lhs && !item_->rhs) {
			*bt = item_->lhs;
			item_->lhs->parent = item_->parent;
		} else if(item_->rhs && !item_->lhs) {
			*bt = item_->rhs;
			item_->rhs->parent = item_->parent;
		} else if(!item_->rhs && !item_->lhs) {
			*bt = NULL;
		} else {
			bt_item_t last_item = (bt_item_t)bt_last(item_->lhs);
			item_->rhs->parent = last_item;
			last_item->rhs = item_->rhs;

			*bt = item_->lhs;
			item_->lhs->parent = item_->parent;
		}

		item_->lhs = NULL;
		item_->rhs = NULL;
		item_->parent = NULL;

		if(delete_func)
			(*delete_func)(item_, context);

		return true;
	}

	return false;
}

void*
bt_first(void* item) {
	bt_item_t item_ = item;

	if(item_)
		while(item_->lhs)
			item_ = item_->lhs;

	return (void*)item_;
}

void*
bt_next(void* item) {
	bt_item_t item_ = item;

	if(item) {
		if(item_->rhs) {
			item_ = bt_first(item_->rhs);
		} else {
			while(item_->parent && (item_->parent->rhs == item_)) {
				item_ = item_->parent;
			}
			item_ = item_->parent;
		}
	}

	return (void*)item_;
}

void*
bt_last(void* item) {
	bt_item_t item_ = item;

	if(item_)
		while(item_->rhs)
			item_ = item_->rhs;

	return (void*)item_;
}

void*
bt_prev(void* item) {
	bt_item_t item_ = item;

	if(item) {
		if(item_->lhs) {
			item_ = bt_last(item_->lhs);
		} else {
			while(item_->parent && (item_->parent->lhs == item_)) {
				item_ = item_->parent;
			}
			item_ = item_->parent;
		}
	}

	return (void*)item_;
}

#ifndef __SDCC
size_t
bt_count(void*const* bt) {
	size_t ret = 0;

	if(*bt) {
		bt_item_t iter = bt_first(*bt);
		const bt_item_t end = bt_last(*bt);

		// We start at 1 here because our end
		// iterator is pointing at the last
		// item instead of the end marker.
		// Without this, this method will
		// be off by 1.
		ret = 1;

		for(; iter != end; iter = bt_next(iter))
			ret++;
	}
	return ret;
}

void
bt_rotate_right(void** bt) {
	bt_item_t item = *bt;

	if(item && item->lhs) {
		item->lhs->parent = item->parent;
		item->parent = item->lhs;
		*bt = item->lhs;
		if(item->lhs->rhs)
			item->lhs->rhs->parent = item;
		item->lhs = item->lhs->rhs;
		((bt_item_t)*bt)->rhs = item;
	}
}

void
bt_rotate_left(void** bt) {
	bt_item_t item = *bt;

	if(item && item->rhs) {
		item->rhs->parent = item->parent;
		item->parent = item->rhs;
		*bt = item->rhs;
		if(item->rhs->lhs)
			item->rhs->lhs->parent = item;
		item->rhs = item->rhs->lhs;
		((bt_item_t)*bt)->lhs = item;
	}
}

unsigned int
bt_unbalance(void** bt) {
	unsigned int ret = 0;
	bt_item_t item = *bt;

	if(!item)
		goto bail;

	while(item->lhs) {
		bt_rotate_right(bt);
		item = *bt;
		ret++;
	}

	ret += bt_unbalance((void**)&item->rhs);

bail:
	return ret;
}

unsigned int
bt_splay(void** bt, void* root) {
	unsigned int ret = 0;
	bt_item_t item = root;

	if(*bt==root)
		goto bail;

	while((item!=*bt) && item && item->parent&& item->parent->parent) {
		void** pivot;

		if(item->parent->parent->lhs==item->parent)
			pivot=(void**)&item->parent->parent->lhs;
		else
			pivot=(void**)&item->parent->parent->rhs;

		if(item->parent->lhs==item)
			bt_rotate_right(pivot);
		else
			bt_rotate_left(pivot);

		ret++;
	}

	if(*bt!=root) {
		if(((bt_item_t)*bt)->lhs==root)
			bt_rotate_right(bt);
		else
			bt_rotate_left(bt);
		ret++;
	}

	assert(*bt==root);

bail:
	return ret;
}

int
bt_get_balance(void* node) {
	int ret = 0;
	int root_index = 0;

	bt_item_t iter = bt_first(node);
	const bt_item_t end = bt_next(bt_last(node));

	for(;iter!=end;iter=bt_next(iter)) {
		if(iter==node)
			root_index = ret;
		ret++;
	}

	ret /= 2;
	ret -= root_index;

	return ret;
}

unsigned int
bt_rebalance(void** bt) {
	unsigned int ret = 0;

	bt_item_t iter = bt_first(*bt);
	bt_item_t median = iter;
	const bt_item_t end = bt_next(bt_last(*bt));

	if(!iter)
		goto bail;

	// Find the median node.
	while(iter!=end) {
		iter = bt_next(iter);
		if(iter==end)
			break;
		iter = bt_next(iter);
		median = bt_next(median);
	}

	// Splay the tree so that the median node is at the root.
	ret += bt_splay(bt,median);

	// Rinse and repeat on both child branches.
	iter = *bt;
	ret += bt_rebalance((void**)&iter->lhs);
	ret += bt_rebalance((void**)&iter->rhs);

bail:
	return ret;
}

#endif // !__SDCC

/* -------------------------------------------------------------------------- */

#if BTREE_SELF_TEST

#include <stdlib.h>
#include <string.h>

static int nodes_alive = 0;

struct self_test_node_s {
	struct bt_item_s item;
	char* name;
};

typedef struct self_test_node_s *self_test_node_t;

void
self_test_node_delete(self_test_node_t item, void* context) {
	free(item->name);
	memset(item, 0, sizeof(*item));
	free(item);

	// Decrement total node count.
	(*(int*)context)--;
}

bt_compare_result_t
self_test_node_compare(
	self_test_node_t lhs,
	self_test_node_t rhs,
	void* context
) {
	(void)context; // This parameter is not used. Supress warning.

	if(lhs->name == rhs->name)
		return 0;
	if(!lhs->name)
		return 1;
	if(!rhs->name)
		return -1;
	return strcmp(lhs->name, rhs->name);
}

bt_compare_result_t
self_test_node_compare_cstr(
	self_test_node_t lhs,
	const char* rhs,
	void* context
) {
	(void)context; // This parameter is not used. Supress warning.

	if(lhs->name == rhs)
		return 0;
	if(!lhs->name)
		return 1;
	if(!rhs)
		return -1;
	return strcmp(lhs->name, rhs);
}

void
forward_traversal_test(self_test_node_t root) {
	int j = 0;
	self_test_node_t iter;

	printf("Forward traversal test...");

	fflush(stdout);

	for(iter = bt_first(root); iter; iter = bt_next(iter)) {
		j++;

		if(nodes_alive < j) {
			printf("Bad node count in forward traversal, too many nodes!\n");
			exit(-1);
		}
	}

	if(nodes_alive != j) {
		printf("Bad node count in forward traversal, not enough nodes!\n");
		exit(-1);
	}
	printf("OK\n");
}

void
reverse_traversal_test(self_test_node_t root) {
	int j = 0;
	self_test_node_t iter;

	printf("Reverse traversal test...");

	fflush(stdout);

	for(iter = bt_last(root); iter; iter = bt_prev(iter)) {
		j++;
		if(nodes_alive < j) {
			printf("Bad node count in forward traversal.\n");
			exit(-1);
		}
	}

	if(nodes_alive != j) {
		printf("Bad node count in reverse traversal.\n");
		exit(-1);
	}
	printf("OK\n");
}

int
main(void) {
	int ret = 0;
	self_test_node_t root = NULL;
	unsigned char c = 0;
	int i;

	// Insert in pseudo random order. Here we are using a very simple
	// linear congruential generator with a=97, c=101, and m=2^8. It
	// will produce a somewhat randomish distribution of numbers between
	// 0 and 255. If you would like to learn more about these types of
	// pseudo random number generators, see wikipedia:
	//
	//  * <http://en.wikipedia.org/wiki/Linear_congruential_generator>
	//
again:
	printf("Inserting nodes in pseudo random order.\n");
	for(c = c * 97 + 101; c; c = c * 97 + 101) {
		self_test_node_t new_node = calloc(sizeof(struct self_test_node_s),
			1);

		asprintf(&new_node->name, "item_%d", c);

		nodes_alive++;

		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);
	}

	printf("Inserted %d nodes.\n", (int)bt_count((void**)&root));

	if(nodes_alive != (int)bt_count((void**)&root)) {
		printf("error: Bad node count.\n");
		ret++;
	}

	printf(" * balance = %d\n",bt_get_balance(root));

	forward_traversal_test(root);
	reverse_traversal_test(root);

	bt_find((void**)&root, "item_1", &self_test_node_compare_cstr, &nodes_alive);

	printf("Removing nodes in pseudo random order.\n");
	for(c = 4 * 97 + 101; c!=4; c = c * 97 + 101) {
		char* name = NULL;

		asprintf(&name, "item_%d", (c==0)?4:c);

		if(!bt_remove(
			(void**)&root,
			name,
			(bt_compare_func_t)&self_test_node_compare_cstr,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		)) {
			printf("error: REMOVE FAILED FOR %d\n",c);
			ret++;
		}
		free(name);
		if(nodes_alive != (int)bt_count((void**)&root)) {
			printf("error: Bad node count.\n");
			ret++;
			break;
		}
		forward_traversal_test(root);
		reverse_traversal_test(root);
	}

	if(nodes_alive) {
		printf("error: Bad node count, should be zero.\n");
		ret++;
	}

	forward_traversal_test(root);
	reverse_traversal_test(root);

	printf("Inserting more nodes in pseudo random order.\n");
	for(c = 5 * 97 + 101; c; c = c * 97 + 101) {
		self_test_node_t new_node = calloc(sizeof(struct self_test_node_s),
			1);

		asprintf(&new_node->name, "item_%d", c);

		nodes_alive++;

		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);
	}

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	printf(" * balance = %d\n",bt_get_balance(root));

	forward_traversal_test(root);
	reverse_traversal_test(root);

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	printf(" * balance = %d\n",bt_get_balance(root));

	forward_traversal_test(root);
	reverse_traversal_test(root);

	// Insert in sequential order.
	printf("Inserting nodes in sequential order.\n");
	for(i = 0; i != 255; i++) {
		self_test_node_t new_node =
			calloc(sizeof(struct self_test_node_s),1);

		asprintf(&new_node->name, "item_%d", i);

		nodes_alive++;

		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);
	}

	printf(" * balance = %d\n",bt_get_balance(root));

	forward_traversal_test(root);
	reverse_traversal_test(root);

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	printf(" * balance = %d\n",bt_get_balance(root));

	forward_traversal_test(root);
	reverse_traversal_test(root);

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	printf(" * balance = %d\n",bt_get_balance(root));

	i = bt_unbalance((void**)&root);
	printf("Unbalance operation took %u rotations\n", i);

	printf(" * balance = %d\n",bt_get_balance(root));

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	if(bt_get_balance(root)) {
		printf(
			"error: Tree doesn't seem balanced even after rebalancing. "
			"balance = %d\n",
			bt_get_balance(root)
		);
		ret++;
	}

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	if(i != 0) {
		printf(
			"error: Rebalance operation should have been trivial, "
			"but did %d rotations anyway.\n",
			i
		);
		ret++;
	}

	forward_traversal_test(root);
	reverse_traversal_test(root);

	// Cleanup.
	printf("Removing all nodes...\n");
	while(root)
		bt_remove(
			(void**)&root,
			root,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);

	bt_find((void**)&root, "item_1", &self_test_node_compare_cstr, &nodes_alive);

	printf("Adding more nodes...\n");
	{
		self_test_node_t new_node;

		new_node = calloc(sizeof(struct self_test_node_s),1);
		asprintf(&new_node->name, "proxy");
		nodes_alive++;
		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);

		new_node = calloc(sizeof(struct self_test_node_s),1);
		asprintf(&new_node->name, ".p");
		nodes_alive++;
		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);

		new_node = calloc(sizeof(struct self_test_node_s),1);
		asprintf(&new_node->name, "device");
		nodes_alive++;
		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);

		new_node = calloc(sizeof(struct self_test_node_s),1);
		asprintf(&new_node->name, "timer");
		nodes_alive++;
		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);

		new_node = calloc(sizeof(struct self_test_node_s),1);
		asprintf(&new_node->name, "async_response");
		nodes_alive++;
		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);

		new_node = calloc(sizeof(struct self_test_node_s),1);
		asprintf(&new_node->name, "lots_of_devices");
		nodes_alive++;
		bt_insert(
			(void**)&root,
			new_node,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);
	}

	forward_traversal_test(root);
	reverse_traversal_test(root);

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	forward_traversal_test(root);
	reverse_traversal_test(root);

	// Cleanup.
	while(root)
		bt_remove((void**)&root,
			root,
			(bt_compare_func_t)&self_test_node_compare,
			(bt_delete_func_t)&self_test_node_delete,
			&nodes_alive
		);

	// Should have no leaks at this point.
	if(nodes_alive != 0) {
		printf("error: nodes_alive = %d, when it should be 0\n", nodes_alive);
		ret++;
	}

	if(ret)
		printf("Failed with %d errors.\n",ret);
	else {
		printf("OK\n");
		//goto again;
	}

	return ret;
}

#endif
