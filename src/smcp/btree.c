/*	Flexible Binary Tree Utilities
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
**
**	Self test code at bottom of file.
*/

#include "btree.h"
#include <assert.h>

// TODO: Add some sort of tree-balancing algorithm, like <http://en.wikipedia.org/wiki/Scapegoat_tree>

int
bt_insert(
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context
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
			bt =
			    (result <
			    0) ? (void**)&location_->rhs : (void**)&location_->lhs;
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
		// Found outselves a good spot. Put the item here.
		*bt = item_;
	}

	return depth;
}

void*
bt_find(
	void*const*			bt,
	const void*			item,
	bt_compare_func_t	compare_func,
	void*				context
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
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context
) {
	bt_item_t const item_ = bt_find(bt, item, compare_func, context);

	if(item_) {
		if(item_->parent) {
			if(item_->parent->lhs == item_) {
				item_->parent->lhs = item_->lhs;
				item_->lhs->parent = item_->parent;
				if(item_->rhs) {
					bt_insert((void**)&item_->parent->lhs,
						item_->rhs,
						compare_func,
						delete_func,
						context);
				}
			} else if(item_->parent->rhs == item_) {
				item_->parent->rhs = item_->lhs;
				item_->lhs->parent = item_->parent;
				if(item_->rhs) {
					bt_insert((void**)&item_->parent->rhs,
						item_->rhs,
						compare_func,
						delete_func,
						context);
				}
			}
		} else if(*bt == item_) {
			if(item_->lhs) {
				item_->lhs->parent = NULL;
				*bt = item_->lhs;
				if(item_->rhs) {
					item_->rhs->parent = NULL;
					bt_insert(bt,
						item_->rhs,
						compare_func,
						delete_func,
						context);
				}
			} else if(item_->rhs) {
				item_->rhs->parent = NULL;
				*bt = item_->rhs;
			} else {
				*bt = NULL;
			}
		}
		item_->lhs = NULL;
		item_->rhs = NULL;
		item_->parent = NULL;

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
bail:

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
bail:

	return (void*)item_;
}

size_t
bt_count(void*const* bt) {
	size_t ret = 0;

	if(*bt) {
		bt_item_t iter = bt_first(*bt);
		bt_item_t end = bt_last(*bt);
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

	while((item!=*bt) && item->parent&& item->parent->parent) {
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
	bt_item_t end = bt_next(bt_last(node));

	for(;iter!=end;iter=bt_next(iter)) {
		if(iter==node)
			root_index = ret;
		ret++;
	}

	ret /= 2;
	ret -= root_index;

bail:
	return ret;
}

unsigned int
bt_rebalance(void** bt) {
	unsigned int ret = 0;

	bt_item_t iter = bt_first(*bt);
	bt_item_t median = iter;
	bt_item_t end = bt_next(bt_last(*bt));

	if(!iter)
		goto bail;

	while(iter!=end) {
		iter = bt_next(iter);
		if(iter==end)
			break;
		iter = bt_next(iter);
		median = bt_next(median);
	}

	ret += bt_splay(bt,median);

	iter = *bt;

	ret += bt_rebalance((void**)&iter->lhs);
	ret += bt_rebalance((void**)&iter->rhs);

bail:
	return ret;
}

//////////////////////////////////////////////////////////////////////////////////
// SELF TEST CODE

#if BTREE_SELF_TEST

#include <stdlib.h>
#include <string.h>

static int nodes_alive = 0;

struct self_test_node_s {
	struct bt_item_s	item;
	char*				name;
};

typedef struct self_test_node_s *self_test_node_t;

void
self_test_node_delete(
	self_test_node_t item, void* context
) {
	free(item->name);
	memset(item, 0, sizeof(*item));
	free(item);

	// Decrement total node count.
	(*(int*)context)--;
}

bt_compare_result_t
self_test_node_compare(
	self_test_node_t lhs, self_test_node_t rhs, void* context
) {
	if(lhs->name == rhs->name)
		return 0;
	if(!lhs->name)
		return 1;
	if(!rhs->name)
		return -1;
	return strcmp(lhs->name, rhs->name);
}

void
forward_traversal_test(self_test_node_t root) {
	printf("Forward traversal test...");
	fflush(stdout);
	int j = 0;
	self_test_node_t iter;
	for(iter = bt_first(root); iter; iter = bt_next(iter)) {
		j++;

		if(nodes_alive < j) {
			printf("Bad node count in forward traversal.\n");
			exit(-1);
		}
	}

	if(nodes_alive != j) {
		printf("Bad node count in forward traversal.\n");
		exit(-1);
	}
	printf("OK\n");
}

void
reverse_traversal_test(self_test_node_t root) {
	printf("Reverse traversal test...");
	fflush(stdout);
	int j = 0;
	self_test_node_t iter;
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
main(
	int argc, char* argv[]
) {
	self_test_node_t root = NULL;
	int i;
	unsigned char c;

	// Insert in pseudo random order.
	printf("Inserting nodes in pseudo random order.\n");
	for(c = 0 * 97 + 101; c; c = c * 97 + 101) {
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
		printf("Bad node count.\n");
		return -1;
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

	forward_traversal_test(root);
	reverse_traversal_test(root);

	// Insert in sequential order.
	printf("Inserting nodes in sequential order.\n");
	for(i = 0; i != 255; i++) {
		self_test_node_t new_node = calloc(sizeof(struct self_test_node_s),
			1);

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

	printf(" * balance = %d\n",bt_get_balance(root));

	i = bt_rebalance((void**)&root);
	printf("Rebalance operation took %u rotations\n", i);

	printf(" * balance = %d\n",bt_get_balance(root));

	forward_traversal_test(root);
	reverse_traversal_test(root);

	// Cleanup.
	while(root)
		bt_remove((void**)&root,
			root,
			    (bt_compare_func_t)&self_test_node_compare,
			    (bt_delete_func_t)&self_test_node_delete,
			&nodes_alive);

	// Should have no leaks at this point.
	if(nodes_alive != 0) {
		printf("nodes_alive = %d, when it should be 0\n", nodes_alive);
		return -1;
	}

	printf("OK\n");
	return 0;
}


#endif
