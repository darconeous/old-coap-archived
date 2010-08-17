/*	Binary Tree Utilities
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/

#include "btree.h"
#include <stdlib.h>

void
bt_insert(
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context
) {
	bt_item_t const location_ = *bt;
	bt_item_t const item_ = item;

	// TODO: Add some sort of tree-balancing algorithm.
	// TODO: Make this function not recursive.

	if(location_) {
		bt_compare_result_t result =
		    (*compare_func)(location_, item_, context);
		if(result > 0) {
			item_->parent = location_;
			bt_insert((void**)&location_->lhs,
				item_,
				compare_func,
				delete_func,
				context);
		} else if(result < 0) {
			item_->parent = location_;
			bt_insert((void**)&location_->rhs,
				item_,
				compare_func,
				delete_func,
				context);
		} else {
			if(item_ != location_) {
				// Item already exists, so we replace.
				item_->parent = location_->parent;
				item_->lhs = location_->lhs;
				item_->rhs = location_->rhs;
				*bt = item_;
				    (*delete_func)(location_, context);
			}
		}
	} else {
		*bt = item_;
	}
}

void*
bt_find(
	void**				bt,
	const void*			item,
	bt_compare_func_t	compare_func,
	void*				context
) {
	bt_item_t location_ = *bt;
	bt_compare_result_t result = -1;

	while(location_) {
		result = (*compare_func)(location_, item, context);

		if(result > 0)
			location_ = location_->lhs;
		else if(result < 0)
			location_ = location_->rhs;
		else
			break;
	}

	return location_;
}

void
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
			*bt = NULL;
		}
		item_->lhs = NULL;
		item_->rhs = NULL;
		item_->parent = NULL;

		    (*delete_func)(item_, context);
	}
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
