/*!	@file btree.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Binary Tree Functions
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
*/

#ifndef __BTREE_HEADER__
#define __BTREE_HEADER__ 1

#if !defined(__BEGIN_DECLS) || !defined(__END_DECLS)
#if defined(__cplusplus)
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS \
	}
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>      // For ssize_t

__BEGIN_DECLS

/*!	@defgroup btree Binary Tree Functions
**	@{
*/


struct bt_item_s;

typedef struct bt_item_s *bt_item_t;

struct bt_item_s {
	bt_item_t	lhs;
	bt_item_t	rhs;
	bt_item_t	parent;
};

typedef signed char bt_compare_result_t;

typedef bt_compare_result_t (*bt_compare_func_t)(const void* lhs,
    const void* rhs, void* context);

typedef void (*bt_delete_func_t)(void* item, void* context);

//! Inserts the given item into the tree.
extern int bt_insert(
	void**				bt,		//!< Pointer to the root of the tree
	void*				item,	//!< Item to insert
	bt_compare_func_t	compare_func,	//!< Comparison function
	bt_delete_func_t	delete_func,	//!< Deletion function, used if comparison is equal
	void*				context	//!< Context, passed into comparison and deletion callbacks.
);

//! Finds and returns a node matching the given criteria.
extern void* bt_find(
	void*const*			bt,
	const void*			item,
	bt_compare_func_t	compare_func,
	void*				context
);

//! Removes the given item from the tree, if present.
extern bool bt_remove(
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context
);

//!	Finds the left-most node in the subtree described by item.
extern void* bt_first(void* item);

//!	Finds the right-most node in the subtree described by item.
extern void* bt_last(void* item);

//!	Returns the next node in the tree, or NULL the given item is the last (right-most) node in the tree.
//! Performs an in-order depth-first traversal.
extern void* bt_next(void* item);

//!	Returns the previous node in the tree, or NULL the given item is the first (left-most) node in the tree.
//! Performs a reverse-order depth-first traversal.
extern void* bt_prev(void* item);

//!	Traverses the given tree to determine the number of nodes it contains.
extern int bt_count(void*const* bt);

extern int bt_get_balance(void* node);

extern void bt_rotate_left(void** pivot);

extern void bt_rotate_right(void** pivot);

//!	Completely rebalance of the tree.
extern unsigned int bt_rebalance(void** bt);

//!	Completely unbalances the tree. Primarily useful for debugging.
extern unsigned int bt_unbalance(void** bt);

//!	Splays the tree to a new root. Useful for splay trees.
extern unsigned int bt_splay(void** bt, void* root);

__END_DECLS

/*!	@} */

#endif
