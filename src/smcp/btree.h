/*	Flexible Binary Tree Utilities
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
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
#include <stdio.h>      // For ssize_t

__BEGIN_DECLS

struct bt_item_s;

typedef struct bt_item_s *bt_item_t;

struct bt_item_s {
	bt_item_t	lhs;
	bt_item_t	rhs;
	bt_item_t	parent;
};

typedef char bt_compare_result_t;

typedef bt_compare_result_t (*bt_compare_func_t)(const void* lhs,
    const void* rhs, void* context);

typedef void (*bt_delete_func_t)(void* item, void* context);

//! Inserts the given item into the tree.
extern void bt_insert(
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context);

//! Finds and returns a node matching the given criteria.
extern void* bt_find(
	void*const*			bt,
	const void*			item,
	bt_compare_func_t	compare_func,
	void*				context);

//! Removes the given item from the tree, if present.
extern bool bt_remove(
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context);

//!	Finds the left-most node in the subtree described by item.
extern void* bt_first(void* item);

//!	Finds the right-most node in the subtree described by item.
extern void* bt_last(void* item);

//!	Returns the next node in the tree, or NULL the given item is the last (right-most) node in the tree.
extern void* bt_next(void* item);

//!	Returns the previous node in the tree, or NULL the given item is the first (left-most) node in the tree.
extern void* bt_prev(void* item);

//!	Traverses the given tree to determine the number of nodes it contains.
extern size_t bt_count(void*const* bt);

extern void bt_rotate_left(void** bt);
extern void bt_rotate_right(void** bt);
extern unsigned int bt_rebalance(void** bt);
extern int bt_get_balance(void* item);

__END_DECLS

#endif
