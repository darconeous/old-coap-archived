/*	Binary Tree Utilities
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

__BEGIN_DECLS

struct bt_item_s;
typedef struct bt_item_s *bt_item_t;
struct bt_item_s {
	bt_item_t	lhs;
	bt_item_t	rhs;
	bt_item_t	parent;
};
typedef int bt_compare_result_t;

typedef bt_compare_result_t (*bt_compare_func_t)(const void* lhs,
    const void* rhs, void* context);
typedef void (*bt_delete_func_t)(void* lhs, void* context);

extern void bt_insert(
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context);
extern void* bt_find(
	void**				bt,
	const void*			item,
	bt_compare_func_t	compare_func,
	void*				context);
extern void bt_remove(
	void**				bt,
	void*				item,
	bt_compare_func_t	compare_func,
	bt_delete_func_t	delete_func,
	void*				context);
extern void* bt_first(void* item);
extern void* bt_next(void* item);

extern int bt_count(void** bt);

__END_DECLS

#endif
