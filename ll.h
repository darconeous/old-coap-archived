/*	Linked List Utilities
**
**	Written by Robert Quattlebaum <darco@deepdarc.com>.
**	PUBLIC DOMAIN.
*/

#ifndef __LL_HEADER__
#define __LL_HEADER__ 1

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

struct ll_item_s;
typedef struct ll_item_s *ll_item_t;
struct ll_item_s {
	ll_item_t	next;
	ll_item_t	prev;
};

typedef int ll_compare_result_t;
typedef ll_compare_result_t (*ll_compare_func_t)(const void* lhs,
    const void* rhs, void* context);


static inline void
ll_insert_after(
	void* where, void* item
) {
	ll_item_t const location_ = where;
	ll_item_t const item_ = item;

	item_->prev = location_;
	item_->next = location_->next;
	location_->next = item_;
}

static inline void
ll_insert(
	void* where, void* item
) {
	ll_item_t const location_ = where;
	ll_item_t const item_ = item;

	item_->next = location_;
	if(location_) {
		item_->prev = location_->prev;
		location_->prev = item;
	}
}

static inline void
ll_prepend(
	void** list, void* item
) {
	ll_insert(*list, item);
	*list = item;
}

static inline void
ll_sorted_insert(
	void** list, void* item, ll_compare_func_t compare_func, void* context
) {
	ll_item_t location_ = *list;

	if(location_) {
		while(compare_func(item, location_, context) > 1) {
			if(location_->next) {
				location_ = location_->next;
			} else {
				ll_insert_after(location_, item);
				return;
			}
		}
		ll_insert(location_, item);
	} else {
		*list = item;
	}
}

static inline void
ll_remove(
	void** list, void* item
) {
	ll_item_t const item_ = item;

	if(item_->prev)
		item_->prev->next = item_->next;
	if(item_->next)
		item_->next->prev = item_->prev;
	if(*list == item_)
		*list = item_->next;
}

__END_DECLS

#endif
