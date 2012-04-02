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

#if LL_DEBUG
#include <assert.h>
#define LL_ASSERT(x)	assert(x)
#else
#define LL_ASSERT(x)	do { } while(0)
#endif

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

static inline void*
ll_last(
	void* item
) {
	ll_item_t iter = item;
	if(iter)
	while(iter->next) {
		iter = iter->next;
	}
	return iter;
}

static inline bool
ll_verify(void* item) {
	int ret = 0;
	ll_item_t item_ = item;
	if(item) {
		while(item_->prev)
			item_ = item_->prev;
		for(; item_->next; item_ = item_->next)
			ret++;
		for(; item_->prev; item_ = item_->prev)
			ret--;
	}

	LL_ASSERT(ret==0);
	return ret == 0;
}

static inline void
ll_insert_after(
	void* where, void* item
) {
	ll_item_t const location_ = where;
	ll_item_t const item_ = item;

	LL_ASSERT(ll_verify(where));

	item_->prev = location_;
	if((item_->next = location_->next))
		item_->next->prev = item_;
	location_->next = item_;

	LL_ASSERT(ll_verify(where));
}

static inline void
ll_insert(
	void* where, void* item
) {
	ll_item_t const location_ = where;
	ll_item_t const item_ = item;

	LL_ASSERT(ll_verify(where));

	item_->next = location_;
	item_->prev = location_->prev;
	location_->prev = item;
	if(item_->prev)
		item_->prev->next = item_;

	LL_ASSERT(ll_verify(item));
}

static inline void
ll_prepend(
	void** list, void* item
) {
	ll_insert(*list, item);
	*list = item;
	LL_ASSERT(ll_verify(*list));
}

static inline void
ll_sorted_insert(
	void** list, void* item, ll_compare_func_t compare_func, void* context
) {
	ll_item_t location_ = *list;

	LL_ASSERT(ll_verify(location_));

	if(location_) {
		while(compare_func(item, location_, context) >= 0) {
			LL_ASSERT(ll_verify(location_));
			if(location_->next) {
				location_ = location_->next;
			} else {
				// We are at the end of the list,
				// so go ahead and add us to the end.
				ll_insert_after(location_, item);
				return;
			}
		}
		if(location_!=*list)
			ll_insert(location_,item);
		else
			ll_prepend(list,item);
	} else {
		*list = item;
	}
	LL_ASSERT(ll_verify(*list));
}

static inline void
ll_remove(
	void** list, void* item
) {
	ll_item_t const item_ = item;

	LL_ASSERT(ll_verify(*list));

	if(item_->prev)
		item_->prev->next = item_->next;
	if(item_->next)
		item_->next->prev = item_->prev;
	if(*list == item_)
		*list = item_->next;

	LL_ASSERT(ll_verify(*list));
}

static inline void*
ll_pop(
	void** list
) {
	void* item = *list;
	ll_remove(list,item);
	return item;
}

static inline void
ll_push(
	void** list, void* item
) {
	if(*list)
		ll_insert_after(ll_last(*list),item);
	else
		*list = item;

	LL_ASSERT(ll_verify(*list));
}

static inline size_t
ll_count(void* item) {
	size_t ret = 0;
	ll_item_t item_ = item;

	for(; item_; item_ = item_->next)
		ret++;
	return ret;
}

__END_DECLS

#endif
