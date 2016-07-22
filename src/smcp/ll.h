/*!	@file ll.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Linked-List functions
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

/*!	@defgroup ll Linked-List Functions
**	@{
*/


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

//!	Returns the last item in the linked list.
static inline void*
ll_last(
	void* item
) {
	ll_item_t iter = (ll_item_t)item;
	if(iter)
	while(iter->next) {
		iter = iter->next;
	}
	return iter;
}

//!	Returns the next item in the linked list.
static inline void*
ll_next(
	void* item
) {
	return ((ll_item_t)item)->next;
}


//!	Verifies that the linked list is internally consistent.
static inline bool
ll_verify(void* item) {
	int ret = 0;
	ll_item_t item_ = (ll_item_t)item;
	if(item) {
		while(item_->prev)
			item_ = item_->prev;
		for(; item_->next; item_ = item_->next)
			ret++;
		for(; item_->prev; item_ = item_->prev)
			ret--;
	}

	return ret == 0;
}

static inline void
ll_insert_after(
	void* where, void* item
) {
	ll_item_t const location_ = (ll_item_t)where;
	ll_item_t const item_ = (ll_item_t)item;

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
	ll_item_t const location_ = (ll_item_t)where;
	ll_item_t const item_ = (ll_item_t)item;

	LL_ASSERT(ll_verify(where));

	item_->next = location_;
	item_->prev = location_->prev;
	location_->prev = item_;
	if(item_->prev)
		item_->prev->next = item_;

	LL_ASSERT(ll_verify(item));
}

static inline void
ll_prepend(
	void** list, void* item
) {
	if(*list)
		ll_insert(*list, item);
	*list = item;
	LL_ASSERT(ll_verify(*list));
}

//!	Inserts an item into a sorted linked list.
static void
#ifndef __SDCC
inline
#endif
ll_sorted_insert(
	void** list, void* item, ll_compare_func_t compare_func, void* context
) {
	ll_item_t location_ = (ll_item_t)*list;

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
		if(location_ == *list) {
			ll_prepend(list, item);
		} else {
			ll_insert(location_, item);
		}
	} else {
		*list = item;
	}

	LL_ASSERT(ll_verify(*list));
}

static inline void
ll_remove(
	void** list, void* item
) {
	ll_item_t const item_ = (ll_item_t)item;

	LL_ASSERT(ll_verify((ll_item_t)*list));

	if(item_->prev)
		item_->prev->next = item_->next;
	if(item_->next)
		item_->next->prev = item_->prev;
	if((ll_item_t)*list == item_)
		*list = item_->next;

	LL_ASSERT(ll_verify(*list));
}

static inline void*
ll_pop(
	void** list
) {
	void* item = (ll_item_t)*list;
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

static inline int
ll_count(void* item) {
	int ret = 0;
	ll_item_t item_ = (ll_item_t)item;

	for(; item_; item_ = item_->next)
		ret++;
	return ret;
}

__END_DECLS

/*!	@} */

#endif
