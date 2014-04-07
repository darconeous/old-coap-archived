/*	@file smcp_timer.c
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

//#define ASSERT_MACROS_USE_VANILLA_PRINTF 1
//#define SMCP_DEBUG_TIMERS	1
//#define VERBOSE_DEBUG 1
//#define DEBUG 1

#include "assert-macros.h"
#include "smcp.h"

#if !SMCP_DEBUG_TIMERS && !VERBOSE_DEBUG
#undef DEBUG_PRINTF
#define DEBUG_PRINTF(fmt, ...) do { } while(0)
#endif

#include <stdio.h>

#include "smcp-timer.h"
#include "smcp.h"
#include "url-helpers.h"
#include "smcp-node-router.h"
#include <string.h>
#include "smcp-internal.h"

#ifndef SMCP_MAX_TIMEOUT
#define SMCP_MAX_TIMEOUT    (SMCP_CONF_MAX_TIMEOUT * MSEC_PER_SEC)
#endif

#if defined(CONTIKI)
#define gettimeofday gettimeofday_
int
gettimeofday(
	struct timeval *tv, void *tzp
) {
	if(tv) {
		tv->tv_sec = clock_seconds();
		tv->tv_usec = (clock_time() % CLOCK_SECOND) * (USEC_PER_SEC / CLOCK_SECOND);
		return 0;
	}
	return -1;
}
#endif

void
convert_cms_to_timeval(
	struct timeval* tv, cms_t cms
) {
	gettimeofday(tv, NULL);

	// Add all whole seconds to tv_sec
	tv->tv_sec += cms / MSEC_PER_SEC;

	// Remove all whole seconds from cms
	cms -= ((cms / MSEC_PER_SEC) * MSEC_PER_SEC);

	tv->tv_usec += ((cms % MSEC_PER_SEC) * MSEC_PER_SEC);

	tv->tv_sec += tv->tv_usec / USEC_PER_SEC;

	tv->tv_usec %= USEC_PER_SEC;
}

cms_t
period_between_timevals_in_cms(const struct timeval* tv_lhs,const struct timeval* tv_rhs) {
	cms_t ret = 0;
	ret = (cms_t)(tv_lhs->tv_sec - tv_rhs->tv_sec) * MSEC_PER_SEC;
	ret += (cms_t)(tv_lhs->tv_usec - tv_rhs->tv_usec) / USEC_PER_MSEC;
	return ret;
}


cms_t
convert_timeval_to_cms(const struct timeval* tv) {
	cms_t ret = 0;
	struct timeval current_time;

	gettimeofday(&current_time, NULL);

	ret = period_between_timevals_in_cms(tv, &current_time);

	if(ret < 0)
		ret = 0;

	return ret;
}


static ll_compare_result_t
smcp_timer_compare_func(
	const void* lhs_, const void* rhs_, void* context
) {
	const smcp_timer_t lhs = (smcp_timer_t)lhs_;
	const smcp_timer_t rhs = (smcp_timer_t)rhs_;

	if(lhs->fire_date.tv_sec > rhs->fire_date.tv_sec)
		return 1;

	if(lhs->fire_date.tv_sec < rhs->fire_date.tv_sec)
		return -1;

	if(lhs->fire_date.tv_usec > rhs->fire_date.tv_usec)
		return 1;

	if(lhs->fire_date.tv_usec < rhs->fire_date.tv_usec)
		return -1;

	return 0;
}


smcp_timer_t
smcp_timer_init(
	smcp_timer_t			self,
	smcp_timer_callback_t	callback,
	smcp_timer_callback_t	cancel,
	void*					context
) {
	if(self) {
		memset(self, 0, sizeof(*self));
		self->context = context;
		self->callback = callback;
		self->cancel = cancel;
	}
	return self;
}

bool
smcp_timer_is_scheduled(
	smcp_t self, smcp_timer_t timer
) {
	SMCP_EMBEDDED_SELF_HOOK;
	return timer->ll.next || timer->ll.prev || (self->timers == timer);
}

smcp_status_t
smcp_schedule_timer(
	smcp_t	self,
	smcp_timer_t	timer,
	cms_t			cms
) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	SMCP_EMBEDDED_SELF_HOOK;

	assert(self!=NULL);
	assert(timer!=NULL);

	// Make sure we aren't already part of the list.
	require(!timer->ll.next, bail);
	require(!timer->ll.prev, bail);
	require(self->timers != timer, bail);

	DEBUG_PRINTF("Timer:%p: Scheduling to fire in %dms ...",timer,cms);
#if SMCP_DEBUG_TIMERS
	size_t previousTimerCount = ll_count(self->timers);
#endif

	if(cms<0)
		cms = 0;

	convert_cms_to_timeval(&timer->fire_date, cms);

	ll_sorted_insert(
		    (void**)&self->timers,
		timer,
		&smcp_timer_compare_func,
		NULL
	);

	ret = SMCP_STATUS_OK;

	DEBUG_PRINTF("Timer:%p(CTX=%p): Scheduled.",timer,timer->context);
	DEBUG_PRINTF("%p: Timers in play = %d",self,(int)ll_count(self->timers));

#if SMCP_DEBUG_TIMERS
	assert((ll_count(self->timers)) == previousTimerCount+1);
#endif

bail:
	return ret;
}

void
smcp_invalidate_timer(
	smcp_t	self,
	smcp_timer_t	timer
) {
	SMCP_EMBEDDED_SELF_HOOK;
#if SMCP_DEBUG_TIMERS
	size_t previousTimerCount = ll_count(self->timers);
	// Sanity check. If we don't have at least one timer
	// then we know something is off.
	check(previousTimerCount>=1);
#endif

	DEBUG_PRINTF("Timer:%p: Invalidating...",timer);
	DEBUG_PRINTF("Timer:%p: (CTX=%p)",timer,timer->context);

	ll_remove((void**)&self->timers, (void*)timer);

#if SMCP_DEBUG_TIMERS
	check((ll_count(self->timers)) == previousTimerCount-1);
#endif
	timer->ll.next = NULL;
	timer->ll.prev = NULL;
	if(timer->cancel)
		(*timer->cancel)(self,timer->context);
	DEBUG_PRINTF("Timer:%p: Invalidated.",timer);
	DEBUG_PRINTF("%p: Timers in play = %d",self,(int)ll_count(self->timers));
}

#if SMCP_DEBUG_TIMERS || VERBOSE_DEBUG
void
smcp_dump_all_timers(smcp_t self) {
	smcp_timer_t iter;

	if(self->timers) {
		DEBUG_PRINTF("smcp(%p): Current Timers:",self);

		for(iter = self->timers;iter;iter = (void*)iter->ll.next) {
			DEBUG_PRINTF("\t* [%p] expires-in:%dms context:%p",iter,convert_timeval_to_cms(&iter->fire_date),iter->context);
		}
	} else {
		DEBUG_PRINTF("smcp(%p): No timers active.",self);
	}
}
#endif

cms_t
smcp_get_timeout(smcp_t self) {
	cms_t ret = SMCP_MAX_TIMEOUT;
	SMCP_EMBEDDED_SELF_HOOK;

	if(self->timers)
		ret = MIN(ret, convert_timeval_to_cms(&self->timers->fire_date));

	ret = MAX(ret, 0);

#if VERBOSE_DEBUG
	if(ret != SMCP_MAX_TIMEOUT) {
		smcp_dump_all_timers(self);
		DEBUG_PRINTF("%p: next timeout = %dms", self, ret);
	}
#endif
	return ret;
}

void
smcp_handle_timers(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	if(	self->timers
		&& (convert_timeval_to_cms(&self->timers->fire_date) <= 0)
	) {
		SMCP_NON_RECURSIVE smcp_timer_t timer;
		SMCP_NON_RECURSIVE smcp_timer_callback_t callback;
		SMCP_NON_RECURSIVE void* context;

		timer = self->timers;
		callback = timer->callback;
		context = timer->context;

		DEBUG_PRINTF("Timer:%p(CTX=%p): Firing...",timer,timer->context);

		timer->cancel = NULL;
		smcp_invalidate_timer(self, timer);
		if(callback)
			callback(self, context);
	}
#if SMCP_DEBUG_TIMERS
	smcp_dump_all_timers(self);
#endif
}
