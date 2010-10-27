//#define VERBOSE_DEBUG 1

#include "assert_macros.h"
#include "smcp_timer.h"
#include <stdio.h>
#include "smcp.h"
#include "url-helpers.h"
#include "smcp_node.h"
#include <string.h>
#include "smcp_internal.h"
#include "smcp_logging.h"

#ifndef SMCP_MAX_TIMEOUT
#define SMCP_MAX_TIMEOUT    (60 * MSEC_PER_SEC)
#endif

#if defined(__CONTIKI__)
#define gettimeofday gettimeofday_
int
gettimeofday(
	struct timeval *tv, void *tzp
) {
	if(tv) {
		tv->tv_sec = clock_seconds();
		tv->tv_usec =
		    (clock_time() % CLOCK_SECOND) * USEC_PER_SEC / CLOCK_SECOND;
		return 0;
	}
	return -1;
}
#endif

void
convert_cms_to_timeval(
	struct timeval* tv, int cms
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

int
convert_timeval_to_cms(const struct timeval* tv) {
	int ret = 0;
	struct timeval current_time;

	gettimeofday(&current_time, NULL);

	if(current_time.tv_sec <= tv->tv_sec) {
		ret = (tv->tv_sec - current_time.tv_sec) * MSEC_PER_SEC;
		ret += (tv->tv_usec - current_time.tv_usec) / USEC_PER_MSEC;

		if(ret < 0)
			ret = 0;
	}

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

bool smcp_daemon_timer_is_scheduled(
	smcp_daemon_t self, smcp_timer_t timer
) {
	return timer->ll.next || timer->ll.prev || (self->timers == timer);
}

extern smcp_status_t smcp_daemon_schedule_timer(
	smcp_daemon_t	self,
	smcp_timer_t	timer,
	int				cms
) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;

	check(self);
	check(timer);

	// Make sure we aren't already part of the list.
	require(!timer->ll.next, bail);
	require(!timer->ll.prev, bail);
	require(self->timers != timer, bail);

	convert_cms_to_timeval(&timer->fire_date, cms);

	ll_sorted_insert(
		    (void**)&self->timers,
		timer,
		&smcp_timer_compare_func,
		NULL
	);

	ret = SMCP_STATUS_OK;

bail:
	return ret;
}

void
smcp_daemon_invalidate_timer(
	smcp_daemon_t	self,
	smcp_timer_t	timer
) {
	ll_remove((void**)&self->timers, (void*)timer);
	timer->ll.next = NULL;
	timer->ll.prev = NULL;
	DEBUG_PRINTF(CSTR("%p: invalidated timer %p"), self, timer);
	DEBUG_PRINTF(CSTR("%p: Timers in play = %d"), self,
		    (int)ll_count(self->timers));
}

cms_t
smcp_daemon_get_timeout(smcp_daemon_t self) {
	cms_t ret = SMCP_MAX_TIMEOUT;

	if(self->timers)
		ret = MIN(ret, convert_timeval_to_cms(&self->timers->fire_date));

	ret = MAX(ret, 0);

	if(ret != SMCP_MAX_TIMEOUT)
		DEBUG_PRINTF(CSTR("%p: next timeout = %dms"), self, ret);
	return ret;
}

void
smcp_daemon_handle_timers(smcp_daemon_t self) {
	while(self->timers &&
	        (convert_timeval_to_cms(&self->timers->fire_date) <= 0)) {
		smcp_timer_t timer = self->timers;
		smcp_timer_callback_t callback = timer->callback;
		void* context = timer->context;
		smcp_daemon_invalidate_timer(self, timer);
		if(callback)
			callback(self, context);
	}
}
