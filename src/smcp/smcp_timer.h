#ifndef __SMCP_TIMER_H__
#define __SMCP_TIMER_H__ 1

#include "smcp.h"
#include "ll.h"
#include "btree.h"

#define USEC_PER_SEC    (1000000)
#define USEC_PER_MSEC   (1000)
#define MSEC_PER_SEC    (1000)

typedef void (*smcp_timer_callback_t)(smcp_daemon_t smcp, void* context);

#if CONTIKI && !CONTIKI_TARGET_MINIMAL_NET && !CONTIKI_TARGET_NATIVE
#if !defined(timeval)
#define timeval timeval
typedef int32_t time_t;
typedef int32_t suseconds_t;
struct timeval {
	time_t		tv_sec;
	suseconds_t tv_usec;
};
#endif
#else
#include <sys/time.h>
#endif

typedef struct smcp_timer_s {
	struct ll_item_s		ll;
	struct timeval			fire_date;
	void*					context;
	smcp_timer_callback_t	callback;
	smcp_timer_callback_t	cancel;
} *smcp_timer_t;

extern smcp_timer_t smcp_timer_init(
	smcp_timer_t			self,
	smcp_timer_callback_t	callback,
	smcp_timer_callback_t	cancel,
	void*					context
);

extern smcp_status_t smcp_daemon_schedule_timer(
	smcp_daemon_t	self,
	smcp_timer_t	timer,
	int				cms
);

extern void smcp_daemon_invalidate_timer(
	smcp_daemon_t self, smcp_timer_t timer);
extern cms_t smcp_daemon_get_timeout(smcp_daemon_t self);
extern void smcp_daemon_handle_timers(smcp_daemon_t self);
extern bool smcp_daemon_timer_is_scheduled(
	smcp_daemon_t self, smcp_timer_t timer);

extern void convert_cms_to_timeval(
	struct timeval* tv, int cms);
extern int convert_timeval_to_cms(const struct timeval* tv);

#endif //__SMCP_TIMER_H__
