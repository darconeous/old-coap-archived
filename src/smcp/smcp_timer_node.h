#ifndef __SMCP_TIMER_NODE_H__
#define __SMCP_TIMER_NODE_H__ 1

#include "smcp_timer.h"
#include "smcp_node.h"

#ifndef SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
#define SMCP_CONF_TIMER_NODE_INCLUDE_COUNT 1
#endif

typedef struct smcp_timer_node_s {
	struct smcp_node_s	node;
	struct smcp_timer_s timer;
	uint32_t			period;
	uint32_t			remaining;
#if SMCP_CONF_TIMER_NODE_INCLUDE_COUNT
	uint32_t			count;
#endif
	uint8_t				autorestart;
} *smcp_timer_node_t;

smcp_timer_node_t smcp_timer_node_alloc();
smcp_timer_node_t smcp_timer_node_init(
	smcp_timer_node_t	self,
	smcp_node_t			parent,
	const char*			name
);


void smcp_timer_node_start(smcp_timer_node_t self);
void smcp_timer_node_stop(smcp_timer_node_t self);
void smcp_timer_node_reset(smcp_timer_node_t self);
void smcp_timer_node_restart(smcp_timer_node_t self);
void smcp_timer_node_set_autorestart(smcp_timer_node_t self, bool x);

#endif //__SMCP_TIMER_NODE_H__
