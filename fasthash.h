//
//  fasthash.h
//  SMCP
//
//  Created by Robert Quattlebaum on 12/23/12.
//  Copyright (c) 2012 deepdarc. All rights reserved.
//

#ifndef SMCP_fasthash_h
#define SMCP_fasthash_h

#include <stdint.h>

// Warning: This is not reentrant!
// Justification for non-reentrancy was to avoid extra stack usage on
// constrainted platforms.

typedef uint32_t fasthash_hash_t;

struct fasthash_state_s {
	fasthash_hash_t hash;
	uint32_t bytes;
	fasthash_hash_t next;
};

extern void fasthash_start(fasthash_hash_t salt);
extern void fasthash_feed_byte(uint8_t data);
extern void fasthash_feed(const uint8_t* data, uint8_t len);
extern fasthash_hash_t fasthash_finish();
extern uint32_t fasthash_finish_uint32();
extern uint16_t fasthash_finish_uint16();
extern uint8_t fasthash_finish_uint8();


#endif
