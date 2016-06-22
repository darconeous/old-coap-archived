//
//  fasthash.c
//  SMCP
//
//  Created by Robert Quattlebaum on 12/23/12.
//  Copyright (c) 2012 deepdarc. All rights reserved.
//

#include "fasthash.h"
#include <stdio.h>
#include <string.h>

///////////////////////////////////////////////////////////////////////////////
// MARK: -
// MARK: Fasthash

static void
fasthash_feed_block(struct fasthash_state_s* state, uint32_t blk) {
	// XOR the block count into the block.
	blk ^= (state->bytes >> 2);

	// XOR the previous result into the hash state.
	state->hash ^= blk;

	// Mix up the hash state using a linear congruential generator.
	state->hash = state->hash * 1664525 + 1013904223;

	state->hash ^= blk * 1103515245;
}

void
fasthash_start(struct fasthash_state_s* state, uint32_t salt) {
	memset((void*)state, 0, sizeof(*state));
	// Feed in the salt first.
	fasthash_feed_block(state, salt);
}

void
fasthash_feed_byte(struct fasthash_state_s* state, uint8_t data) {
	state->next |= (data << (8 * (state->bytes++ & 3)));
	if ((state->bytes & 3) == 0) {
		fasthash_feed_block(state, state->next);
		state->next = 0;
	}
}

void
fasthash_feed(struct fasthash_state_s* state, const uint8_t* data, uint8_t len) {
	while (len--) {
		fasthash_feed_byte(state, *data++);
	}
}

fasthash_hash_t
fasthash_finish(struct fasthash_state_s* state) {
	if (state->bytes & 3) {
		fasthash_feed_block(state, state->next);
		state->bytes = 0;
	}

	// One last shuffle
	fasthash_feed_block(state, 1103515245);

	return state->hash;
}

uint32_t
fasthash_finish_uint32(struct fasthash_state_s* state) {
	return fasthash_finish(state) >> 0;
}

uint16_t
fasthash_finish_uint16(struct fasthash_state_s* state) {
	return fasthash_finish_uint32(state)>>16;
}

uint8_t
fasthash_finish_uint8(struct fasthash_state_s* state) {
	return fasthash_finish_uint32(state)>>24;
}
