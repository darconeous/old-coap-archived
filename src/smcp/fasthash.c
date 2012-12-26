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
#pragma mark -
#pragma mark Fasthash

static struct fasthash_state_s global_fasthash_state;

static void
fasthash_feed_block(uint32_t blk) {
	blk ^= (global_fasthash_state.bytes>>2);
	global_fasthash_state.hash ^= blk;
	global_fasthash_state.hash = global_fasthash_state.hash*1664525 + 1013904223;
}

void
fasthash_start(uint32_t salt) {
	memset((void*)&global_fasthash_state,sizeof(global_fasthash_state),0);
	fasthash_feed_block(salt);
}

void
fasthash_feed_byte(uint8_t data) {
	global_fasthash_state.next |= (data<<(8*(global_fasthash_state.bytes++&3)));
	if((global_fasthash_state.bytes&3)==0) {
		fasthash_feed_block(global_fasthash_state.next);
		global_fasthash_state.next = 0;
	}
}

void
fasthash_feed(const uint8_t* data, uint8_t len) {
	while(len--)
		fasthash_feed_byte(*data++);
}

fasthash_hash_t
fasthash_finish() {
	if(global_fasthash_state.bytes&3) {
		fasthash_feed_block(global_fasthash_state.next);
		global_fasthash_state.bytes = 0;
	}
	return global_fasthash_state.hash;
}

uint32_t
fasthash_finish_uint32() {
	return fasthash_finish()>>0;
}

uint16_t
fasthash_finish_uint16() {
	return fasthash_finish_uint32()>>16;
}

uint8_t
fasthash_finish_uint8() {
	return fasthash_finish_uint32()>>24;
}
