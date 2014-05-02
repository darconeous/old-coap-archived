/*	@file fasthash.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2012 Robert Quattlebaum
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
