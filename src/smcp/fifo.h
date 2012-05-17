// NOT FINISHED.

#ifndef __FIFO_HEADER__
#define __FIFO_HEADER__ 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint8_t head,tail;
	uint8_t buffer[256];
} fifo_256_t;

static inline bool
fido_256_push(fifo_256_t* fifo,const uint8_t* data, uint8_t len) {
	if(255-(tail-head)<len) {
		// Not enough space.
		return NO;
	}

	if(255-head>=len) {
		memcpy(fifo->buffer+head,data,len);
	} else {
	}

	head += len;
	return YES;
}

#endif
