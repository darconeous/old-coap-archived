/*!	@file smcp-dupe.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Duplicate packet detection
**
**	Copyright (C) 2014 Robert Quattlebaum
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

#include <stdio.h>
#include "smcp-internal.h"
#include "smcp-dupe.h"
#include "fasthash.h"

// TODO: This code could use some optimization.

bool
smcp_inbound_dupe_check(void)
{
	smcp_t const self = smcp_get_current_instance();
	bool is_dupe = false;
	struct fasthash_state_s fasthash;
	uint32_t hash;

	// Calculate the message-id hash (address+port+message_id)
	fasthash_start(&fasthash, 0);
	fasthash_feed(&fasthash, (const void*)smcp_plat_get_remote_sockaddr(), sizeof(smcp_sockaddr_t));
	fasthash_feed(&fasthash, (const uint8_t*)&self->inbound.packet->msg_id,sizeof(self->inbound.packet->msg_id));
	hash = fasthash_finish_uint32(&fasthash);

	// Check to see if this packet is a duplicate.
	unsigned int i = SMCP_CONF_DUPE_BUFFER_SIZE;
	while (i--) {
		if (self->dupe_info.dupe[i].hash == hash) {
			if ((0 == memcmp(&self->dupe_info.dupe[i].from, (const void*)smcp_plat_get_remote_sockaddr(), sizeof(smcp_sockaddr_t)))
				&& (self->dupe_info.dupe[i].msg_id == self->inbound.packet->msg_id)
			) {
				is_dupe = true;
				break;
			}
		}
	}

	if (!is_dupe) {
		// This is not a dupe, add it to the list.
		self->dupe_info.dupe[self->dupe_info.dupe_index].hash = hash;
		self->dupe_info.dupe[self->dupe_info.dupe_index].msg_id = self->inbound.packet->msg_id;
		memcpy(&self->dupe_info.dupe[self->dupe_info.dupe_index].from, (const void*)smcp_plat_get_remote_sockaddr(), sizeof(smcp_sockaddr_t));
		self->dupe_info.dupe_index++;
		self->dupe_info.dupe_index %= SMCP_CONF_DUPE_BUFFER_SIZE;
	}

	return is_dupe;
}
