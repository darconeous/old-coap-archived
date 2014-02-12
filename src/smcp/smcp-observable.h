/*!	@file smcp-observable.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2013 Robert Quattlebaum
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

#ifndef __SMCP_OBSERVABLE_H__
#define __SMCP_OBSERVABLE_H__ 1

#include "smcp.h"

__BEGIN_DECLS

/*!	@addtogroup smcp
**	@{
*/

/*!	@defgroup smcp-observable Observable API
**	@{
**	@brief Functions for creating observable resources.
**
**	@sa @ref smcp-example-4
*/

//! Observable context.
/*!	The observable context is a datastructure that keeps track of
**	who is observing which resources. You may have as many or as few as
**	you like.
**
**	@sa smcp_observable_update(), smcp_observable_trigger()
*/
struct smcp_observable_s {
#if !SMCP_EMBEDDED
	smcp_t interface;
#endif

	// Consider all members below this line as private!

	int8_t first_observer; //!^ always +1, zero is end of list
	int8_t last_observer; //!^ always +1, zero is end of list
};

//! Key to trigger all observers using the given observable context.
#define SMCP_OBSERVABLE_BROADCAST_KEY		(0xFF)

typedef struct smcp_observable_s *smcp_observable_t;

//!	Hook for making a resource observable.
/*!	This must be called after you have "begun" to compose the outbound
**	response message but *before* you have started to compose the content.
**	More explicitly:
**
**	 * *After* smcp_outbound_begin() or smcp_outbound_begin_response()
**	 * *Before* smcp_outbound_get_content_ptr(), smcp_outbound_append_content(),
**	   smcp_outbound_send(), etc.
**
**	You may choose any value for `key`, as long as it matches what you pass
**	to smcp_observable_trigger() to trigger updates.
*/
extern smcp_status_t smcp_observable_update(
	smcp_observable_t context, //!< [IN] Pointer to observable context
	uint8_t key		//!< [IN] Key for this resource (must be same as used in trigger)
);

//!	Triggers an observable resource to send an update to its observers.
/*!
**	You may use SMCP_OBSERVABLE_BROADCAST_KEY for the key to trigger
**	all resources associated with this observable context to update.
*/
extern smcp_status_t smcp_observable_trigger(
	smcp_observable_t context, //!< [IN] Pointer to observable context
	uint8_t key,	//!< [IN] Key for this resource (must be same as used in update)
	uint8_t flags	//!< [IN] Flags (Currently unused)
);

//!	Gets the number of observers for a given resource and key
/*!
**	You may use SMCP_OBSERVABLE_BROADCAST_KEY for the key to get the
**	count of all observers associated with this context.
*/
extern int smcp_observable_observer_count(
	smcp_observable_t context, //!< [IN] Pointer to observable context
	uint8_t key	//!< [IN] Key for this resource (must be same as used in update)
);

/*!	@} */
/*!	@} */

__END_DECLS

#endif
