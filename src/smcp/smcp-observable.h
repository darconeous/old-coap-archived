/*	@file smcp-observable.h
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

/*!	@defgroup smcp_observable Observable API
**	@{
*/

struct smcp_observable_s {
#if !SMCP_EMBEDDED
	smcp_t interface;
#endif
	int8_t first_observer; //!^ always +1, zero is end of list
	int8_t last_observer; //!^ always +1, zero is end of list
};

#define SMCP_OBSERVABLE_BROADCAST_KEY		(0xFF)

typedef struct smcp_observable_s *smcp_observable_t;

extern smcp_status_t smcp_observable_update(smcp_observable_t context, uint8_t key);

extern smcp_status_t smcp_observable_trigger(smcp_observable_t context, uint8_t key);

/*!	@} */
/*!	@} */

__END_DECLS

#endif
