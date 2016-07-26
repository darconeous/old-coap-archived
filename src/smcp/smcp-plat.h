/*!	@file smcp-plat.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Platfom-defined methods
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
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

#ifndef SMCP_PLAT_HEADER_INCLUDED
#define SMCP_PLAT_HEADER_INCLUDED 1

#if SMCP_USE_BSD_SOCKETS
#include "smcp-plat-bsd.h"
#elif SMCP_USE_UIP
#include "smcp-plat-uip.h"
#endif

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#if SMCP_EMBEDDED
#define smcp_plat_get_port(self)		smcp_plat_get_port()
#define smcp_plat_init(self)		smcp_plat_init()
#define smcp_plat_finalize(self)		smcp_plat_finalize()
#define smcp_plat_get_fd(self)		smcp_plat_get_fd()
#define smcp_plat_process(self)		smcp_plat_process()
#define smcp_plat_wait(self,...)		smcp_plat_wait(__VA_ARGS__)
#define smcp_plat_outbound_start(self,...)		smcp_plat_outbound_start(__VA_ARGS__)
#define smcp_plat_outbound_finish(self,...)		smcp_plat_outbound_finish(__VA_ARGS__)
#define smcp_plat_bind_to_port(self,...)		smcp_plat_bind_to_port(__VA_ARGS__)
#define smcp_plat_bind_to_sockaddr(self,...)		smcp_plat_bind_to_sockaddr(__VA_ARGS__)
#endif

#endif

/*!	@addtogroup smcp
**	@{
*/


/*!	@defgroup smcp-plat Platform API
**	@{
*/

/*!	## Defining New Platforms ##
**
**	Platforms have two header files, one for the public API (Called
**	something like `smcp-plat-bsd.h`, for example) and one for the
**	internal API (Called something like `smcp-plat-bsd-internal.h`).
**	These files are analogous to `smcp.h` and `smcp-internal.h`---they
**	describe both the external user-facing interface and the internal
**	under-the-hood implementation details.
**
**	To implement a new platform, the following methods must be implemented:
**
**	* smcp_plat_init()
**	* smcp_plat_finalize()
**	* smcp_plat_lookup_hostname()
**	* smcp_plat_bind_to_sockaddr()
**	* smcp_plat_bind_to_port()
**	* smcp_plat_cms_to_timestamp()
**	* smcp_plat_timestamp_to_cms()
**	* smcp_plat_timestamp_diff()
**	* smcp_plat_get_session_type()
**	* smcp_plat_set_session_type()
**	* smcp_plat_get_remote_sockaddr()
**	* smcp_plat_get_local_sockaddr()
**	* smcp_plat_set_remote_sockaddr()
**	* smcp_plat_set_local_sockaddr()
**	* smcp_plat_outbound_start()
**	* smcp_plat_outbound_send_packet()
**
**	Any data that you need to associate with an instance needs to
**	be stored in the struct `smcp_plat_s`, defined in the internal
**	platform-specific header:
**
**	* struct smcp_plat_s {}
**
**	Optionally, if the platform supports simplified run-loops you should also
**	implement:
**
**	* smcp_plat_process()
**	* smcp_plat_wait()
**
**	Optionally, if the platform supports unix file descriptors, you may want
**	to also implement:
**
**	* smcp_plat_update_pollfds()
**	* smcp_plat_update_fdsets()
**
*/

// MARK: -
// MARK: Async IO

/*!	@addtogroup smcp-asyncio
**	@{
*/

//!	Processes one event or inbound packet (if available).
/*!	This function must be called periodically for SMCP to
**	handle events and packets.
*/
SMCP_API_EXTERN smcp_status_t smcp_plat_process(smcp_t self);

//!	Block until smcp_plat_process() should be called.
/*! @returns 0 if smcp_plat_process() should be executed,
**           SMCP_STATUS_TIMEOUT if the given timeout expired,
**           or an error number if there is some sort of other failure.
**  Some platforms do not implement this function. */
SMCP_API_EXTERN smcp_status_t smcp_plat_wait(smcp_t self, smcp_cms_t cms);

/*!	@} */

/*!	@addtogroup smcp_timer
**	@{
*/

//!< Converts relative time from 'now' into an absolute time.
SMCP_API_EXTERN smcp_timestamp_t smcp_plat_cms_to_timestamp(
	smcp_cms_t cms //!< [IN] Time from now, in milliseconds
);

SMCP_API_EXTERN smcp_cms_t smcp_plat_timestamp_to_cms(smcp_timestamp_t timestamp);

SMCP_API_EXTERN smcp_cms_t smcp_plat_timestamp_diff(smcp_timestamp_t lhs, smcp_timestamp_t rhs);

/*!	@} */

//! Returns the current listening port of the instance in host order.
/*! This function will likely be DEPRECATED in the future */
SMCP_API_EXTERN uint16_t smcp_plat_get_port(smcp_t self);

SMCP_API_EXTERN smcp_status_t smcp_plat_bind_to_sockaddr(
	smcp_t self,
	smcp_session_type_t type,
	const smcp_sockaddr_t* sockaddr
);

SMCP_API_EXTERN smcp_status_t smcp_plat_bind_to_port(
	smcp_t self,
	smcp_session_type_t type,
	uint16_t port
);

SMCP_API_EXTERN void smcp_plat_set_remote_sockaddr(const smcp_sockaddr_t* addr);
SMCP_API_EXTERN void smcp_plat_set_local_sockaddr(const smcp_sockaddr_t* addr);
SMCP_API_EXTERN smcp_status_t smcp_plat_set_remote_hostname_and_port(const char* hostname, uint16_t port);
SMCP_API_EXTERN void smcp_plat_set_session_type(smcp_session_type_t type);

SMCP_API_EXTERN smcp_status_t smcp_plat_multicast_join(smcp_t self, smcp_addr_t *group, int interface);
SMCP_API_EXTERN smcp_status_t smcp_plat_multicast_leave(smcp_t self, smcp_addr_t *group, int interface);

//!	Gets a pointer to the sockaddr of the remote machine for the current packet.
SMCP_API_EXTERN const smcp_sockaddr_t* smcp_plat_get_remote_sockaddr(void);

//!	Gets a pointer to the sockaddr of the local socket for the current packet.
SMCP_API_EXTERN const smcp_sockaddr_t* smcp_plat_get_local_sockaddr(void);

//!	Gets the session type for the current packet.
SMCP_API_EXTERN smcp_session_type_t smcp_plat_get_session_type(void);

struct pollfd;

//! Support for `poll()` style asynchronous operation
SMCP_API_EXTERN int smcp_plat_update_pollfds(
	smcp_t self,
	struct pollfd *fds,
	int maxfds
);

#define SMCP_LOOKUP_HOSTNAME_FLAG_DEFAULT			0
#define SMCP_LOOKUP_HOSTNAME_FLAG_IPV6_ONLY			(1<<0)
#define SMCP_LOOKUP_HOSTNAME_FLAG_IPV4_ONLY			(1<<1)

SMCP_INTERNAL_EXTERN smcp_status_t smcp_plat_lookup_hostname(const char* hostname, smcp_sockaddr_t* sockaddr, int flags);
SMCP_INTERNAL_EXTERN smcp_status_t smcp_plat_outbound_start(smcp_t self, uint8_t** data_ptr, coap_size_t *data_len);
SMCP_INTERNAL_EXTERN smcp_status_t smcp_plat_outbound_finish(smcp_t self, const uint8_t* data_ptr, coap_size_t data_len, int flags);

/*!	@} */

/*!	@} */


#endif /* SMCP_PLAT_HEADER_INCLUDED */
