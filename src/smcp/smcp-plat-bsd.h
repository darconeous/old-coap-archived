/*	@file smcp-plat-bsd.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
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

#ifndef SMCP_smcp_plat_bsd_h
#define SMCP_smcp_plat_bsd_h

#if !SMCP_USE_BSD_SOCKETS
#error SMCP_USE_BSD_SOCKETS not defined
#endif

#define __USE_GNU	1
#define __APPLE_USE_RFC_3542 1

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef SMCP_BSD_SOCKETS_NET_FAMILY
#define SMCP_BSD_SOCKETS_NET_FAMILY		AF_INET6
#endif

#if SMCP_BSD_SOCKETS_NET_FAMILY == AF_INET6
typedef struct in6_addr smcp_addr_t;
typedef struct sockaddr_in6 smcp_sockaddr_t;
#define smcp_addr		sin6_addr
#define smcp_port		sin6_port
#elif SMCP_BSD_SOCKETS_NET_FAMILY == AF_INET
typedef struct in_addr smcp_addr_t;
typedef struct sockaddr_in smcp_sockaddr_t;
#define smcp_addr		sin_addr
#define smcp_port		sin_port
#else  // SMCP_BSD_SOCKETS_NET_FAMILY
#error Unsupported value for SMCP_BSD_SOCKETS_NET_FAMILY
#endif // SMCP_BSD_SOCKETS_NET_FAMILY

//!	Gets the file descriptor for the UDP socket.
/*!	Useful for implementing asynchronous operation using select(),
**	poll(), or other async mechanisms. */
extern int smcp_get_fd(smcp_t self);

#endif
