/*	@file smcp-plat-bsd-internal.h
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

#ifndef SMCP_smcp_plat_bsd_internal_h
#define SMCP_smcp_plat_bsd_internal_h

#if !SMCP_USE_BSD_SOCKETS
#error SMCP_USE_BSD_SOCKETS not defined
#endif

#define __USE_GNU	1
#define __APPLE_USE_RFC_3542 1

#include "smcp.h"
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef SMCP_BSD_SOCKETS_NET_FAMILY
#define SMCP_BSD_SOCKETS_NET_FAMILY		AF_INET6
#endif

#define SMCP_ADDR_NTOP(str, len, addr) inet_ntop(SMCP_BSD_SOCKETS_NET_FAMILY, addr , str, len-1)

#if SMCP_BSD_SOCKETS_NET_FAMILY == AF_INET6
#define ___smcp_len		sin6_len
#define ___smcp_family	sin6_family
#define SMCP_IS_ADDR_MULTICAST(addrptr)	  (IN6_IS_ADDR_MULTICAST(addrptr) || (IN6_IS_ADDR_V4MAPPED(addrptr) && ((addrptr)->s6_addr[12] & 0xF0)==0xE0))
#define SMCP_IS_ADDR_LOOPBACK(addrptr)	  (IN6_IS_ADDR_LOOPBACK(addrptr) || (IN6_IS_ADDR_V4MAPPED(addrptr) && (addrptr)->s6_addr[12] == 127))
#define SMCP_IS_ADDR_UNSPECIFIED(addrptr) IN6_IS_ADDR_UNSPECIFIED(addrptr)

#define SMCP_COAP_MULTICAST_ALLDEVICES_ADDR	COAP_MULTICAST_IP6_LL_ALLDEVICES

#ifdef IPV6_RECVPKTINFO
#define SMCP_RECVPKTINFO IPV6_RECVPKTINFO
#endif
#ifdef IPV6_PKTINFO
#define SMCP_PKTINFO IPV6_PKTINFO
#endif
#define SMCP_IPPROTO IPPROTO_IPV6

#elif SMCP_BSD_SOCKETS_NET_FAMILY == AF_INET
#define ___smcp_len		sin_len
#define ___smcp_family	sin_family
#ifdef IP_RECVPKTINFO
#define SMCP_RECVPKTINFO IP_RECVPKTINFO
#endif
#ifdef IP_PKTINFO
#define SMCP_PKTINFO IP_PKTINFO
#endif
#define SMCP_IPPROTO IPPROTO_IPV4

#define SMCP_IS_ADDR_MULTICAST(addrptr) ((*(const uint8_t*)(addrptr)&0xF0)==224)
#define SMCP_IS_ADDR_UNSPECIFIED(addrptr) (*(const uint32_t*)(addrptr)==0)
#define SMCP_IS_ADDR_LOOPBACK(addrptr)	(*(const uint8_t*)(addrptr)==127)
#define SMCP_COAP_MULTICAST_ALLDEVICES_ADDR	COAP_MULTICAST_IP4_ALLDEVICES

#else  // SMCP_BSD_SOCKETS_NET_FAMILY
#error Unsupported value for SMCP_BSD_SOCKETS_NET_FAMILY
#endif // SMCP_BSD_SOCKETS_NET_FAMILY

SMCP_INTERNAL_EXTERN smcp_status_t smcp_internal_lookup_hostname(const char* hostname, smcp_sockaddr_t* sockaddr);

#endif
