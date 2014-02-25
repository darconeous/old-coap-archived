/*!	@file smcp-opts.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief SMCP Build Options
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

#ifndef __SMCP_OPS_H__
#define __SMCP_OPS_H__

#include "coap.h"

/*****************************************************************************/
#pragma mark - SMCP Build Parameters

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef SMCP_EMBEDDED
#if CONTIKI
#define SMCP_EMBEDDED			(1)
#else
#define SMCP_EMBEDDED			(0)
#endif
#endif

#ifndef SMCP_USE_BSD_SOCKETS
#define SMCP_USE_BSD_SOCKETS    !SMCP_EMBEDDED
#endif

#ifndef SMCP_USE_UIP
#define SMCP_USE_UIP			!SMCP_USE_BSD_SOCKETS
#endif

#if !defined(SMCP_UIP_INCLUDE_PATH)
#if CONTIKI
#define SMCP_UIP_INCLUDE_PATH	"net"
#else
#define SMCP_UIP_INCLUDE_PATH	"uip"
#endif
#endif

#ifndef SMCP_DEFAULT_PORT
#define SMCP_DEFAULT_PORT           COAP_DEFAULT_PORT
#endif

#define SMCP_DEFAULT_PORT_CSTR      #SMCP_DEFAULT_PORT

#ifndef IPv4_COMPATIBLE_IPv6_PREFIX
#define IPv4_COMPATIBLE_IPv6_PREFIX "::FFFF:"
#endif

#ifndef SMCP_MAX_PATH_LENGTH
#define SMCP_MAX_PATH_LENGTH        (127)
#endif

#ifndef SMCP_MAX_URI_LENGTH
// This is calclated as the sum of the following:
//	* strlen("coap://")
//	* strlen("[0000:0000:0000:0000:0000:0000:0000:0000]:65535")
//	* SMCP_MAX_PATH_LENGTH
#if SMCP_EMBEDDED
#define SMCP_MAX_URI_LENGTH (7 + 47 + (SMCP_MAX_PATH_LENGTH) )
#else
#define SMCP_MAX_URI_LENGTH (1024)
#endif
#endif

#if !defined(SMCP_MAX_PACKET_LENGTH) && !defined(SMCP_MAX_CONTENT_LENGTH)
#if SMCP_USE_UIP
#define SMCP_MAX_PACKET_LENGTH ((UIP_BUFSIZE - UIP_LLH_LEN - UIP_IPUDPH_LEN))
#else
#define SMCP_MAX_CONTENT_LENGTH     (1024)
#endif
#endif

#if defined(SMCP_MAX_PACKET_LENGTH) && !defined(SMCP_MAX_CONTENT_LENGTH)
#define SMCP_MAX_CONTENT_LENGTH     (SMCP_MAX_PACKET_LENGTH-128)
#endif

#if !defined(SMCP_MAX_PACKET_LENGTH) && defined(SMCP_MAX_CONTENT_LENGTH)
#define SMCP_MAX_PACKET_LENGTH      ((size_t)SMCP_MAX_CONTENT_LENGTH+128)
#endif

#ifndef SMCP_USE_CASCADE_COUNT
#define SMCP_USE_CASCADE_COUNT      (0)
#endif

#ifndef SMCP_MAX_CASCADE_COUNT
#define SMCP_MAX_CASCADE_COUNT      (128)
#endif

#ifndef SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
#if DEBUG
#define SMCP_ADD_NEWLINES_TO_LIST_OUTPUT	(1)
#else
#define SMCP_ADD_NEWLINES_TO_LIST_OUTPUT	(0)
#endif
#endif

#ifndef SMCP_AVOID_PRINTF
#define SMCP_AVOID_PRINTF	SMCP_EMBEDDED
#endif

//!	@define SMCP_AVOID_MALLOC
/*!	If set, static global pools are used instead of malloc/free,
**	where possible. Not fully implemented yet.
*/
#ifndef SMCP_AVOID_MALLOC
#define SMCP_AVOID_MALLOC	SMCP_EMBEDDED
#endif

#ifndef SMCP_CONF_USE_DNS
#define SMCP_CONF_USE_DNS						1
#endif

//!	Only relevant when SMCP_AVOID_MALLOC is set.
#ifndef SMCP_CONF_MAX_TRANSACTIONS
#define SMCP_CONF_MAX_TRANSACTIONS				4
#endif

//!	Only relevant when SMCP_AVOID_MALLOC is set.
#ifndef SMCP_CONF_MAX_ALLOCED_NODES
#define SMCP_CONF_MAX_ALLOCED_NODES				4
#endif

#ifndef SMCP_CONF_MAX_TIMEOUT
#define SMCP_CONF_MAX_TIMEOUT					30
#endif

#ifndef SMCP_CONF_DUPE_BUFFER_SIZE
#define SMCP_CONF_DUPE_BUFFER_SIZE				(16)
#endif

#ifndef SMCP_CONF_ENABLE_VHOSTS
#define SMCP_CONF_ENABLE_VHOSTS					!SMCP_EMBEDDED
#endif

#ifndef SMCP_MAX_VHOSTS
#define SMCP_MAX_VHOSTS							3
#endif

#ifndef SMCP_CONF_TRANS_ENABLE_BLOCK2
#define SMCP_CONF_TRANS_ENABLE_BLOCK2			!SMCP_EMBEDDED
#endif

#ifndef SMCP_CONF_TRANS_ENABLE_OBSERVING
#define SMCP_CONF_TRANS_ENABLE_OBSERVING		!SMCP_EMBEDDED
#endif

#ifndef SMCP_TRANSACTIONS_USE_BTREE
#define SMCP_TRANSACTIONS_USE_BTREE				!SMCP_EMBEDDED
#endif

#ifndef SMCP_NODE_ROUTER_USE_BTREE
#define SMCP_NODE_ROUTER_USE_BTREE				!SMCP_EMBEDDED
#endif

/*****************************************************************************/
#pragma mark - Debugging

#ifdef SMCP_CONF_DEBUG_INBOUND_DROP_PERCENT
#define SMCP_DEBUG_INBOUND_DROP_PERCENT	(SMCP_CONF_DEBUG_INBOUND_DROP_PERCENT)
#endif

#ifdef SMCP_CONF_DEBUG_OUTBOUND_DROP_PERCENT
#define SMCP_DEBUG_OUTBOUND_DROP_PERCENT (SMCP_CONF_DEBUG_OUTBOUND_DROP_PERCENT)
#endif

/*****************************************************************************/
#pragma mark - Observation Options

#ifdef SMCP_CONF_MAX_OBSERVERS
#define SMCP_MAX_OBSERVERS			(SMCP_CONF_MAX_OBSERVERS)
#else
#if SMCP_EMBEDDED
#define SMCP_MAX_OBSERVERS			(2)
#else
#define SMCP_MAX_OBSERVERS			(8)
#endif
#endif

#ifndef SMCP_OBSERVATION_KEEPALIVE_INTERVAL
#define SMCP_OBSERVATION_KEEPALIVE_INTERVAL		(45*MSEC_PER_SEC)
#endif

#ifndef SMCP_OBSERVATION_DEFAULT_MAX_AGE
#define SMCP_OBSERVATION_DEFAULT_MAX_AGE		(30*MSEC_PER_SEC)
#endif

#ifndef SMCP_OBSERVER_CON_EVENT_EXPIRATION
#define SMCP_OBSERVER_CON_EVENT_EXPIRATION		(30*MSEC_PER_SEC)
#endif

#ifndef SMCP_OBSERVER_NON_EVENT_EXPIRATION
#define SMCP_OBSERVER_NON_EVENT_EXPIRATION		(1*MSEC_PER_SEC)
#endif

/*****************************************************************************/
#pragma mark - Extras

#ifndef SMCP_CONF_NODE_ROUTER
#define SMCP_CONF_NODE_ROUTER		!SMCP_EMBEDDED
#endif

#ifndef SMCP_VARIABLE_MAX_VALUE_LENGTH
#define SMCP_VARIABLE_MAX_VALUE_LENGTH		(127)
#endif

#ifndef SMCP_VARIABLE_MAX_KEY_LENGTH
#define SMCP_VARIABLE_MAX_KEY_LENGTH		(23)
#endif

#ifndef SMCP_DTLS
#define SMCP_DTLS							(1)
#endif

#ifndef SMCP_USE_EXPERIMENTAL_DIGEST_AUTH
#define SMCP_USE_EXPERIMENTAL_DIGEST_AUTH	(1)
#endif

/*****************************************************************************/
#pragma mark - SMCP Compiler Stuff

#if SMCP_EMBEDDED
#define SMCP_NON_RECURSIVE	static
#else
#define SMCP_NON_RECURSIVE
#endif

#ifndef SMCP_DEPRECATED
#if defined(__GNUC__) || defined(__clang__)
#define SMCP_DEPRECATED __attribute__ ((deprecated))
#else
#define SMCP_DEPRECATED
#endif
#endif

#endif
