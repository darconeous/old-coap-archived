/*!	@file smcp-defaults.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief SMCP Default Build Options
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

#ifndef __SMCP_DEFAULTS_H__
#define __SMCP_DEFAULTS_H__

/*****************************************************************************/
// MARK: - SMCP Build Parameters

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef SMCP_EMBEDDED
#if CONTIKI || SMCP_USE_UIP
#define SMCP_EMBEDDED			(1)
#else
#define SMCP_EMBEDDED			(0)
#endif
#endif

#ifndef SMCP_THREAD_SAFE
#define SMCP_THREAD_SAFE		!SMCP_EMBEDDED
#endif

#ifndef SMCP_USE_BSD_SOCKETS
#define SMCP_USE_BSD_SOCKETS    !SMCP_EMBEDDED
#endif

#ifndef SMCP_USE_UIP
#define SMCP_USE_UIP			!SMCP_USE_BSD_SOCKETS
#endif

#ifndef SMCP_DEFAULT_PORT
#define SMCP_DEFAULT_PORT           COAP_DEFAULT_PORT
#endif

#define SMCP_DEFAULT_PORT_CSTR      #SMCP_DEFAULT_PORT

#ifndef SMCP_MAX_PATH_LENGTH
#define SMCP_MAX_PATH_LENGTH        (127)
#endif

//!	@define SMCP_MAX_URI_LENGTH
/*!
**	This is calclated as the sum of the following:
**
**	 * `strlen("coap://")`
**	 * `strlen("[0000:0000:0000:0000:0000:0000:0000:0000]:65535")`
**	 * `SMCP_MAX_PATH_LENGTH`
*/
#ifndef SMCP_MAX_URI_LENGTH
#if SMCP_EMBEDDED
#define SMCP_MAX_URI_LENGTH (7 + 47 + (SMCP_MAX_PATH_LENGTH) )
#else
#define SMCP_MAX_URI_LENGTH (1024)
#endif
#endif

//!	@define SMCP_MAX_PACKET_LENGTH
/*! Maximum supported CoAP packet length.
*/
#if !defined(SMCP_MAX_PACKET_LENGTH) && !defined(SMCP_MAX_CONTENT_LENGTH)
#if SMCP_USE_UIP
#define SMCP_MAX_PACKET_LENGTH ((UIP_BUFSIZE - UIP_LLH_LEN - UIP_IPUDPH_LEN))
#else
#define SMCP_MAX_CONTENT_LENGTH     (1024)
#endif
#endif

//!	@define SMCP_MAX_CONTENT_LENGTH
/*!	The maximum number of *content* bytes allowed in an outgoing packet. */
#if defined(SMCP_MAX_PACKET_LENGTH) && !defined(SMCP_MAX_CONTENT_LENGTH)
#define SMCP_MAX_CONTENT_LENGTH     (SMCP_MAX_PACKET_LENGTH-8)
#endif

//!	@define SMCP_MAX_PACKET_LENGTH
/*!	The maximum *total* number of bytes allowed in an outgoing packet. */
#if !defined(SMCP_MAX_PACKET_LENGTH) && defined(SMCP_MAX_CONTENT_LENGTH)
#define SMCP_MAX_PACKET_LENGTH      ((coap_size_t)SMCP_MAX_CONTENT_LENGTH+8)
#endif

//!	@define SMCP_AVOID_PRINTF
/*!	If set, use of printf() (or any of its variants) is avoided.
*/
#ifndef SMCP_AVOID_PRINTF
#define SMCP_AVOID_PRINTF	SMCP_EMBEDDED
#endif

//!	@define SMCP_AVOID_MALLOC
/*!	Prevents SMCP from calling malloc.
**
**	If set, static global pools are used instead of malloc/free,
**	where possible. Also applies to functions that use malloc/free,
**	like strdup().
*/
#ifndef SMCP_AVOID_MALLOC
#define SMCP_AVOID_MALLOC	SMCP_EMBEDDED
#endif

//!	@define SMCP_CONF_USE_DNS
/*!	Determines if SMCP can lookup domain names.
*/
#ifndef SMCP_CONF_USE_DNS
#define SMCP_CONF_USE_DNS						1
#endif

//!	@define SMCP_TRANSACTION_POOL_SIZE
/*!	Maximum number of general-purpose active transactions
**
**	NOTE: Only relevant when SMCP_AVOID_MALLOC is set.
**
**	You can have more than this value if you statically
**	allocate the transactions. Dynamic allocation is
**	disabled if this value is set to zero and SMCP_AVOID_MALLOC
**	is set.
**
*/
#ifndef SMCP_TRANSACTION_POOL_SIZE
#define SMCP_TRANSACTION_POOL_SIZE				2
#endif

//!	@define SMCP_CONF_MAX_TIMEOUT
/*! The maximum timeout (in seconds) returned form `smcp_get_timeout()`
*/
#ifndef SMCP_CONF_MAX_TIMEOUT
#define SMCP_CONF_MAX_TIMEOUT					3600
#endif

//! @define SMCP_CONF_DUPE_BUFFER_SIZE
/*! Number of previous packets to keep track of for duplicate detection.
*/
#ifndef SMCP_CONF_DUPE_BUFFER_SIZE
#if SMCP_EMBEDDED
#define SMCP_CONF_DUPE_BUFFER_SIZE				16
#else
#define SMCP_CONF_DUPE_BUFFER_SIZE				64
#endif
#endif

//! @define SMCP_CONF_ENABLE_VHOSTS
/*! Determines of virtual host support is included.
*/
#ifndef SMCP_CONF_ENABLE_VHOSTS
#define SMCP_CONF_ENABLE_VHOSTS					!SMCP_EMBEDDED
#endif

//! @define SMCP_MAX_VHOSTS
/*! The maximum number of supported vhosts.
*/
#ifndef SMCP_MAX_VHOSTS
#if SMCP_EMBEDDED
#define SMCP_MAX_VHOSTS							3
#else
#define SMCP_MAX_VHOSTS							16
#endif
#endif

#ifndef SMCP_CONF_TRANS_ENABLE_BLOCK2
#define SMCP_CONF_TRANS_ENABLE_BLOCK2			!SMCP_EMBEDDED
#endif

#ifndef SMCP_CONF_TRANS_ENABLE_OBSERVING
#define SMCP_CONF_TRANS_ENABLE_OBSERVING		!SMCP_EMBEDDED
#endif

//! @define SMCP_TRANSACTIONS_USE_BTREE
/*! Determines if transactions should be stored in a linked list
**	or a binary tree. Binary tree is faster when there are lots
**	of transactions, but linked lists are smaller and faster when
**	there are few or infrequent transactions.
*/
#ifndef SMCP_TRANSACTIONS_USE_BTREE
#define SMCP_TRANSACTIONS_USE_BTREE				!SMCP_EMBEDDED
#endif

//! @define SMCP_TRANSACTION_BURST_COUNT
/*!	Number of retransmit attempts during a burst. */
#ifndef SMCP_TRANSACTION_BURST_COUNT
#define SMCP_TRANSACTION_BURST_COUNT 3
#endif

//! @define SMCP_TRANSACTION_BURST_TIMEOUT_MAX
/*!	Maximum time (in milliseconds) between burst packet
**	retransmits when using the burst retransmit strategy. */
#ifndef SMCP_TRANSACTION_BURST_TIMEOUT_MAX
#define SMCP_TRANSACTION_BURST_TIMEOUT_MAX 50
#endif

//! @define SMCP_TRANSACTION_BURST_TIMEOUT_MIN
/*!	Minimum time (in milliseconds) between burst packet
**	retransmits when using the burst retransmit strategy. */
#ifndef SMCP_TRANSACTION_BURST_TIMEOUT_MIN
#define SMCP_TRANSACTION_BURST_TIMEOUT_MIN 20
#endif

#ifndef SMCP_ASYNC_RESPONSE_MAX_LENGTH
#if SMCP_EMBEDDED
#define SMCP_ASYNC_RESPONSE_MAX_LENGTH		80
#else
#define SMCP_ASYNC_RESPONSE_MAX_LENGTH		SMCP_MAX_PACKET_LENGTH
#endif
#endif

/*****************************************************************************/
// MARK: - Debugging

#ifdef SMCP_CONF_DEBUG_INBOUND_DROP_PERCENT
#define SMCP_DEBUG_INBOUND_DROP_PERCENT	(SMCP_CONF_DEBUG_INBOUND_DROP_PERCENT)
#endif

#ifdef SMCP_CONF_DEBUG_OUTBOUND_DROP_PERCENT
#define SMCP_DEBUG_OUTBOUND_DROP_PERCENT (SMCP_CONF_DEBUG_OUTBOUND_DROP_PERCENT)
#endif

/*****************************************************************************/
// MARK: - Observation Options

#ifdef SMCP_CONF_MAX_OBSERVERS
#define SMCP_MAX_OBSERVERS			(SMCP_CONF_MAX_OBSERVERS)
#else
#if SMCP_EMBEDDED
#define SMCP_MAX_OBSERVERS			(2)
#else
#define SMCP_MAX_OBSERVERS			(64)
#endif
#endif

#ifndef SMCP_OBSERVATION_KEEPALIVE_INTERVAL
#define SMCP_OBSERVATION_KEEPALIVE_INTERVAL		(45*MSEC_PER_SEC)
#endif

#ifndef SMCP_OBSERVATION_DEFAULT_MAX_AGE
#define SMCP_OBSERVATION_DEFAULT_MAX_AGE		(30*MSEC_PER_SEC)
#endif

#ifndef SMCP_OBSERVER_CON_EVENT_EXPIRATION
#define SMCP_OBSERVER_CON_EVENT_EXPIRATION		(10*MSEC_PER_SEC)
#endif

#ifndef SMCP_OBSERVER_NON_EVENT_EXPIRATION
#define SMCP_OBSERVER_NON_EVENT_EXPIRATION		(1*MSEC_PER_SEC)
#endif

/*****************************************************************************/
// MARK: - Extras

#ifndef SMCP_CONF_NODE_ROUTER
#define SMCP_CONF_NODE_ROUTER		!SMCP_EMBEDDED
#endif

#ifndef SMCP_CONF_MAX_PAIRINGS
#if SMCP_EMBEDDED
#define SMCP_CONF_MAX_PAIRINGS				2
#else
#define SMCP_CONF_MAX_PAIRINGS				16
#endif
#endif

#ifndef SMCP_CONF_MAX_GROUPS
#if SMCP_EMBEDDED
#define SMCP_CONF_MAX_GROUPS				2
#else
#define SMCP_CONF_MAX_GROUPS				16
#endif
#endif

#ifndef SMCP_NODE_ROUTER_USE_BTREE
#define SMCP_NODE_ROUTER_USE_BTREE				SMCP_TRANSACTIONS_USE_BTREE
#endif

//!	@define SMCP_CONF_MAX_ALLOCED_NODES
/*!	Node Router: Maximum number of allocated nodes
**
**	Only relevant when SMCP_AVOID_MALLOC is set.
*/
#ifndef SMCP_CONF_MAX_ALLOCED_NODES
#define SMCP_CONF_MAX_ALLOCED_NODES				0
#endif

//!	@define SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
/*!	If set, newlines are added to list output when using the node router.
**
**	@sa SMCP_CONF_NODE_ROUTER
*/
#ifndef SMCP_ADD_NEWLINES_TO_LIST_OUTPUT
#if DEBUG
#define SMCP_ADD_NEWLINES_TO_LIST_OUTPUT	(1)
#else
#define SMCP_ADD_NEWLINES_TO_LIST_OUTPUT	(0)
#endif
#endif

#ifndef SMCP_VARIABLE_MAX_VALUE_LENGTH
#define SMCP_VARIABLE_MAX_VALUE_LENGTH		(127)
#endif

#ifndef SMCP_VARIABLE_MAX_KEY_LENGTH
#define SMCP_VARIABLE_MAX_KEY_LENGTH		(23)
#endif

#ifndef SMCP_DTLS
#define SMCP_DTLS							0
#endif

/*****************************************************************************/
// MARK: - Experimental Options

//!	@define SMCP_USE_CASCADE_COUNT
/*!	If set, add experiental support an event cascade counter.
**	This is used to prevent storms of events if a device is misconfigured.
*/
#ifndef SMCP_USE_CASCADE_COUNT
#define SMCP_USE_CASCADE_COUNT      (0)
#endif

//!	@define SMCP_MAX_CASCADE_COUNT
/*!	The initial value of the cascade count option.
*/
#ifndef SMCP_MAX_CASCADE_COUNT
#define SMCP_MAX_CASCADE_COUNT      (128)
#endif

/*****************************************************************************/
// MARK: - SMCP Compiler Stuff

#if SMCP_EMBEDDED
#define SMCP_NON_RECURSIVE	static
#else
#define SMCP_NON_RECURSIVE
#endif

#ifndef SMCP_API_EXTERN
#define SMCP_API_EXTERN		extern
#endif

#ifndef SMCP_INTERNAL_EXTERN
#define SMCP_INTERNAL_EXTERN		extern
#endif

#ifndef SMCP_DEPRECATED
#if defined(__GNUC__) || defined(__clang__)
#define SMCP_DEPRECATED __attribute__ ((deprecated))
#else
#define SMCP_DEPRECATED
#endif
#endif

#endif
