/*
 *  smcp_pairing.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 8/31/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert_macros.h"

#include "smcp.h"
#include "smcp_logging.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include "ll.h"

#if SMCP_USE_BSD_SOCKETS
#include <netdb.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#elif __CONTIKI__
#include "resolv.h"
#endif

#include "smcp_pairing.h"
#include "smcp_node.h"

#include "smcp_helpers.h"
#include "url-helpers.h"

#pragma mark -
#pragma mark Macros


#pragma mark -
#pragma mark Paring

smcp_status_t
smcp_daemon_pair_with_uri(
	smcp_daemon_t self, const char* path, const char* uri, int flags
) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;

	smcp_node_t node =
	    smcp_node_find_with_path(smcp_daemon_get_root_node(self), path);

	require(node, bail);

	ret = smcp_node_pair_with_uri(
		node,
		uri,
		flags
	    );

bail:
	return ret;
}

smcp_status_t
smcp_node_pair_with_uri(
	smcp_node_t node, const char* uri_, int flags
) {
	smcp_status_t ret = 0;
	char uri[uri_ ? strlen(uri_) : 0 + 1];        // Requires compiler support for variable sized arrays
	char* proto_str = NULL;
	char* path_str = NULL;
	char* addr_str = NULL;
	char* port_str = NULL;

#if SMCP_USE_BSD_SOCKETS
	struct sockaddr_in6 saddr = {
		.sin6_family	= AF_INET6,
#if SOCKADDR_HAS_LENGTH_FIELD
		.sin6_len		= sizeof(struct sockaddr_in6),
#endif
		.sin6_port		= htons(SMCP_DEFAULT_PORT),
	};
#elif __CONTIKI__
	uip_ipaddr_t toaddr;
	uint16_t toport = SMCP_DEFAULT_PORT;
#endif

	require_action_string(node,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT,
		"NULL node parameter");
	require_action_string(uri_,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT,
		"NULL uri parameter");

	strcpy(uri, uri_);
	require_action_string(
		url_parse(uri, &proto_str, &addr_str, &port_str, &path_str),
		bail,
		ret = SMCP_STATUS_UNSUPPORTED_URI,
		"Unable to parse URL"
	);

	require_action((strcmp(proto_str,
				"smcp") == 0) || (strcmp(proto_str,
				"coap") == 0), bail, ret = SMCP_STATUS_UNSUPPORTED_URI);

	if(port_str) {
#if SMCP_USE_BSD_SOCKETS
		saddr.sin6_port = htons(strtol(port_str, NULL, 10));
#elif __CONTIKI__
		toport = strtol(port_str, NULL, 10);
#else
#error TODO: Implement me!
#endif
#if SMCP_USE_BSD_SOCKETS
	} else {
		port_str = SMCP_DEFAULT_PORT_CSTR;
#endif
	}

	DEBUG_PRINTF(
		CSTR("URI Parse: \"%s\" -> host=\"%s\" port=\"%s\" path=\"%s\""),
		uri_,
		addr_str,
		port_str,
		path_str
	);

#if SMCP_USE_BSD_SOCKETS
	{
		struct addrinfo hint = {
			.ai_flags		= AI_ALL | AI_V4MAPPED,
			.ai_family		= AF_INET6,
			.ai_socktype	= SOCK_DGRAM,
			.ai_protocol	= IPPROTO_UDP,
		};
		struct addrinfo *results = NULL;
		int error = getaddrinfo(addr_str, port_str, &hint, &results);

		if(error && (inet_addr(addr_str) != INADDR_NONE)) {
			char addr_v4mapped_str[8 + strlen(addr_str)];
			sprintf(addr_v4mapped_str, "::ffff:%s", addr_str);
			error = getaddrinfo(addr_v4mapped_str,
				port_str,
				&hint,
				&results);
		}

		require_action_string(!error,
			bail,
			ret = SMCP_STATUS_FAILURE,
			gai_strerror(error));
		require_action(results, bail, ret = SMCP_STATUS_FAILURE);

		memcpy(&saddr, results->ai_addr, results->ai_addrlen);
	}
#elif __CONTIKI__
	ret = uiplib_ipaddrconv(addr_str, &toaddr);
	if(ret) {
		uip_ipaddr_t *temp = resolv_lookup(addr_str);
		if(temp) {
			memcpy(&toaddr, temp, sizeof(uip_ipaddr_t));
			ret = 0;
		} else {
			resolv_query(addr_str);
			// TODO: We should be doing domain name resolution here too!
		}
	}
	require_action_string(ret == SMCP_STATUS_OK,
		bail,
		ret = SMCP_STATUS_FAILURE,
		"Unable to resolve hostname");
#else
#error TODO: Implement me!
#endif

	// Pair with sockaddr.
#if SMCP_USE_BSD_SOCKETS
	ret = smcp_node_pair_with_sockaddr(node,
		    (struct sockaddr*)&saddr,
		sizeof(saddr),
		path_str,
		flags);
#elif __CONTIKI__
	ret = smcp_node_pair_with_sockaddr(node,
		&toaddr,
		toport,
		path_str,
		flags);
#endif
bail:
	return ret;
}

smcp_status_t
smcp_node_pair_with_sockaddr(
	smcp_node_t node, SMCP_SOCKET_ARGS, const char* path, int flags
) {
	smcp_status_t ret = 0;
	smcp_pairing_t pairing = NULL;

	require_action(node, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action((node->type == SMCP_NODE_EVENT) ||
		    (node->type == SMCP_NODE_ACTION),
		bail,
		ret = SMCP_STATUS_BAD_NODE_TYPE);
	require_action(path, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
#if SMCP_USE_BSD_SOCKETS
	require_action(saddr, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
	require_action(socklen > 0, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
#elif __CONTIKI__
	require_action(toaddr, bail, ret = SMCP_STATUS_INVALID_ARGUMENT);
#endif

	pairing = calloc(1, sizeof(*pairing));

	require(pairing, bail);

#if SMCP_USE_BSD_SOCKETS
	memcpy(&pairing->saddr, saddr, socklen);
#elif __CONTIKI__
	pairing->addr = *toaddr;
	pairing->port = toport;
#endif

	if(node->type == SMCP_NODE_EVENT)
		pairing->seq = pairing->ack = SMCP_FUNC_RANDOM_UINT32();

	pairing->path = strdup(path);
	pairing->flags = flags;

	ll_prepend((void**)&((smcp_event_node_t)node)->pairings, pairing);

bail:
	return ret;
}

smcp_pairing_t
smcp_node_get_first_pairing(smcp_node_t node) {
	smcp_pairing_t ret = NULL;

	require_string(node, bail, "NULL node argument");

#if SMCP_PAIRINGS_ARE_IN_NODES
	switch(node->type) {
	case SMCP_NODE_EVENT:
	case SMCP_NODE_ACTION:
		ret = ((smcp_event_node_t)node)->pairings;
		break;
	}
#endif

bail:
	return ret;
}

#if !SMCP_PAIRINGS_ARE_IN_NODES
static bt_compare_result_t
smcp_pairing_compare(
	smcp_pairing_t lhs, smcp_pairing_t rhs
) {
	if(lhs->path == rhs->path)
		return 0;
	if(!lhs->path)
		return 1;
	if(!rhs->path)
		return -1;
	return strcmp(lhs->path, rhs->path);
}

static bt_compare_result_t
smcp_pairing_compare_cstr(
	smcp_pairing_t lhs, const char* rhs
) {
	if(lhs->path == rhs)
		return 0;
	if(!lhs->path)
		return 1;
	if(!rhs)
		return -1;
	return strcmp(lhs->path, rhs);
}
#endif

smcp_pairing_t
smcp_daemon_get_first_pairing_for_path(
	smcp_daemon_t self, const char* path
) {
	smcp_pairing_t ret = NULL;

#if SMCP_PAIRINGS_ARE_IN_NODES
	smcp_node_t node =
	    smcp_node_find_with_path(smcp_daemon_get_root_node(self), path);

	ret = smcp_node_get_first_pairing(node);
#else
#endif

bail:
	if(!ret)
		DEBUG_PRINTF(CSTR(
				"Unable to find pairings for node path %s (node=%p)"),
			path, node);
	return ret;
}

smcp_pairing_t
smcp_daemon_next_pairing(
	smcp_daemon_t self, smcp_pairing_t pairing
) {
	smcp_pairing_t ret = NULL;

	require(pairing != NULL, bail);

	ret = pairing->next;

bail:
	return ret;
}
