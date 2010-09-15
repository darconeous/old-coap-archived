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
#endif

#include "smcp_pairing.h"
#include "smcp_node.h"

#include "smcp_helpers.h"

#pragma mark -
#pragma mark Macros


#pragma mark -
#pragma mark Paring

smcp_status_t
smcp_node_pair_with_uri(
	smcp_node_t node, const char* uri, int flags
) {
	smcp_status_t ret = 0;
	const char* path_str = NULL;
	const char* addr_str = NULL;
	const char* addr_end;
	size_t addr_str_len;
	char addr_cstr[256] = "";

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
	bool is_ipv6_or_hostname = false;

	require_action_string(node,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT,
		"NULL node parameter");
	require_action_string(uri,
		bail,
		ret = SMCP_STATUS_INVALID_ARGUMENT,
		"NULL uri parameter");
	require_action(strncmp(uri,
			"smcp://",
			7) == 0, bail, ret = SMCP_STATUS_UNSUPPORTED_URI);

	// Parse the URI.

	// Find the start of the path
	for(path_str = uri + 7; *path_str && (*path_str != '/'); path_str++) {
	}

	// Find the end of the address part.
	for(addr_end = path_str;; addr_end--) {
		if((addr_end < uri + 7) || (*addr_end == '@')) {
			// There was no port, just an address.
			addr_str = addr_end + 1;
			addr_end = path_str;
			break;
		}
		if((*addr_end == ']')) {
			for(addr_str = addr_end;
			        (addr_str > (uri + 7)) && (addr_str[-1] != '[');
			    addr_str--) {
			}
			is_ipv6_or_hostname = true;
			break;
		}
		if((*addr_end == ':')) {
#if SMCP_USE_BSD_SOCKETS
			saddr.sin6_port = htons(strtol(addr_end + 1, NULL, 10));
#elif __CONTIKI__
			toport = strtol(addr_end + 1, NULL, 10);
#else
#error TODO: Implement me!
#endif

			for(addr_str = addr_end;
			        (addr_str > (uri + 7)) && (addr_str[-1] != '@');
			    addr_str--) {
			}

			break;
		}
	}

	if(addr_end[-1] == ']') {
		addr_end--;
		addr_str++;
		is_ipv6_or_hostname = true;
	} else if(!isnumber(addr_str[0])) {
		is_ipv6_or_hostname = true;
	}

	addr_str_len = addr_end - addr_str;

	if(is_ipv6_or_hostname) {
		memcpy(addr_cstr, addr_str, MIN(addr_str_len, sizeof(addr_cstr)));
	} else {
		memcpy(addr_cstr, IPv4_COMPATIBLE_IPv6_PREFIX, 7);
		memcpy(addr_cstr + 7, addr_str,
			MIN(addr_str_len, sizeof(addr_cstr) - 7));
	}

	DEBUG_PRINTF(
		CSTR("URI Parse: ADDR: %s   PORT: %d   PATH: %s"),
		addr_cstr,
#if SMCP_USE_BSD_SOCKETS
		ntohs(saddr.sin6_port),
#elif __CONTIKI__
		toport,
#else
#error TODO: Implement me!
#endif
		path_str
	);

#if SMCP_USE_BSD_SOCKETS
	{
		struct hostent *tmp = gethostbyname2(addr_cstr, AF_INET6);
		require_action(!h_errno && tmp, bail, ret = -1);
		require_action(tmp->h_length > 1, bail, ret = -1);
		memcpy(&saddr.sin6_addr.s6_addr, tmp->h_addr_list[0], 16);
	}
#elif __CONTIKI__
	// TODO: We should be doing domain name resolution here too!
	require_action(uiplib_ipaddrconv(addr_cstr,
			&toaddr) != 0, bail, ret = -1);
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
smcp_node_get_first_pairing_for_node(smcp_node_t node) {
	smcp_pairing_t ret = NULL;

	require_string(node, bail, "NULL node argument");

	switch(node->type) {
	case SMCP_NODE_EVENT:
	case SMCP_NODE_ACTION:
		ret = ((smcp_event_node_t)node)->pairings;
		break;
	}
bail:
	return ret;
}

smcp_pairing_t
smcp_daemon_get_first_pairing_for_path(
	smcp_daemon_t self, const char* path
) {
	smcp_pairing_t ret = NULL;
	smcp_node_t node =
	    smcp_node_find_with_path(smcp_daemon_get_root_node(self), path);

	ret = smcp_node_get_first_pairing_for_node(node);

	if(!ret)
		DEBUG_PRINTF(CSTR(
				"Unable to find pairings for node path %s (node=%p)"),
			path, node);

bail:
	return ret;
}
