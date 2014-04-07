//
//  smcp-plat-bsd.c
//  SMCP
//
//  Created by Robert Quattlebaum on 2/12/14.
//  Copyright (c) 2014 deepdarc. All rights reserved.
//

#if HAVE_CONFIG_H
#include <config.h>
#endif

#define __APPLE_USE_RFC_3542 1

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert-macros.h"

#include "smcp.h"
#include "smcp-internal.h"
#include "smcp-logging.h"
#include "smcp-auth.h"

#include <stdio.h>

#if SMCP_USE_BSD_SOCKETS

#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>

smcp_status_t
smcp_outbound_send_hook() {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();
	coap_size_t header_len;

	header_len = (smcp_outbound_get_content_ptr(NULL)-(char*)self->outbound.packet);

	// Remove the start-of-payload marker if we have no payload.
	if(!smcp_get_current_instance()->outbound.content_len)
		header_len--;

#if VERBOSE_DEBUG
	{
		static const char prefix[] = "Outbound:\t";
		char from_addr_str[50] = "???";
		char addr_str[50] = "???";
		uint16_t port = 0;
		inet_ntop(AF_INET6,&smcp_get_current_instance()->outbound.saddr.sin6_addr,addr_str,sizeof(addr_str)-1);
		inet_ntop(AF_INET6,&smcp_get_current_instance()->inbound.pktinfo.ipi6_addr,from_addr_str,sizeof(addr_str)-1);
		port = ntohs(smcp_get_current_instance()->outbound.saddr.sin6_port);

		DEBUG_PRINTF("%sTO -> [%s]:%d",prefix,addr_str,(int)port);
		DEBUG_PRINTF("%sFROM -> [%s]",prefix,from_addr_str);
		coap_dump_header(
			SMCP_DEBUG_OUT_FILE,
			prefix,
			self->outbound.packet,
			header_len+smcp_get_current_instance()->outbound.content_len
		);
	}
#endif

	require_string(smcp_get_current_instance()->outbound.socklen,bail,"Destaddr not set");

	ssize_t sent_bytes;

	if(self->is_processing_message)
	{
		struct iovec iov = {
			self->outbound.packet_bytes,
			header_len + self->outbound.content_len
		};
		uint8_t cmbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
		struct cmsghdr *scmsgp;
		struct in6_pktinfo *pktinfo;
		struct msghdr msg = {
			.msg_name = &self->outbound.saddr,
			.msg_namelen = self->outbound.socklen,
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmbuf,
			.msg_controllen = sizeof(cmbuf),
		};
		scmsgp = CMSG_FIRSTHDR(&msg);
		scmsgp->cmsg_level = IPPROTO_IPV6;
		scmsgp->cmsg_type = IPV6_PKTINFO;
		scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		pktinfo = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));
		*pktinfo = self->inbound.pktinfo;
		sent_bytes = sendmsg(self->fd, &msg, 0);
		memset(pktinfo,0,sizeof(*pktinfo));
	} else {
		sent_bytes = sendto(
			self->fd,
			self->outbound.packet_bytes,
			header_len +
			self->outbound.content_len,
			0,
			(struct sockaddr *)&self->outbound.saddr,
			self->outbound.socklen
		);
	}

	require_action_string(
		(sent_bytes>=0),
		bail, ret = SMCP_STATUS_ERRNO, strerror(errno)
	);

	require_action_string(
		sent_bytes,
		bail, ret = SMCP_STATUS_FAILURE, "sendto() returned zero."
	);

	ret = SMCP_STATUS_OK;
bail:
	return ret;
}

smcp_status_t
smcp_outbound_send_secure_hook() {
	smcp_status_t ret = SMCP_STATUS_FAILURE;

	// DTLS support not yet implemeted.
	ret = SMCP_STATUS_NOT_IMPLEMENTED;

bail:
	return ret;
}

#endif // #if SMCP_USE_BSD_SOCKETS
