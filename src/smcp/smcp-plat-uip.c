/*	@file smcp-plat-uip.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

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

#if CONTIKI
#include "contiki.h"
#include "net/ip/tcpip.h"
#include "net/ip/resolv.h"
#endif

#include <stdio.h>

#if SMCP_USE_UIP
#include "net/ip/uip-udp-packet.h"
#include "net/ip/uiplib.h"
extern uint16_t uip_slen;
extern void *uip_sappdata;

#define UIP_IP_BUF                          ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if UIP_CONF_IPV6
#define UIP_UDP_BUF                        ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#else
#define UIP_UDP_BUF                        ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#endif

smcp_status_t
smcp_plat_join_standard_groups(smcp_t self, int interface)
{
	SMCP_EMBEDDED_SELF_HOOK;
	// TODO: Implement me!
	return SMCP_STATUS_NOT_IMPLEMENTED;
}

smcp_t
smcp_plat_init(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

#if UIP_CONF_IPV6
	{
		uip_ipaddr_t all_coap_nodes_addr;
		if(uiplib_ipaddrconv(
			COAP_MULTICAST_IP6_LL_ALLDEVICES,
			&all_coap_nodes_addr
		)) {
			uip_ds6_maddr_add(&all_coap_nodes_addr);
		}
	}
#endif

	return self;
}

smcp_status_t
smcp_plat_bind_to_port(
	smcp_t self,
	smcp_session_type_t type,
	uint16_t port
) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_status_t ret = SMCP_STATUS_FAILURE;

	switch(type) {
	case SMCP_SESSION_TYPE_UDP:
#if SMCP_DTLS
	case SMCP_SESSION_TYPE_DTLS:
#endif
#if SMCP_TCP
	case SMCP_SESSION_TYPE_TCP:
#endif
#if SMCP_TLS
	case SMCP_SESSION_TYPE_TLS:
#endif
		break;

	default:
		ret = SMCP_STATUS_NOT_IMPLEMENTED;
		// Unsupported session type.
		goto bail;
	}

	// Set up the UDP port for listening.
	self->plat.udp_conn = udp_new(NULL, 0, NULL);
	uip_udp_bind(self->plat.udp_conn, htons(port));
	self->plat.udp_conn->rport = 0;

	ret = SMCP_STATUS_OK;

bail:
	return ret;
}

void
smcp_plat_finalize(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

	if(self->plat.udp_conn) {
		uip_udp_remove(self->plat.udp_conn);
	}
}

smcp_status_t
smcp_plat_set_remote_hostname_and_port(const char* hostname, uint16_t port)
{
	smcp_status_t ret;
	SMCP_NON_RECURSIVE smcp_sockaddr_t saddr;

	DEBUG_PRINTF("Outbound: Dest host [%s]:%d",hostname,port);

#if SMCP_DTLS
	smcp_plat_ssl_set_remote_hostname(hostname);
#endif

	// Check to see if this host is a group we know about.
	if (strcasecmp(hostname, COAP_MULTICAST_STR_ALLDEVICES) == 0) {
		hostname = SMCP_COAP_MULTICAST_ALLDEVICES_ADDR;
	}

	ret = smcp_plat_lookup_hostname(hostname, &saddr, SMCP_LOOKUP_HOSTNAME_FLAG_DEFAULT);
	require_noerr(ret, bail);

	saddr.smcp_port = htons(port);

	smcp_plat_set_remote_sockaddr(&saddr);

bail:
	return ret;
}


void
smcp_plat_set_remote_sockaddr(const smcp_sockaddr_t* addr)
{
	smcp_t const self = smcp_get_current_instance();

	if (addr) {
		self->plat.sockaddr_remote = *addr;
	} else {
		memset(&self->plat.sockaddr_remote,0,sizeof(self->plat.sockaddr_remote));
	}
}

void
smcp_plat_set_local_sockaddr(const smcp_sockaddr_t* addr)
{
	smcp_t const self = smcp_get_current_instance();

	if (addr) {
		self->plat.sockaddr_local = *addr;
	} else {
		memset(&self->plat.sockaddr_local,0,sizeof(self->plat.sockaddr_local));
	}
}

void
smcp_plat_set_session_type(smcp_session_type_t type)
{
	smcp_t const self = smcp_get_current_instance();

	self->plat.session_type = type;
}


const smcp_sockaddr_t*
smcp_plat_get_remote_sockaddr(void)
{
	return &smcp_get_current_instance()->plat.sockaddr_remote;
}

const smcp_sockaddr_t*
smcp_plat_get_local_sockaddr(void)
{
	return &smcp_get_current_instance()->plat.sockaddr_local;
}

smcp_session_type_t
smcp_plat_get_session_type(void)
{
	return smcp_get_current_instance()->plat.session_type;
}


struct uip_udp_conn*
smcp_plat_get_udp_conn(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	return self->plat.udp_conn;
}

uint16_t
smcp_plat_get_port(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	return ntohs(self->plat.udp_conn->lport);
}


smcp_status_t
smcp_plat_outbound_start(smcp_t self, uint8_t** data_ptr, coap_size_t *data_len)
{
	SMCP_EMBEDDED_SELF_HOOK;
	uint8_t *buffer;
	int space_remaining = UIP_BUFSIZE;

	uip_udp_conn = self->plat.udp_conn;
	buffer = (uint8_t*)uip_sappdata;

	if(buffer == (uint8_t*)self->inbound.packet) {
		// We want to preserve at least the headers from the inbound packet,
		// so we will put the outbound packet immediately after the last
		// header option of the inbound packet.
		buffer = (uint8_t*)self->inbound.content_ptr;

		// Fix the alignment for 32-bit platforms.
		buffer = (uint8_t*)((uintptr_t)((uint8_t*)self->outbound.packet+7)&~(uintptr_t)0x7);

		space_remaining -= (buffer-(uint8_t*)uip_buf);

		if (space_remaining-4<0) {
			buffer = (uint8_t*)uip_sappdata;
			space_remaining = UIP_BUFSIZE;
		}
	}

	if (data_ptr) {
		*data_ptr = buffer;
	}

	if (data_len) {
		*data_len = space_remaining;
	}

	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_plat_outbound_finish(smcp_t self,const uint8_t* data_ptr, coap_size_t data_len, int flags)
{
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_status_t ret = SMCP_STATUS_FAILURE;

	assert(uip_udp_conn == self->plat.udp_conn);

	uip_slen = data_len;

	require_action(uip_slen<SMCP_MAX_PACKET_LENGTH, bail, ret = SMCP_STATUS_MESSAGE_TOO_BIG);

	if (data_ptr != uip_sappdata) {
		memmove(
			uip_sappdata,
			data_ptr,
			uip_slen
		);
		data_ptr = (const uint8_t*)uip_sappdata;
	}

#if 0
	// TODO: For some reason this isn't working anymore. Investigate.
	if(self->is_responding) {
		// We are responding, let uIP handle preparing the packet.
	} else
#endif

	{	// Here we explicitly tickle UIP to send the packet.

		// Change the remote IP address temporarily.
		uip_ipaddr_copy(&uip_udp_conn->ripaddr, &self->plat.sockaddr_remote.smcp_addr);
		smcp_get_current_instance()->plat.udp_conn->rport = self->plat.sockaddr_remote.smcp_port;

		uip_process(UIP_UDP_SEND_CONN);

#if UIP_CONF_IPV6_MULTICAST
		/* Let the multicast engine process the datagram before we send it */
		if (uip_is_addr_mcast_routable(&uip_udp_conn->ripaddr)) {
			UIP_MCAST6.out();
		}
#endif /* UIP_IPV6_MULTICAST */

		// TODO: This next part is somewhat contiki-ish. Abstract somehow?
#if UIP_CONF_IPV6
		tcpip_ipv6_output();
#else
		tcpip_output();
#endif

		// Since we just sent out packet, we need to zero out uip_slen
		// to prevent uIP from trying to send out a packet.
		uip_slen = 0;

		// Make our remote address unspecified again, so that we can continue
		// to receive traffic.
		memset(&smcp_get_current_instance()->plat.udp_conn->ripaddr, 0, sizeof(uip_ipaddr_t));
		smcp_get_current_instance()->plat.udp_conn->rport = 0;
	}

	ret = SMCP_STATUS_OK;
bail:
	return ret;
}

// MARK: -

smcp_status_t
smcp_plat_wait(
	smcp_t self, smcp_cms_t cms
) {
	// This doesn't really make sense with UIP.
	return SMCP_STATUS_OK;
}

smcp_status_t
smcp_plat_process(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

	if (!uip_udpconnection()) {
		goto bail;
	}

	if (uip_udp_conn != smcp_plat_get_udp_conn(smcp)) {
		goto bail;
	}

	if(uip_newdata()) {
		memcpy(&self->plat.sockaddr_remote.smcp_addr,&UIP_IP_BUF->srcipaddr,sizeof(smcp_addr_t));
		self->plat.sockaddr_remote.smcp_port = UIP_UDP_BUF->srcport;

		memcpy(&self->plat.sockaddr_local.smcp_addr,&UIP_IP_BUF->destipaddr,sizeof(smcp_addr_t));
		self->plat.sockaddr_local.smcp_port = UIP_UDP_BUF->destport;

		smcp_plat_set_session_type(SMCP_SESSION_TYPE_UDP);

		smcp_inbound_packet_process(smcp, uip_appdata, uip_datalen(), 0);
	} else if(uip_poll()) {
		smcp_set_current_instance(self);
		smcp_handle_timers(self);
	}

bail:
	smcp_set_current_instance(NULL);
	self->is_responding = false;

	return 0;
}

smcp_status_t
smcp_plat_lookup_hostname(const char* hostname, smcp_sockaddr_t* saddr, int flags)
{
	smcp_status_t ret;
	memset(saddr, 0, sizeof(*saddr));

	ret = uiplib_ipaddrconv(
		hostname,
		&saddr->smcp_addr
	) ? SMCP_STATUS_OK : SMCP_STATUS_HOST_LOOKUP_FAILURE;

#if SMCP_CONF_USE_DNS
#if CONTIKI
	if(ret) {
		SMCP_NON_RECURSIVE uip_ipaddr_t *temp = NULL;
		switch(resolv_lookup(hostname,&temp)) {
			case RESOLV_STATUS_CACHED:
				memcpy(&saddr->smcp_addr, temp, sizeof(uip_ipaddr_t));
				ret = SMCP_STATUS_OK;
				break;
			case RESOLV_STATUS_UNCACHED:
			case RESOLV_STATUS_EXPIRED:
				resolv_query(hostname);
			case RESOLV_STATUS_RESOLVING:
				ret = SMCP_STATUS_WAIT_FOR_DNS;
				break;
			default:
			case RESOLV_STATUS_ERROR:
			case RESOLV_STATUS_NOT_FOUND:
				ret = SMCP_STATUS_HOST_LOOKUP_FAILURE;
				break;
		}
	}
#else // CONTIKI
#error SMCP_CONF_USE_DNS was set, but no DNS lookup mechamism is known!
#endif
#endif // SMCP_CONF_USE_DNS

	require_noerr(ret,bail);

bail:
	return ret;
}


#if defined(CONTIKI)
smcp_timestamp_t
smcp_plat_cms_to_timestamp(
	smcp_cms_t cms
) {
	return clock_time() + cms*CLOCK_SECOND/MSEC_PER_SEC;
}
smcp_cms_t
smcp_plat_timestamp_diff(smcp_timestamp_t lhs, smcp_timestamp_t rhs) {
	return (lhs - rhs)*MSEC_PER_SEC/CLOCK_SECOND;
}
smcp_cms_t
smcp_plat_timestamp_to_cms(smcp_timestamp_t ts) {
	return smcp_plat_timestamp_diff(ts, clock_time());
}
#endif




#endif //#if SMCP_USE_UIP
