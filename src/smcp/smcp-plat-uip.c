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
#include "smcp-auth.h"

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


smcp_t
smcp_init(
	smcp_t self, uint16_t port
) {
	SMCP_EMBEDDED_SELF_HOOK;

	require(self != NULL, bail);

	if(port == 0)
		port = COAP_DEFAULT_PORT;

	// Clear the entire structure.
	memset(self, 0, sizeof(*self));

	// Set up the UDP port for listening.
	self->udp_conn = udp_new(NULL, 0, NULL);
	uip_udp_bind(self->udp_conn, htons(port));
	self->udp_conn->rport = 0;

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

bail:
	return self;
}

void
smcp_release_plat(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

	if(self->udp_conn)
		uip_udp_remove(self->udp_conn);
}


struct uip_udp_conn*
smcp_get_udp_conn(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	return self->udp_conn;
}

uint16_t
smcp_get_port(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;
	return ntohs(self->udp_conn->lport);
}

smcp_status_t
smcp_outbound_send_hook(void) {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();
	coap_size_t header_len;

	assert(uip_udp_conn == smcp_get_current_instance()->udp_conn);

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
		port = ntohs(self->outbound.saddr.smcp_port);
		SMCP_ADDR_NTOP(addr_str,sizeof(addr_str),&self->outbound.saddr.smcp_addr);
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

	uip_slen = header_len +	smcp_get_current_instance()->outbound.content_len;

	require_action(uip_slen<SMCP_MAX_PACKET_LENGTH, bail, ret = SMCP_STATUS_MESSAGE_TOO_BIG);

	if (self->outbound.packet!=(struct coap_header_s*)uip_sappdata) {
		memmove(
			uip_sappdata,
			(char*)self->outbound.packet,
			uip_slen
		);
		self->outbound.packet = (struct coap_header_s*)uip_sappdata;
	}

	//uip_sappdata = self->outbound.packet;

#if 0
	// TODO: For some reason this isn't working anymore. Investigate.
	if(self->is_responding) {
		// We are responding, let uIP handle preparing the packet.
	} else
#endif
	{	// Here we explicitly tickle UIP to send the packet.

		// Change the remote IP address temporarily.
		uip_ipaddr_copy(&uip_udp_conn->ripaddr, &self->outbound.saddr.smcp_addr);
		smcp_get_current_instance()->udp_conn->rport = self->outbound.saddr.smcp_port;

		uip_process(UIP_UDP_SEND_CONN);

#if UIP_CONF_IPV6_MULTICAST
		/* Let the multicast engine process the datagram before we send it */
		if(uip_is_addr_mcast_routable(&uip_udp_conn->ripaddr)) {
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

		// Make our remote address unspecified again.
		memset(&smcp_get_current_instance()->udp_conn->ripaddr, 0, sizeof(uip_ipaddr_t));
		smcp_get_current_instance()->udp_conn->rport = 0;
	}

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

// MARK: -

smcp_status_t
smcp_wait(
	smcp_t self, cms_t cms
) {
	SMCP_EMBEDDED_SELF_HOOK;
	smcp_status_t ret = 0;

	// This doesn't really make sense with UIP.

bail:
	return ret;
}

smcp_status_t
smcp_process(smcp_t self) {
	SMCP_EMBEDDED_SELF_HOOK;

	if (!uip_udpconnection()) {
		goto bail;
	}

	if (uip_udp_conn != smcp_get_udp_conn(smcp)) {
		goto bail;
	}

	if(uip_newdata()) {
		smcp_inbound_start_packet(smcp, uip_appdata, uip_datalen());
		{
			// Put all of this stuff in a block so it doesn't get added
			// to the stack for no reason.
			smcp_sockaddr_t addr;

#if 0
			char addr_str[50];
			SMCP_ADDR_NTOP(addr_str,sizeof(addr_str),&UIP_IP_BUF->srcipaddr);
			printf("**** IN %s\n",addr_str);
#endif

			memcpy(&addr.smcp_addr,&UIP_IP_BUF->srcipaddr,sizeof(addr.smcp_addr));
			addr.smcp_port = UIP_UDP_BUF->srcport;
			smcp_inbound_set_srcaddr(&addr);

			memcpy(&addr.smcp_addr,&UIP_IP_BUF->destipaddr,sizeof(addr.smcp_addr));
			addr.smcp_port = UIP_UDP_BUF->destport;
			smcp_inbound_set_destaddr(&addr);
		}
		smcp_inbound_finish_packet();
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
smcp_internal_lookup_hostname(const char* hostname, smcp_sockaddr_t* saddr)
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


#endif //#if SMCP_USE_UIP
