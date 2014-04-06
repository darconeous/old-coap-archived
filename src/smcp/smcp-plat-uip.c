//
//  smcp-plat-uip.c
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

#if CONTIKI
#include "contiki.h"
#include "net/ip/tcpip.h"
#endif

#include <stdio.h>

#if SMCP_USE_UIP
#include "net/ip/uip-udp-packet.h"
#include "net/ip/uiplib.h"
extern uint16_t uip_slen;

smcp_status_t
smcp_outbound_send_hook() {
	smcp_status_t ret = SMCP_STATUS_FAILURE;
	smcp_t const self = smcp_get_current_instance();
	size_t header_len;

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
		port = ntohs(smcp_get_current_instance()->udp_conn->rport);
#define CSTR_FROM_6ADDR(dest,addr) sprintf(dest,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
		CSTR_FROM_6ADDR(addr_str,&smcp_get_current_instance()->udp_conn->ripaddr);
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

	if(self->outbound.packet!=(struct coap_header_s*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN]) {
		memmove(
			&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN],
			(char*)self->outbound.packet,
			uip_slen
		);
		self->outbound.packet = (struct coap_header_s*)&uip_buf[UIP_LLH_LEN + UIP_IPUDPH_LEN];
	}

	uip_udp_conn = smcp_get_current_instance()->udp_conn;

	uip_process(UIP_UDP_SEND_CONN);

#if UIP_CONF_IPV6
	tcpip_ipv6_output();
#else
	if(uip_len > 0)
		tcpip_output();
#endif
	uip_slen = 0;

	memset(&smcp_get_current_instance()->udp_conn->ripaddr, 0, sizeof(uip_ipaddr_t));
	smcp_get_current_instance()->udp_conn->rport = 0;

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

#endif //#if SMCP_USE_UIP
