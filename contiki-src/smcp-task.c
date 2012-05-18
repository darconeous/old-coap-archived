
#include "contiki.h"

#include <stdio.h>
#include <string.h>

#include <smcp/smcp.h>

#include "smcp-task.h"
#include <smcp/smcp_pairing.h>
#include "net/uip.h"
#include "net/uip-udp-packet.h"
#include "sys/clock.h"
#include "watchdog.h"

#if DEBUG
#include <stdio.h>
#if __AVR__
#define PRINTF(FORMAT,args...) printf_P(PSTR(FORMAT),##args)
#else
#define PRINTF(...) printf(__VA_ARGS__)
#endif
#else
#define PRINTF(...)
#endif

#define UIP_IP_BUF                          ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if UIP_CONF_IPV6
#define UIP_UDP_BUF                        ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#else
#define UIP_UDP_BUF                        ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#endif

PROCESS(smcp_task, "SMCP/CoAP Daemon");

PROCESS_THREAD(smcp_task, ev, data)
{
	static struct etimer et;

	PROCESS_BEGIN();

	PRINTF("Starting SMCP\n");

	if(!smcp_daemon_init(smcp_daemon, SMCP_DEFAULT_PORT)) {
		PRINTF("Failed to start SMCP\n");
		goto bail;
	}

	if(!smcp_daemon_get_udp_conn(smcp_daemon)) {
		PRINTF("SMCP failed to create UDP conneciton!\n");
		goto bail;
	}

	PRINTF("SMCP started. UDP Connection = %p\n",smcp_daemon_get_udp_conn(smcp_daemon));

	smcp_pairing_init(smcp_daemon,smcp_daemon_get_root_node(smcp_daemon),NULL);

	etimer_set(&et, 1);

	while(1) {
		PROCESS_WAIT_EVENT();

		if(ev == tcpip_event) {
			if(uip_udpconnection() && (uip_udp_conn == smcp_daemon_get_udp_conn(smcp_daemon))) {
				if(uip_newdata())
					smcp_daemon_handle_inbound_packet(
						smcp_daemon,
						uip_appdata,
						uip_datalen(),
						&UIP_IP_BUF->srcipaddr,
						UIP_UDP_BUF->srcport
					);
				else if(uip_poll())
					smcp_daemon_process(smcp_daemon, 0);

				etimer_set(&et, CLOCK_SECOND*smcp_daemon_get_timeout(smcp_daemon)/1000+1);
			}
		} else if(ev == PROCESS_EVENT_TIMER) {
			if(etimer_expired(&et)) {
				tcpip_poll_udp(smcp_daemon_get_udp_conn(smcp_daemon));
			}
		}
	}

bail:
	PRINTF("Stopping SMCP\n");
	PROCESS_END();
}
