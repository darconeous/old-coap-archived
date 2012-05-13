#ifndef __SMCP_CURL_PROXY_H__
#define __SMCP_CURL_PROXY_H__ 1

#include "smcp_node.h"
#include <curl/curl.h>

typedef struct smcp_curl_proxy_node_s {
	struct smcp_node_s	node;
	//struct smcp_timer_s timer;
	CURLM *curl_multi_handle;
} *smcp_curl_proxy_node_t;

smcp_curl_proxy_node_t smcp_smcp_curl_proxy_node_alloc();

smcp_curl_proxy_node_t smcp_curl_proxy_node_init(
	smcp_curl_proxy_node_t	self,
	smcp_daemon_t		smcp,
	smcp_node_t			parent,
	const char*			name
);

#endif //__SMCP_TIMER_NODE_H__
