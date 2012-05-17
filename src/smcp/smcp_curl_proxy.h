#ifndef __SMCP_CURL_PROXY_H__
#define __SMCP_CURL_PROXY_H__ 1

#include "smcp_node.h"
#include <curl/curl.h>

typedef struct smcp_curl_proxy_node_s {
	struct smcp_node_s	node;
	CURLM *curl_multi_handle;
} *smcp_curl_proxy_node_t;

extern smcp_curl_proxy_node_t smcp_smcp_curl_proxy_node_alloc();

extern smcp_curl_proxy_node_t smcp_curl_proxy_node_init(
	smcp_curl_proxy_node_t	self,
	smcp_node_t			parent,
	const char*			name,
	CURLM *multi_handle
);

#endif //__SMCP_TIMER_NODE_H__
