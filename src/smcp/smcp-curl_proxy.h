/*!	@file smcp-curl_proxy.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Curl-based CoAP-HTTP Proxy Request Handler
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

#ifndef __SMCP_CURL_PROXY_H__
#define __SMCP_CURL_PROXY_H__ 1

#include "smcp.h"
#include "smcp-node-router.h"
#include <curl/curl.h>

/*!	@addtogroup smcp-extras
**	@{
*/

/*!	@defgroup smcp-curl_proxy CuRL Proxy
**	@{
**	@brief Curl-based CoAP-HTTP Proxy Request Handler (Experimental)
**
*/


typedef struct smcp_curl_proxy_node_s {
	struct smcp_node_s	node;
	CURLM *curl_multi_handle;
	smcp_t interface;
} *smcp_curl_proxy_node_t;

extern smcp_curl_proxy_node_t smcp_smcp_curl_proxy_node_alloc();

extern smcp_curl_proxy_node_t smcp_curl_proxy_node_init(
	smcp_curl_proxy_node_t	self,
	smcp_node_t			parent,
	const char*			name
);

extern smcp_status_t smcp_curl_proxy_node_update_fdset(
	smcp_curl_proxy_node_t node,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *exc_fd_set,
    int *max_fd,
	cms_t *timeout
);

extern smcp_status_t smcp_curl_proxy_node_process(smcp_curl_proxy_node_t node);

extern smcp_status_t smcp_curl_proxy_request_handler(smcp_curl_proxy_node_t node);

/*!	@} */
/*!	@} */

#endif //__SMCP_TIMER_NODE_H__
