/*	@file cgi-node.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2016 Robert Quattlebaum
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

#include <stdio.h>

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include <syslog.h>
#include "smcp/assert-macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <libnyoci/libnyoci.h>
#include <libnyociextra/libnyociextra.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "cgi-node.h"

#ifndef CGI_NODE_MAX_REQUESTS
#define CGI_NODE_MAX_REQUESTS		(20)
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "0.0-xcode"
#endif

#ifndef MIN
#if defined(__GCC_VERSION__)
#define MIN(a, \
		b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a < \
			  _b ? _a : _b; })
#else
#define MIN(a,b)	((a)<(b)?(a):(b))	// NAUGHTY!...but compiles
#endif
#endif

#ifndef MAX
#if defined(__GCC_VERSION__)
#define MAX(a, \
		b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a > \
			  _b ? _a : _b; })
#else
#define MAX(a,b)	((a)<(b)?(b):(a))	// NAUGHTY!...but compiles
#endif
#endif

/*

Events:
	First request, w/out block1
	First request, w/block1
	Additional request, w/block1
	Last block1 request
	Additional request, w/block2
	ACK from block2
	ACK from block1
	READY from fd_cmd_stdin
	EPIPE from fd_cmd_stdin
	DATA from fd_cmd_stdout
	EOF from fd_cmd_stdout

States:
	Inactive
	Finished
	ACTIVE_BLOCK1_WAIT_REQ - Input Pending, waiting for request
	ACTIVE_BLOCK1_WAIT_FD - Input Pending, async response, waiting to write to fd_cmd_stdin
	ACTIVE_BLOCK1_WAIT_ACK - Input Pending, async response sent, waiting for ack
	ACTIVE_BLOCK2_WAIT_REQ - Input Finished, Waiting For Request
	ACTIVE_BLOCK2_WAIT_FD - Input Finished, Async Response, Waiting For Data from fd_cmd_stdout
	ACTIVE_BLOCK2_WAIT_ACK - Input Finished, Async Response Sent, Waiting For Ack



*/

typedef enum {
	CGI_NODE_STATE_INACTIVE=0,
	CGI_NODE_STATE_FINISHED=1,
	CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ=2,
	CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD=3,
	CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK=4,
	CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ=5,
	CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD=6,
	CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK=7,
} cgi_node_state_t;

#define BLOCK_OPTION_UNSPECIFIED		(0xFFFFFFFF)
#define BLOCK_OPTION_DEFAULT			(0x03)

struct cgi_node_request_s {

	struct nyoci_async_response_s async_response;
	cgi_node_state_t state;
	nyoci_timestamp_t expiration;
	bool is_active;

	int fd_cmd_stdin;
	int fd_cmd_stdout;
	int pid;
	uint32_t block1;
	uint32_t block2;
	size_t bytes_sent;
	char* stdin_buffer;
	size_t stdin_buffer_len;
	char* stdout_buffer;
	size_t stdout_buffer_len;
	nyoci_transaction_t transaction;
};
typedef struct cgi_node_request_s* cgi_node_request_t;

struct cgi_node_s {
	struct nyoci_node_s node;
	nyoci_t interface;
	const char* shell;
	const char* cmd;

	struct cgi_node_request_s requests[CGI_NODE_MAX_REQUESTS];
	int request_count;
};

nyoci_status_t cgi_node_request_change_state(cgi_node_t node, cgi_node_request_t request, cgi_node_state_t new_state);

cgi_node_request_t
cgi_node_get_associated_request(cgi_node_t node) {
	cgi_node_request_t ret = NULL;
	int i;

	for(i = 0; i < CGI_NODE_MAX_REQUESTS; i++) {
		cgi_node_request_t request = &node->requests[i];

		if (request->state < CGI_NODE_STATE_FINISHED) {
			continue;
		}

		if (!nyoci_inbound_is_related_to_async_response(&request->async_response)) {
			syslog(LOG_DEBUG, "cgi_node_get_associated_request: %d: session mismatch", i);
			continue;
		}

		ret = request;
		break;
	}

	return ret;
}

cgi_node_request_t
cgi_node_create_request(cgi_node_t node) {
	cgi_node_request_t ret = NULL;
	int i;
	int pipe_cmd_stdin[2];
	int pipe_cmd_stdout[2];

	for (i=0; i < CGI_NODE_MAX_REQUESTS; i++) {
		if (node->requests[i].state <= CGI_NODE_STATE_FINISHED) {
			ret = &node->requests[i];
			if (node->requests[i].state == CGI_NODE_STATE_INACTIVE) {
				break;
			}
		}
	}

	require(ret,bail);

	ret->is_active = 1;
	ret->state = CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ;

	if(ret->pid != 0 && ret->pid != -1) {
		int status;
		kill(ret->pid,SIGKILL);
		waitpid(ret->pid, &status, 0);
	}

	if(ret->fd_cmd_stdin>=0) {
		close(ret->fd_cmd_stdin);
	}

	if(ret->fd_cmd_stdout>=0) {
		close(ret->fd_cmd_stdout);
	}

	ret->pid = 0;
	ret->fd_cmd_stdin = -1;
	ret->fd_cmd_stdout = -1;
	ret->block1 = BLOCK_OPTION_UNSPECIFIED;
	ret->block2 = BLOCK_OPTION_DEFAULT; // Default value, overwrite with actual block
	ret->stdin_buffer_len = 0;
	ret->stdout_buffer_len = 0;
	ret->expiration = nyoci_plat_cms_to_timestamp(30 * MSEC_PER_SEC);

	free(ret->stdin_buffer);
	ret->stdin_buffer = NULL;

	free(ret->stdout_buffer);
	ret->stdout_buffer = NULL;

	nyoci_start_async_response(&ret->async_response, NYOCI_ASYNC_RESPONSE_FLAG_DONT_ACK);

	pipe(pipe_cmd_stdin);
	pipe(pipe_cmd_stdout);

	if(!(ret->pid=fork())) {
		// We are the child!
		char path[2048]; // todo: this max should be a preprocessor macro

		// Update stdin and stdout.
		dup2(pipe_cmd_stdin[0],STDIN_FILENO);
		dup2(pipe_cmd_stdout[1],STDOUT_FILENO);

		close(pipe_cmd_stdin[0]);
		close(pipe_cmd_stdin[1]);
		close(pipe_cmd_stdout[0]);
		close(pipe_cmd_stdout[1]);

		path[0] = 0;
		nyoci_node_get_path(&node->node,path,sizeof(path));
		setenv("SCRIPT_NAME",path,1);

		setenv("SERVER_SOFTWARE","smcpd/" PACKAGE_VERSION,1);
		setenv("REQUEST_METHOD",coap_code_to_cstr(nyoci_inbound_get_packet()->code),1);
		setenv("REQUEST_URI",nyoci_inbound_get_path(path,2),1);
		setenv("GATEWAY_INTERFACE","CGI/1.1",1);
		setenv("SERVER_PROTOCOL","CoAP/1.0",1);

		setenv("REMOTE_ADDR","",1);
		setenv("REMOTE_PORT","",1);
		setenv("SERVER_NAME","",1);
		setenv("SERVER_ADDR","",1);
		setenv("SERVER_PORT","",1);

		if (0 == strncmp(path,getenv("SCRIPT_NAME"),strlen(getenv("SCRIPT_NAME")))) {
			setenv("PATH_INFO",path+strlen(getenv("SCRIPT_NAME")),1);
		}

		syslog(LOG_DEBUG, "cgi-node: About to execute \"%s\" using shell \"%s\"", node->cmd, node->shell);

		execl(node->shell,node->shell,"-c",node->cmd,NULL);

		syslog(LOG_ERR, "cgi-node: Failed to execute \"%s\" using shell \"%s\"", node->cmd, node->shell);

		// We should never get here...
		abort();
	}

	if (ret->pid < 0) {
		// Oh hell.

		syslog(LOG_ERR,"Unable to fork!");

		close(pipe_cmd_stdin[0]);
		close(pipe_cmd_stdin[1]);
		close(pipe_cmd_stdout[0]);
		close(pipe_cmd_stdout[1]);

		ret->is_active = 0;
		ret->state = CGI_NODE_STATE_INACTIVE;

		ret = NULL;
		goto bail;
	}

	ret->fd_cmd_stdin = pipe_cmd_stdin[1];
	ret->fd_cmd_stdout = pipe_cmd_stdout[0];

	close(pipe_cmd_stdin[0]);
	close(pipe_cmd_stdout[1]);

bail:
	return ret;
}

nyoci_status_t
cgi_node_async_resend_response(void* context)
{
	nyoci_status_t ret = 0;
	cgi_node_request_t request = context;
	coap_size_t block_len = (coap_size_t)(1<<((request->block2&0x7)+4));
	coap_size_t max_len;

	syslog(LOG_INFO, "cgi-node: Resending async response. . .");

	ret = nyoci_outbound_begin_async_response(COAP_RESULT_205_CONTENT,&request->async_response);
	require_noerr(ret,bail);

//	ret = nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
//	require_noerr(ret,bail);

	if (request->block1!=BLOCK_OPTION_UNSPECIFIED) {
		ret = nyoci_outbound_add_option_uint(COAP_OPTION_BLOCK1,request->block1);
		require_noerr(ret,bail);
	}

	if (request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK) {
		if ( request->stdout_buffer_len > block_len
		  || request->fd_cmd_stdout >= 0
		  || ((request->block2>>4)!=0)
		) {
			if ( request->stdout_buffer_len > block_len
			  || request->fd_cmd_stdout >= 0
			) {
				request->block2 |= (1<<3);
			} else {
				request->block2 &= ~(1<<3);
			}
			ret = nyoci_outbound_add_option_uint(COAP_OPTION_BLOCK2,request->block2);
			require_noerr(ret,bail);
		}

		char *content = nyoci_outbound_get_content_ptr(&max_len);
		require_noerr(ret,bail);

		memcpy(content,request->stdout_buffer,MIN(request->stdout_buffer_len,block_len));

		ret = nyoci_outbound_set_content_len((coap_size_t)MIN(request->stdout_buffer_len,block_len));
		require_noerr(ret,bail);
	}

	ret = nyoci_outbound_send();
	require_noerr(ret,bail);

bail:
	return ret;
}

nyoci_status_t
cgi_node_request_pop_bytes_from_stdin(cgi_node_request_t request, int count)
{
	request->stdin_buffer_len-=count;
	memmove(request->stdin_buffer,request->stdin_buffer+count,request->stdin_buffer_len);
	return NYOCI_STATUS_OK;
}

nyoci_status_t
cgi_node_request_pop_bytes_from_stdout(cgi_node_request_t request, int count)
{
	syslog(LOG_INFO, "cgi-node: pushing %d bytes from stdout buffer", count);

	if((signed)request->stdout_buffer_len>count) {
		request->stdout_buffer_len-=count;
		memmove(request->stdout_buffer,request->stdout_buffer+count,request->stdout_buffer_len);
	} else {
		request->stdout_buffer_len = 0;
	}
	return NYOCI_STATUS_OK;
}

nyoci_status_t
cgi_node_async_ack_handler(int statuscode, void* context)
{
	nyoci_status_t ret = NYOCI_STATUS_OK;
	cgi_node_request_t request = context;
	cgi_node_t node = (cgi_node_t)nyoci_get_current_instance(); // TODO: WTF!!?!!!

	syslog(LOG_INFO, "cgi-node: Finished sending async response.");

	if(request->state==CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK) {
		if(request->block1!=BLOCK_OPTION_UNSPECIFIED && 0==(request->block1&(1<<3))) {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
			);
		} else {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ
			);
		}
	} else if(request->state==CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK) {
		if(request->fd_cmd_stdout<0 && request->stdout_buffer_len<=2*(1<<((request->block2&0x7)+4))) {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_FINISHED
			);
		} else {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ
			);
		}
	} else {
		// What the...?
	}

	request->transaction = NULL;

	return ret;
}
nyoci_status_t
cgi_node_send_next_block(cgi_node_t node,cgi_node_request_t request) {
	nyoci_status_t ret = 0;

	// If we are currently asynchronous, go ahead and send an asynchronous response.
	// Otherwise, we don't have much to do: We will just go ahead and send
	// the rest of the data at the next query.

	// TODO: Writeme!

	nyoci_transaction_t transaction = nyoci_transaction_init(
		request->transaction,
		0,
		&cgi_node_async_resend_response,
		&cgi_node_async_ack_handler,
		(void*)request
	);
	if(!transaction) {
		ret = NYOCI_STATUS_MALLOC_FAILURE;
		goto bail;
	}

	ret = nyoci_transaction_begin(
		node->interface,
		transaction,
		30*MSEC_PER_SEC
	);
	if(ret) {
		nyoci_transaction_end(nyoci_get_current_instance(),transaction);
		goto bail;
	}


bail:
	return ret;
}

nyoci_status_t
cgi_node_request_change_state(cgi_node_t node, cgi_node_request_t request, cgi_node_state_t new_state) {
	// TODO: Possibly do more later...?

	syslog(LOG_INFO, "cgi-node: %d -> %d", request->state, new_state);

	if(request->state == new_state) {
		// Same state, do nothing.
	} else

	if ( request->state == CGI_NODE_STATE_INACTIVE
	  && new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
	) {

	} else if ( request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
	         && new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD
	) {
		nyoci_start_async_response(&request->async_response, 0);

	} else if ( request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD
	         && new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
	) {
		cgi_node_send_next_block(node,request);

	} else if ( request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
	         && new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
	) {
		if (request->transaction) {
			nyoci_transaction_end(nyoci_get_current_instance(),request->transaction);
			request->transaction = NULL;
		}

	} else if ( ( (request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ)
	           || (request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ)
	            )
	         && ( new_state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD)
	) {
		if(!request->stdin_buffer_len &&  request->fd_cmd_stdin>=0) {
			close(request->fd_cmd_stdin);
			request->fd_cmd_stdin = -1;
		}
		nyoci_start_async_response(&request->async_response, 0);
	} else if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD
		&& new_state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK
	) {
		if(!request->stdin_buffer_len &&  request->fd_cmd_stdin>=0) {
			close(request->fd_cmd_stdin);
			request->fd_cmd_stdin = -1;
		}
		cgi_node_send_next_block(node,request);
	} else if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK
		&& new_state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ
	) {
		if(!request->stdin_buffer_len &&  request->fd_cmd_stdin>=0) {
			close(request->fd_cmd_stdin);
			request->fd_cmd_stdin = -1;
		}
		//cgi_node_request_pop_bytes_from_stdout(request,(1<<((request->block2&0x7)+4)));
		if(request->transaction) {
			nyoci_transaction_end(nyoci_get_current_instance(),request->transaction);
			request->transaction = NULL;
		}
	} else if(new_state == CGI_NODE_STATE_FINISHED) {
		if(request->transaction) {
			nyoci_transaction_end(nyoci_get_current_instance(),request->transaction);
			request->transaction = NULL;
		}
		close(request->fd_cmd_stdin);
		request->fd_cmd_stdin = -1;
		close(request->fd_cmd_stdout);
		request->fd_cmd_stdout = -1;
		if(request->pid != 0 && request->pid != -1) {
			int status;
			kill(request->pid,SIGTERM);
			if(waitpid(request->pid, &status, WNOHANG) == request->pid) {
				request->pid = 0;
			}
		}
	} else {
		// INVALID STATE TRANSITION!
		syslog(LOG_ERR, "cgi-node: BAD STATE CHANGE: %d -> %d", request->state, new_state);
		abort();
	}

	request->state = new_state;

	return NYOCI_STATUS_OK;
}



nyoci_status_t
cgi_node_request_handler(
	cgi_node_t		node
) {
	nyoci_status_t ret = 0;
	cgi_node_request_t request = NULL;
	uint32_t block2_option = BLOCK_OPTION_DEFAULT;
	uint32_t block1_option = BLOCK_OPTION_UNSPECIFIED;
	coap_code_t	method = nyoci_inbound_get_code();

	require(node,bail);

	node->interface = nyoci_get_current_instance();

	if (method==COAP_METHOD_GET) {
		ret = 0;
	}

	require_noerr(ret,bail);

	{
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;
		while ((key=nyoci_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
			if (key == COAP_OPTION_BLOCK2) {
				uint8_t i;
				block2_option = 0;
				for (i = 0; i < value_len; i++) {
					block2_option = (block2_option << 8) + value[i];
				}
			}
			if (key == COAP_OPTION_BLOCK1) {
				uint8_t i;
				block1_option = 0;
				for (i = 0; i < value_len; i++) {
					block1_option = (block1_option << 8) + value[i];
				}
			}
		}
	}


	// Make sure this is a supported method.
	switch (method) {
	case COAP_METHOD_GET:
	case COAP_METHOD_PUT:
	case COAP_METHOD_POST:
	case COAP_METHOD_DELETE:
		break;
	default:
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
		goto bail;
		break;
	}

	request = cgi_node_get_associated_request(node);

	if (request == NULL) {
		// Possibly new request.
		// Assume new for now, but we may need to do additional checks.

		// We don't support non-zero block indexes on the first packet.
		require_action((block2_option>>4) == 0, bail, ret = NYOCI_STATUS_INVALID_ARGUMENT);

		request = cgi_node_create_request(node);
		require_action(request != NULL, bail, ret = NYOCI_STATUS_FAILURE);
		request->block2 = block2_option;
	}

	require(request,bail);

	if ( request->state==CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
	  || request->state==CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
	) {
		if (request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK) {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
			);
		}

		if (nyoci_inbound_get_content_len()) {
			request->stdin_buffer_len += nyoci_inbound_get_content_len();
			request->stdin_buffer = realloc(request->stdin_buffer,request->stdin_buffer_len);
			// TODO: We should look at the block1 header to make sure it makes sense!
			// This could be a duplicate or it could be *ahead* of where we are. We
			// must catch these cases in the future!
			if (request->stdin_buffer) {
				memcpy(
					request->stdin_buffer+request->stdin_buffer_len - nyoci_inbound_get_content_len(),
					nyoci_inbound_get_content_ptr(),
					nyoci_inbound_get_content_len()
				);
			} else {
				ret = NYOCI_STATUS_MALLOC_FAILURE;
				goto bail;
			}
		}

		if ((block1_option == 0xFFFFFFFF) || (0 == (block1_option&0x4))) {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD
			);
		} else {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD
			);
		}
	} else if (request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD) {
		// We should not get a request at this point in the state machine.
		if (nyoci_inbound_is_dupe()) {
			nyoci_outbound_begin_response(COAP_CODE_EMPTY);
			nyoci_outbound_send();
			ret = NYOCI_STATUS_OK;
		} else {
			ret = NYOCI_STATUS_FAILURE;
		}
	} else if ( request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ
	         || request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK
	         || request->state == CGI_NODE_STATE_FINISHED
	) {
		// Ongoing request. Handle it.
		uint32_t block2_start = (block2_option>>4) * (1<<((block2_option&0x7)+4));
		uint32_t block2_stop = block2_start + (1<<((block2_option&0x7)+4));

		if ( request->block2 != BLOCK_OPTION_UNSPECIFIED
		  && block2_start < (request->block2>>4) * (1<<((request->block2&0x7)+4))
		) {
				// Old Dupe?
				nyoci_outbound_drop();
				ret = NYOCI_STATUS_DUPE;
				goto bail;
		}

		if (request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK) {
			// OK, we need to clear out the previous stuff.
			if(block2_stop != (request->block2>>4) * (1<<((request->block2&0x7)+4))) {
				// Looks like the sender skipped some blocks.
				// Hmm. This isn't good.
				ret = NYOCI_STATUS_FAILURE;
				goto bail;
			}

			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ
			);
		} else if (block2_option != request->block2) {
			// TODO: check to make sure this is valid!
			ret = cgi_node_request_pop_bytes_from_stdout(request,(1<<((request->block2&0x7)+4)));
			require_noerr(ret,bail);
		}

		request->block2 = block2_option;

		coap_size_t block_len = (coap_size_t)(1<<((request->block2&0x7)+4));

		if ( request->stdout_buffer_len >= block_len
		  || request->fd_cmd_stdout <= -1
		) {
			// We have data!
			coap_size_t max_len;

			ret = nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);
			require_noerr(ret,bail);

//			ret = nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
//			require_noerr(ret,bail);

			if ( request->stdout_buffer_len>block_len
			  || request->fd_cmd_stdout >= 0
			) {
				ret = nyoci_outbound_add_option_uint(COAP_OPTION_BLOCK2,request->block2);
				require_noerr(ret,bail);
			}

			char *content = nyoci_outbound_get_content_ptr(&max_len);
			require_noerr(ret,bail);

			memcpy(content,request->stdout_buffer,MIN(request->stdout_buffer_len,block_len));

			ret = nyoci_outbound_set_content_len((coap_size_t)MIN(request->stdout_buffer_len,block_len));
			require_noerr(ret,bail);

			ret = nyoci_outbound_send();
			require_noerr(ret,bail);

			if ( request->fd_cmd_stdout < 0
			  && request->stdout_buffer_len <= block_len
			) {
				ret = cgi_node_request_change_state(
					node,
					request,
					CGI_NODE_STATE_FINISHED
				);
			}

		} else if (request->fd_cmd_stdout >= 0) {
			// Not enough data yet.
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD
			);
		}
	} else if (request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD) {
		// We should not get a request at this point in the state machine.
		if (nyoci_inbound_is_dupe()) {
			nyoci_outbound_begin_response(COAP_CODE_EMPTY);
			nyoci_outbound_send();
			ret = NYOCI_STATUS_OK;
		} else {
			ret = NYOCI_STATUS_FAILURE;
		}
	}

bail:

	return ret;
}

void
cgi_node_dealloc(cgi_node_t x) {
	// TODO: Clean up requests!
	free((void*)x->cmd);
	free((void*)x->shell);
	free(x);
}

cgi_node_t
cgi_node_alloc() {
	cgi_node_t ret = (cgi_node_t)calloc(sizeof(struct cgi_node_s), 1);

	ret->node.finalize = (void (*)(nyoci_node_t)) &cgi_node_dealloc;
	return ret;
}

cgi_node_t
cgi_node_init(
	cgi_node_t	self,
	nyoci_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	int i;

	NYOCI_LIBRARY_VERSION_CHECK();

	require(cmd!=NULL, bail);
	require(cmd[0]!=0, bail);
	require(name!=NULL, bail);
	require(self || (self = cgi_node_alloc()), bail);

	require(nyoci_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	((nyoci_node_t)&self->node)->request_handler = (void*)&cgi_node_request_handler;
	self->cmd = strdup(cmd);
	self->shell = strdup("/bin/sh");

	for(i=0;i<CGI_NODE_MAX_REQUESTS;i++) {
		self->requests[i].fd_cmd_stdin = -1;
		self->requests[i].fd_cmd_stdout = -1;
	}

bail:
	return self;
}

nyoci_status_t
cgi_node_update_fdset(
	cgi_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	nyoci_cms_t *timeout
) {
	int i;
	for (i = 0; i < CGI_NODE_MAX_REQUESTS; i++) {
		cgi_node_request_t request = &self->requests[i];

		if (request->state<=CGI_NODE_STATE_FINISHED) {
			continue;
		}

		if ( request->stdin_buffer_len
		  && request->fd_cmd_stdin >= 0
		) {
			printf("Adding FD %d to write set\n",request->fd_cmd_stdin);
			if (write_fd_set) {
				FD_SET(request->fd_cmd_stdin,write_fd_set);
			}
			if (error_fd_set) {
				FD_SET(request->fd_cmd_stdin,error_fd_set);
			}
			if (fd_count) {
				*fd_count = MAX(*fd_count,request->fd_cmd_stdin+1);
			}
		}

		if ( request->fd_cmd_stdout >= 0
		  && request->stdout_buffer_len<(1<<((request->block2&0x7)+4))
		) {
			printf("Adding FD %d to read set\n",request->fd_cmd_stdout);
			if (read_fd_set) {
				FD_SET(request->fd_cmd_stdout, read_fd_set);
			}
			if (error_fd_set) {
				FD_SET(request->fd_cmd_stdout, error_fd_set);
			}
			if (fd_count) {
				*fd_count = MAX(*fd_count,request->fd_cmd_stdout+1);
			}
		}

		if (timeout && request->expiration) {
			*timeout = MIN(*timeout,MAX(0,nyoci_plat_timestamp_to_cms(request->expiration)));
		}

	}
	return NYOCI_STATUS_OK;
}

nyoci_status_t
cgi_node_process(cgi_node_t self) {
	int i;
	fd_set rd_set, wr_set, er_set;
	int fd_count = 0;
	struct timeval tv = {0,0};
	nyoci_cms_t timeout = CMS_DISTANT_FUTURE;

	FD_ZERO(&rd_set);
	FD_ZERO(&wr_set);
	FD_ZERO(&er_set);

	cgi_node_update_fdset(self, &rd_set, &wr_set, &er_set, &fd_count, &timeout);

	errno = 0;
	if (select(fd_count, &rd_set, &wr_set, &er_set, &tv) >= 0) {

		for (i=0; i < CGI_NODE_MAX_REQUESTS; i++) {
			cgi_node_request_t request = &self->requests[i];

			if (request->state <= CGI_NODE_STATE_FINISHED) {
				//printf("Skipping Request %p, stdin_fd=%d, stdout_fd=%d\n",request,request->fd_cmd_stdin,request->fd_cmd_stdout);
				continue;
			}

			if (nyoci_plat_timestamp_to_cms(request->expiration) < 0) {
				request->expiration = 0;
				cgi_node_request_change_state(
					self,
					request,
					CGI_NODE_STATE_FINISHED
				);
			}

			printf("Request %p, stdin_fd=%d, stdout_fd=%d\n",request,request->fd_cmd_stdin,request->fd_cmd_stdout);
			errno = 0;

			if ( request->stdin_buffer_len
			  && request->fd_cmd_stdin >= 0
			  && ( FD_ISSET(request->fd_cmd_stdin,&wr_set)
			    || FD_ISSET(request->fd_cmd_stdin,&er_set)
			  )
			) {
				// Ready to send data to command
				int bytes_written = write(request->fd_cmd_stdin, request->stdin_buffer, request->stdin_buffer_len);
				printf("WROTE %d BYTES TO FD_CMD_STDIN\n",bytes_written);
				if (bytes_written<0 || errno || FD_ISSET(request->fd_cmd_stdin,&er_set)) {
					if (errno!=EPIPE) {
						syslog(LOG_ERR,"Error on write, %s (%d)",strerror(errno),errno);
					}
					close(request->fd_cmd_stdin);
					request->fd_cmd_stdin = -1;
				} else if ((size_t)bytes_written==request->stdin_buffer_len) {
					request->stdin_buffer_len = 0;
				} else {
					request->stdin_buffer_len-=bytes_written;
					memmove(request->stdin_buffer,request->stdin_buffer+bytes_written,request->stdin_buffer_len);
				}
			}

			if (request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD) {
				if ( request->stdin_buffer_len == 0
				  || request->fd_cmd_stdin < 0
				) {
					cgi_node_request_change_state(
						self,
						request,
						CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
					);
				}
			}

			errno = 0;
			if ( request->fd_cmd_stdout >= 0
			  && ( FD_ISSET(request->fd_cmd_stdout,&rd_set)
			    || FD_ISSET(request->fd_cmd_stdout,&er_set)
			  )
			) {
				// Data is pending from command
				int bytes_read = (1<<((request->block2&0x7)+4))*2;
				request->stdout_buffer = realloc(request->stdout_buffer,request->stdout_buffer_len+bytes_read);
				if(!request->stdout_buffer)
					return NYOCI_STATUS_MALLOC_FAILURE;
				bytes_read = read(request->fd_cmd_stdout, request->stdout_buffer+request->stdout_buffer_len, bytes_read);

				if(bytes_read<=0 || errno || FD_ISSET(request->fd_cmd_stdout,&er_set)) {
					if(errno && errno!=EPIPE)
						syslog(LOG_ERR,"Error on read, %s (%d)",strerror(errno),errno);
					close(request->fd_cmd_stdout);
					request->fd_cmd_stdout = -1;
				} else {
					printf("READ %d BYTES FROM FD_CMD_STDOUT\n",bytes_read);
					request->stdout_buffer_len += bytes_read;
				}
			}

			if (request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD) {
				if ( !request->stdin_buffer_len
				  && request->fd_cmd_stdin >= 0
				) {
					close(request->fd_cmd_stdin);
					request->fd_cmd_stdin = -1;
				}
				if ( request->stdout_buffer_len>= (1<<((request->block2&0x7)+4))
				  || request->fd_cmd_stdout <= 0
				) {
					cgi_node_request_change_state(
						self,
						request,
						CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK
					);
				}
			}
		}
	} else {
		if (fd_count > 0) {
			printf("...fd_count:%d timeout:%d errno: %d %s\n",fd_count,timeout, errno, strerror(errno));
		}
	}
	return NYOCI_STATUS_OK;
}



nyoci_status_t
SMCPD_module__cgi_node_process(cgi_node_t self) {
	return cgi_node_process(self);
}

nyoci_status_t
SMCPD_module__cgi_node_update_fdset(
	cgi_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	nyoci_cms_t *timeout
) {
	return cgi_node_update_fdset(self, read_fd_set, write_fd_set, error_fd_set, fd_count, timeout);
}

cgi_node_t
SMCPD_module__cgi_node_init(
	cgi_node_t	self,
	nyoci_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	return cgi_node_init(self, parent, name, cmd);
}
