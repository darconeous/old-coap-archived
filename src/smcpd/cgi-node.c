/*	@file cgi-node.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
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

#include <stdio.h>

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <syslog.h>
#include <smcp/assert-macros.h>
#include <stdio.h>
#include <stdlib.h>
#include <smcp/smcp.h>
#include <smcp/smcp-transaction.h>
#include <smcp/smcp-node-router.h>
#include <smcp/coap.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#ifndef CGI_NODE_MAX_REQUESTS
#define CGI_NODE_MAX_REQUESTS		(20)
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

struct smcp_async_response_s async_response;
	cgi_node_state_t state;
	time_t expiration;
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
	smcp_transaction_t transaction;
};
typedef struct cgi_node_request_s* cgi_node_request_t;

struct cgi_node_s {
	struct smcp_node_s node;
	smcp_t interface;
	const char* shell;
	const char* cmd;

	struct cgi_node_request_s requests[CGI_NODE_MAX_REQUESTS];
	int request_count;
};

typedef struct cgi_node_s* cgi_node_t;

smcp_status_t cgi_node_request_change_state(cgi_node_t node, cgi_node_request_t request, cgi_node_state_t new_state);

cgi_node_request_t
cgi_node_get_associated_request(cgi_node_t node) {
	cgi_node_request_t ret = NULL;
	int i;

	for(i=0;i<CGI_NODE_MAX_REQUESTS;i++) {
		cgi_node_request_t request = &node->requests[i];
		if(request->state<CGI_NODE_STATE_FINISHED) {
			continue;
		}
		if(request->async_response.request.header.token_len != smcp_inbound_get_packet()->token_len) {
//			printf("cgi_node_get_associated_request: %d: token_len mitmatch\n",i);
			continue;
		}
		if(request->async_response.request.header.code != smcp_inbound_get_packet()->code) {
//			printf("cgi_node_get_associated_request: %d: code mitmatch\n",i);
			continue;
		}
		if(0!=memcmp(request->async_response.request.header.token,smcp_inbound_get_packet()->token,smcp_inbound_get_packet()->token_len)) {
//			printf("cgi_node_get_associated_request: %d: token mitmatch\n",i);
			continue;
		}
		if(0!=memcmp(&request->async_response.saddr,smcp_inbound_get_saddr(),smcp_inbound_get_socklen())) {
//			printf("cgi_node_get_associated_request: %d: saddr mitmatch\n",i);
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
//	int set = 1;

	for(i=0;i<CGI_NODE_MAX_REQUESTS;i++) {
		if(node->requests[i].state<=CGI_NODE_STATE_FINISHED) {
			ret = &node->requests[i];
			if(node->requests[i].state==CGI_NODE_STATE_INACTIVE)
				break;
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
	if(ret->fd_cmd_stdin>=0)
		close(ret->fd_cmd_stdin);
	if(ret->fd_cmd_stdout>=0)
		close(ret->fd_cmd_stdout);

	ret->pid = 0;
	ret->fd_cmd_stdin = -1;
	ret->fd_cmd_stdout = -1;
	ret->block1 = BLOCK_OPTION_UNSPECIFIED;
	ret->block2 = BLOCK_OPTION_DEFAULT; // Default value, overwrite with actual block
	ret->stdin_buffer_len = 0;
	ret->stdout_buffer_len = 0;
	ret->expiration = time(NULL)+30;

	free(ret->stdin_buffer);
	ret->stdin_buffer = NULL;

	free(ret->stdout_buffer);
	ret->stdout_buffer = NULL;

	smcp_start_async_response(&ret->async_response, SMCP_ASYNC_RESPONSE_FLAG_DONT_ACK);

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
		smcp_node_get_path(&node->node,path,sizeof(path));
		setenv("SCRIPT_NAME",path,1);

		setenv("SERVER_SOFTWARE","smcpd/"PACKAGE_VERSION,1);
		setenv("REQUEST_METHOD",coap_code_to_cstr(smcp_inbound_get_packet()->code),1);
		setenv("REQUEST_URI",smcp_inbound_get_path(path,2),1);
		setenv("GATEWAY_INTERFACE","CGI/1.1",1);
		setenv("SERVER_PROTOCOL","CoAP/1.0",1);

		setenv("REMOTE_ADDR","",1);
		setenv("REMOTE_PORT","",1);
		setenv("SERVER_NAME","",1);
		setenv("SERVER_ADDR","",1);
		setenv("SERVER_PORT","",1);

		if(0==strncmp(path,getenv("SCRIPT_NAME"),strlen(getenv("SCRIPT_NAME")))) {
			setenv("PATH_INFO",path+strlen(getenv("SCRIPT_NAME")),1);
		}

//		fprintf(stderr,"CHILD: About to execute \"%s\" using shell \"%s\"\n",node->cmd,node->shell);
//		fflush(stderr);

		execl(node->shell,node->shell,"-c",node->cmd,NULL);

		fprintf(stderr,"CHILD: Failed to execute \"%s\" using shell \"%s\"\n",node->cmd,node->shell);

		// We should never get here...
		abort();
	}

	if(ret->pid<0) {
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

smcp_status_t
cgi_node_async_resend_response(void* context) {
	smcp_status_t ret = 0;
	cgi_node_request_t request = context;
	size_t block_len = (1<<((request->block2&0x7)+4));
	size_t max_len;

//	printf("Resending async response. . .\n");

	ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(ret,bail);

	ret = smcp_outbound_set_async_response(&request->async_response);
	require_noerr(ret,bail);

//	ret = smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
//	require_noerr(ret,bail);

	if(request->block1!=BLOCK_OPTION_UNSPECIFIED) {
		ret = smcp_outbound_add_option_uint(COAP_OPTION_BLOCK1,request->block1);
		require_noerr(ret,bail);
	}

	if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK) {
		if(request->stdout_buffer_len>block_len || request->fd_cmd_stdout>=0 || ((request->block2>>4)!=0)) {
			if(request->stdout_buffer_len>block_len || request->fd_cmd_stdout>=0)
				request->block2 |= (1<<3);
			else
				request->block2 &= ~(1<<3);
			ret = smcp_outbound_add_option_uint(COAP_OPTION_BLOCK2,request->block2);
			require_noerr(ret,bail);
		}

		char *content = smcp_outbound_get_content_ptr(&max_len);
		require_noerr(ret,bail);

		memcpy(content,request->stdout_buffer,MIN(request->stdout_buffer_len,block_len));

		ret = smcp_outbound_set_content_len(MIN(request->stdout_buffer_len,block_len));
		require_noerr(ret,bail);
	}

	ret = smcp_outbound_send();
	require_noerr(ret,bail);

bail:
	return ret;
}

smcp_status_t
cgi_node_request_pop_bytes_from_stdin(cgi_node_request_t request, int count) {
	request->stdin_buffer_len-=count;
	memmove(request->stdin_buffer,request->stdin_buffer+count,request->stdin_buffer_len);
	return SMCP_STATUS_OK;
}

smcp_status_t
cgi_node_request_pop_bytes_from_stdout(cgi_node_request_t request, int count) {
	//fprintf(stderr,"pushing %d bytes from stdout buffer\n",count);
	if((signed)request->stdout_buffer_len>count) {
		request->stdout_buffer_len-=count;
		memmove(request->stdout_buffer,request->stdout_buffer+count,request->stdout_buffer_len);
	} else {
		request->stdout_buffer_len = 0;
	}
	return SMCP_STATUS_OK;
}

smcp_status_t
cgi_node_async_ack_handler(int statuscode, void* context) {
	smcp_status_t ret = SMCP_STATUS_OK;
	cgi_node_request_t request = context;
	cgi_node_t node = (cgi_node_t)smcp_get_current_instance(); // TODO: WTF!!?!!!

//	printf("Finished sending async response.\n");


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
smcp_status_t
cgi_node_send_next_block(cgi_node_t node,cgi_node_request_t request) {
	smcp_status_t ret = 0;

	// If we are currently asynchronous, go ahead and send an asynchronous response.
	// Otherwise, we don't have much to do: We will just go ahead and send
	// the rest of the data at the next query.

	// TODO: Writeme!

	smcp_transaction_t transaction = smcp_transaction_init(
		request->transaction,
		0,
		&cgi_node_async_resend_response,
		&cgi_node_async_ack_handler,
		(void*)request
	);
	if(!transaction) {
		ret = SMCP_STATUS_MALLOC_FAILURE;
		goto bail;
	}

	ret = smcp_transaction_begin(
		node->interface,
		transaction,
		30*MSEC_PER_SEC
	);
	if(ret) {
		smcp_transaction_end(smcp_get_current_instance(),transaction);
		goto bail;
	}


bail:
	return ret;
}

smcp_status_t
cgi_node_request_change_state(cgi_node_t node, cgi_node_request_t request, cgi_node_state_t new_state) {
	// TODO: Possibly do more later...?

	//printf("STATE CHANGE: %d -> %d\n",request->state,new_state);


	if(request->state == new_state) {
		// Same state, do nothing.
	} else

	if(request->state == CGI_NODE_STATE_INACTIVE
		&& new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
	) {
	} else if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
		&& new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD
	) {
		smcp_start_async_response(&request->async_response, 0);
	} else if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD
		&& new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
	) {
		cgi_node_send_next_block(node,request);
	} else if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
		&& new_state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
	) {
		if(request->transaction) {
			smcp_transaction_end(smcp_get_current_instance(),request->transaction);
			request->transaction = NULL;
		}
	} else

	if( (request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ || request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ)
		&& new_state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD
	) {
		if(!request->stdin_buffer_len &&  request->fd_cmd_stdin>=0) {
			close(request->fd_cmd_stdin);
			request->fd_cmd_stdin = -1;
		}
		smcp_start_async_response(&request->async_response, 0);
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
			smcp_transaction_end(smcp_get_current_instance(),request->transaction);
			request->transaction = NULL;
		}
	} else if(new_state == CGI_NODE_STATE_FINISHED) {
		if(request->transaction) {
			smcp_transaction_end(smcp_get_current_instance(),request->transaction);
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
//		printf("BAD STATE CHANGE: %d -> %d\n",request->state,new_state);
		abort();
	}

	request->state = new_state;

	return SMCP_STATUS_OK;
}



smcp_status_t
cgi_node_request_handler(
	cgi_node_t		node
) {
	smcp_status_t ret = 0;
	cgi_node_request_t request = NULL;
	uint32_t block2_option = BLOCK_OPTION_DEFAULT;
	uint32_t block1_option = BLOCK_OPTION_UNSPECIFIED;
	smcp_method_t	method = smcp_inbound_get_code();

	require(node,bail);

	node->interface = smcp_get_current_instance();

	if(method==COAP_METHOD_GET) {
		ret = 0;
	}

	require_noerr(ret,bail);

	{
		const uint8_t* value;
		size_t value_len;
		coap_option_key_t key;
		while((key=smcp_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
			if(key == COAP_OPTION_BLOCK2) {
				uint8_t i;
				block2_option = 0;
				for(i = 0; i < value_len; i++)
					block2_option = (block2_option << 8) + value[i];
			}
			if(key == COAP_OPTION_BLOCK1) {
				uint8_t i;
				block1_option = 0;
				for(i = 0; i < value_len; i++)
					block1_option = (block1_option << 8) + value[i];
			}
		}
	}


	// Make sure this is a supported method.
	switch(method) {
		case COAP_METHOD_GET:
		case COAP_METHOD_PUT:
		case COAP_METHOD_POST:
		case COAP_METHOD_DELETE:
			break;
		default:
			ret = SMCP_STATUS_NOT_IMPLEMENTED;
			goto bail;
			break;
	}

	request = cgi_node_get_associated_request(node);

	if(!request) {
		// Possibly new request.
		// Assume new for now, but we may need to do additional checks.

		// We don't support non-zero block indexes on the first packet.
		require_action((block2_option>>4)==0,bail,ret=SMCP_STATUS_INVALID_ARGUMENT);

		request = cgi_node_create_request(node);
		require_action(request!=NULL,bail,ret = SMCP_STATUS_FAILURE);
		request->block2 = block2_option;

	}

	require(request,bail);

	if(	request->state==CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
		|| request->state==CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
	) {
		if(request->state==CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK) {
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_REQ
			);
		}

		if(smcp_inbound_get_content_len()) {
			request->stdin_buffer_len += smcp_inbound_get_content_len();
			request->stdin_buffer = realloc(request->stdin_buffer,request->stdin_buffer_len);
			// TODO: We should look at the block1 header to make sure it makes sense!
			// This could be a duplicate or it could be *ahead* of where we are. We
			// must catch these cases in the future!
			if(request->stdin_buffer) {
				memcpy(
					request->stdin_buffer+request->stdin_buffer_len - smcp_inbound_get_content_len(),
					smcp_inbound_get_content_ptr(),
					smcp_inbound_get_content_len()
				);
			} else {
				ret = SMCP_STATUS_MALLOC_FAILURE;
				goto bail;
			}
		}

		if(block1_option==0xFFFFFFFF || (0==(block1_option&0x4))) {
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
	} else if(request->state==CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD) {
		// We should not get a request at this point in the state machine.
		if(smcp_inbound_is_dupe()) {
			smcp_outbound_begin_response(COAP_CODE_EMPTY);
			smcp_outbound_send();
			ret = SMCP_STATUS_OK;
		} else {
			ret = SMCP_STATUS_FAILURE;
		}
	} else if(	request->state==CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ
				|| request->state==CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK
				|| request->state==CGI_NODE_STATE_FINISHED
	) {
		// Ongoing request. Handle it.
		uint32_t block2_start = (block2_option>>4) * (1<<((block2_option&0x7)+4));
		uint32_t block2_stop = block2_start + (1<<((block2_option&0x7)+4));

		if(	request->block2!=BLOCK_OPTION_UNSPECIFIED
			&& block2_start < (request->block2>>4) * (1<<((request->block2&0x7)+4))
		) {
				// Old Dupe?
				smcp_outbound_drop();
				ret = SMCP_STATUS_DUPE;
				goto bail;
		}

		if(request->state==CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK) {
			// OK, we need to clear out the previous stuff.
			if(block2_stop != (request->block2>>4) * (1<<((request->block2&0x7)+4))) {
				// Looks like the sender skipped some blocks.
				// Hmm. This isn't good.
				ret = SMCP_STATUS_FAILURE;
				goto bail;
			}

			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_REQ
			);
		} else if(block2_option != request->block2) {
			// TODO: check to make sure this is valid!
			ret = cgi_node_request_pop_bytes_from_stdout(request,(1<<((request->block2&0x7)+4)));
			require_noerr(ret,bail);
		}

		request->block2 = block2_option;

		size_t block_len = (1<<((request->block2&0x7)+4));

		if(request->stdout_buffer_len>=block_len || request->fd_cmd_stdout<=-1) {
			// We have data!
			size_t max_len;

			ret = smcp_outbound_begin_response(COAP_RESULT_205_CONTENT);
			require_noerr(ret,bail);

//			ret = smcp_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
//			require_noerr(ret,bail);

			if(request->stdout_buffer_len>block_len || request->fd_cmd_stdout>=0) {
				ret = smcp_outbound_add_option_uint(COAP_OPTION_BLOCK2,request->block2);
				require_noerr(ret,bail);
			}

			char *content = smcp_outbound_get_content_ptr(&max_len);
			require_noerr(ret,bail);

			memcpy(content,request->stdout_buffer,MIN(request->stdout_buffer_len,block_len));

			ret = smcp_outbound_set_content_len(MIN(request->stdout_buffer_len,block_len));
			require_noerr(ret,bail);

			ret = smcp_outbound_send();
			require_noerr(ret,bail);

			if(request->fd_cmd_stdout<0 && request->stdout_buffer_len<=block_len) {
				ret = cgi_node_request_change_state(
					node,
					request,
					CGI_NODE_STATE_FINISHED
				);
			}

		} else
		if(request->fd_cmd_stdout>=0) {
			// Not enough data yet.
			ret = cgi_node_request_change_state(
				node,
				request,
				CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD
			);
		}
	} else if(request->state==CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD) {
		// We should not get a request at this point in the state machine.
		if(smcp_inbound_is_dupe()) {
			smcp_outbound_begin_response(COAP_CODE_EMPTY);
			smcp_outbound_send();
			ret = SMCP_STATUS_OK;
		} else {
			ret = SMCP_STATUS_FAILURE;
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

	ret->node.finalize = (void (*)(smcp_node_t)) &cgi_node_dealloc;
	return ret;
}

cgi_node_t
cgi_node_init(
	cgi_node_t	self,
	smcp_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	int i;

	require(cmd!=NULL, bail);
	require(cmd[0]!=0, bail);
	require(name!=NULL, bail);
	require(self || (self = cgi_node_alloc()), bail);

	require(smcp_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	((smcp_node_t)&self->node)->request_handler = (void*)&cgi_node_request_handler;
	self->cmd = strdup(cmd);
	self->shell = strdup("/bin/sh");

	for(i=0;i<CGI_NODE_MAX_REQUESTS;i++) {
		self->requests[i].fd_cmd_stdin = -1;
		self->requests[i].fd_cmd_stdout = -1;
	}

bail:
	return self;
}

smcp_status_t
cgi_node_update_fdset(
	cgi_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *max_fd,
	cms_t *timeout
) {
	int i;
	for(i=0;i<CGI_NODE_MAX_REQUESTS;i++) {
		cgi_node_request_t request = &self->requests[i];

		if(request->state<=CGI_NODE_STATE_FINISHED)
			continue;

		if(	request->stdin_buffer_len
			&& request->fd_cmd_stdin >= 0
			&& write_fd_set
		) {
			//printf("Adding FD %d to write set\n",request->fd_cmd_stdin);
			FD_SET(request->fd_cmd_stdin,write_fd_set);
			if(error_fd_set)
				FD_SET(request->fd_cmd_stdin,error_fd_set);
			if(max_fd)
				*max_fd = MAX(*max_fd,request->fd_cmd_stdin);
		}

		if(	request->fd_cmd_stdout >= 0
			&& request->stdout_buffer_len<(1<<((request->block2&0x7)+4))
			&& read_fd_set
		) {
			//printf("Adding FD %d to read set\n",request->fd_cmd_stdout);
			FD_SET(request->fd_cmd_stdout,read_fd_set);
			if(error_fd_set)
				FD_SET(request->fd_cmd_stdout,error_fd_set);
			if(max_fd)
				*max_fd = MAX(*max_fd,request->fd_cmd_stdout);
		}

		if(timeout && request->expiration) {
			*timeout = MIN(*timeout,MAX(0,request->expiration-time(NULL) ));
		}

	}
	return SMCP_STATUS_OK;
}

smcp_status_t
cgi_node_process(cgi_node_t self) {
	int i;
	fd_set rd_set, wr_set, er_set;
	int max_fd = -1;
	struct timeval t = {};
	FD_ZERO(&rd_set);
	FD_ZERO(&wr_set);
	FD_ZERO(&er_set);

	cgi_node_update_fdset(self,&rd_set,&wr_set,&er_set,&max_fd,NULL);

	if(select(max_fd+1,&rd_set,&wr_set,&er_set,&t)>0) {
		for(i=0;i<CGI_NODE_MAX_REQUESTS;i++) {
			cgi_node_request_t request = &self->requests[i];
			if(request->state<=CGI_NODE_STATE_FINISHED)
				continue;

			if(request->expiration<time(NULL)) {
				request->expiration = 0;
				cgi_node_request_change_state(
					self,
					request,
					CGI_NODE_STATE_FINISHED
				);
			}

			//printf("Request %p, stdin_fd=%d, stdout_fd=%d\n",request,request->fd_cmd_stdin,request->fd_cmd_stdout);
			errno = 0;

			if(request->stdin_buffer_len && request->fd_cmd_stdin>=0 && (FD_ISSET(request->fd_cmd_stdin,&wr_set)||FD_ISSET(request->fd_cmd_stdin,&er_set))) {
				// Ready to send data to command
				int bytes_written = write(request->fd_cmd_stdin, request->stdin_buffer, request->stdin_buffer_len);
				//printf("WROTE %d BYTES TO FD_CMD_STDIN\n",bytes_written);
				if(bytes_written<0 || errno || FD_ISSET(request->fd_cmd_stdin,&er_set)) {
					if(errno!=EPIPE)
						syslog(LOG_ERR,"Error on write, %s (%d)",strerror(errno),errno);
					close(request->fd_cmd_stdin);
					request->fd_cmd_stdin = -1;
				} else if((size_t)bytes_written==request->stdin_buffer_len) {
					request->stdin_buffer_len = 0;
				} else {
					request->stdin_buffer_len-=bytes_written;
					memmove(request->stdin_buffer,request->stdin_buffer+bytes_written,request->stdin_buffer_len);
				}
			}
			if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_FD) {
				if(request->stdin_buffer_len==0 || request->fd_cmd_stdin<0) {
					cgi_node_request_change_state(
						self,
						request,
						CGI_NODE_STATE_ACTIVE_BLOCK1_WAIT_ACK
					);
				}
			}

			errno = 0;
			if(request->fd_cmd_stdout>=0 && (FD_ISSET(request->fd_cmd_stdout,&rd_set)||FD_ISSET(request->fd_cmd_stdout,&er_set))) {
				// Data is pending from command
				int bytes_read = (1<<((request->block2&0x7)+4))*2;
				request->stdout_buffer = realloc(request->stdout_buffer,request->stdout_buffer_len+bytes_read);
				if(!request->stdout_buffer)
					return SMCP_STATUS_MALLOC_FAILURE;
				bytes_read = read(request->fd_cmd_stdout, request->stdout_buffer+request->stdout_buffer_len, bytes_read);

				if(bytes_read<=0 || errno || FD_ISSET(request->fd_cmd_stdout,&er_set)) {
					if(errno && errno!=EPIPE)
						syslog(LOG_ERR,"Error on read, %s (%d)",strerror(errno),errno);
					close(request->fd_cmd_stdout);
					request->fd_cmd_stdout = -1;
				} else {
					//printf("READ %d BYTES FROM FD_CMD_STDOUT\n",bytes_read);
					request->stdout_buffer_len += bytes_read;
				}
			}
			if(request->state == CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_FD) {
				if(!request->stdin_buffer_len &&  request->fd_cmd_stdin>=0) {
					close(request->fd_cmd_stdin);
					request->fd_cmd_stdin = -1;
				}
				if(request->stdout_buffer_len>=(1<<((request->block2&0x7)+4)) || request->fd_cmd_stdout<0) {
					cgi_node_request_change_state(
						self,
						request,
						CGI_NODE_STATE_ACTIVE_BLOCK2_WAIT_ACK
					);
				}
			}
		}
	} else {
//		if(max_fd>-1)printf("...\n");
	}
	return SMCP_STATUS_OK;
}



extern smcp_status_t
SMCPD_module__cgi_node_process(cgi_node_t self);

extern smcp_status_t
SMCPD_module__cgi_node_update_fdset(
	cgi_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *max_fd,
	cms_t *timeout
);

extern cgi_node_t
SMCPD_module__cgi_node_init(
	cgi_node_t	self,
	smcp_node_t			parent,
	const char*			name,
	const char*			cmd
);

smcp_status_t
SMCPD_module__cgi_node_process(cgi_node_t self) {
	return cgi_node_process(self);
}

smcp_status_t
SMCPD_module__cgi_node_update_fdset(
	cgi_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *max_fd,
	cms_t *timeout
) {
	return cgi_node_update_fdset(self, read_fd_set, write_fd_set, error_fd_set, max_fd, timeout);
}

cgi_node_t
SMCPD_module__cgi_node_init(
	cgi_node_t	self,
	smcp_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	return cgi_node_init(self, parent, name, cmd);
}
