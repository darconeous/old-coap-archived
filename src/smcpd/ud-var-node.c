/*	@file ud-var-node.c
**	@brief Unix-Domain Variable Node
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

#define DEBUG 1
#define VERBOSE_DEBUG 1

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#include "smcp/assert-macros.h"

#include <stdio.h>
#include <libnyoci/libnyoci.h>
#include <libnyociextra/libnyociextra.h>

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "ud-var-node.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <libnyoci/fasthash.h>
#include <libnyoci/url-helpers.h>

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

#ifndef UD_VAR_NODE_MAX_REQUESTS
#define UD_VAR_NODE_MAX_REQUESTS		(20)
#endif

struct ud_var_node_s {
	struct nyoci_node_s node;
	struct nyoci_observable_s observable;
	int fd;
	const char* path;
	uint32_t last_etag;
	nyoci_timestamp_t next_refresh;
	nyoci_cms_t refresh_period;
	nyoci_timestamp_t next_poll;
	nyoci_cms_t poll_period;
};

coap_ssize_t
ud_var_node_get_content(
	ud_var_node_t self,
	char* buffer_ptr,
	coap_size_t buffer_len
) {
	coap_ssize_t ret = 0;
	ssize_t lseek_ret;

	lseek_ret = lseek(self->fd, 0, SEEK_SET);

	check_string(lseek_ret >= 0, strerror(errno));

	ret = (coap_ssize_t)read(self->fd, buffer_ptr, buffer_len);

	require_string(ret >= 0, bail, strerror(errno));

bail:
	return ret;
}

uint32_t
ud_var_node_calc_etag(
	const char* buffer_ptr,
	coap_size_t buffer_len
) {
	struct fasthash_state_s state;

	fasthash_start(&state, 0x12341234);

	while (buffer_len > 255) {
		fasthash_feed(&state, (const uint8_t*)buffer_ptr, 255);
		buffer_len -= 255;
		buffer_ptr += 255;
	}
	fasthash_feed(&state, (const uint8_t*)buffer_ptr, (uint8_t)buffer_len);

	return fasthash_finish_uint32(&state);
}

nyoci_status_t
ud_var_node_request_handler(
	ud_var_node_t self
) {
	nyoci_status_t ret = NYOCI_STATUS_NOT_ALLOWED;
	coap_code_t method = nyoci_inbound_get_code();
	coap_content_type_t accept_type = COAP_CONTENT_TYPE_TEXT_PLAIN;
	uint8_t buffer[256];
	coap_ssize_t buffer_len = 0;
	int write_fd = -1;
	uint32_t value_etag;

	buffer_len = ud_var_node_get_content(self, (char*)buffer, sizeof(buffer));
	require_action_string(buffer_len >= 0, bail, ret = NYOCI_STATUS_ERRNO, strerror(errno));
	value_etag = ud_var_node_calc_etag((const char*)buffer, buffer_len);

	{
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;
		while ((key = nyoci_inbound_next_option(&value, &value_len)) != COAP_OPTION_INVALID) {
			if (key == COAP_OPTION_ACCEPT) {
				accept_type = (coap_content_type_t)coap_decode_uint32(value, (uint8_t)value_len);

			} else if (key == COAP_OPTION_CONTENT_TYPE) {
				accept_type = (coap_content_type_t)coap_decode_uint32(value, (uint8_t)value_len);

			} else {
				require_action(key != COAP_OPTION_URI_PATH, bail, ret = NYOCI_STATUS_NOT_FOUND);

				require_action(!COAP_OPTION_IS_CRITICAL(key), bail, ret = NYOCI_STATUS_BAD_OPTION);
			}
		}
	}

	// Make sure this is a supported method.
	switch (method) {
	case COAP_METHOD_GET:
	case COAP_METHOD_PUT:
	case COAP_METHOD_POST:
		break;

	default:
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
		goto bail;
		break;
	}

	switch (accept_type) {
	case NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED:
	case COAP_CONTENT_TYPE_TEXT_PLAIN:
		break;

	default:
		ret = NYOCI_STATUS_UNSUPPORTED_MEDIA_TYPE;
		goto bail;
	}

	if ( (COAP_METHOD_PUT == method)
	  || (COAP_METHOD_POST == method && !nyoci_inbound_is_dupe())
	) {
		const char* content_ptr = nyoci_inbound_get_content_ptr();
		coap_size_t content_len = nyoci_inbound_get_content_len();
		ssize_t bytes_written = 0;

		write_fd = open(self->path, O_WRONLY | O_NONBLOCK);

		require_action_string(write_fd >= 0, bail, ret = NYOCI_STATUS_ERRNO, strerror(errno));

		bytes_written = write(write_fd, content_ptr, content_len);

		require_action_string(bytes_written >= 0, bail, ret = NYOCI_STATUS_ERRNO, strerror(errno));

		// Must close to commit the change
		close(write_fd);
		write_fd = -1;

		// Refresh the value
		buffer_len = ud_var_node_get_content(self, (char*)buffer, sizeof(buffer));
		require_action_string(buffer_len >= 0, bail, ret = NYOCI_STATUS_ERRNO, strerror(errno));
		value_etag = ud_var_node_calc_etag((const char*)buffer, buffer_len);
	}


	if (COAP_METHOD_GET == method) {
		ret = nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);
	} else {
		if (nyoci_inbound_is_multicast() || nyoci_inbound_is_fake()) {
			ret = NYOCI_STATUS_OK;
			goto bail;
		}
		ret = nyoci_outbound_begin_response(COAP_RESULT_204_CHANGED);
	}

	require_noerr(ret, bail);

	ret = nyoci_outbound_add_option_uint(COAP_OPTION_ETAG, value_etag);

	require_noerr(ret, bail);

	ret = nyoci_observable_update(&self->observable, 0);

	check_noerr_string(ret, nyoci_status_to_cstr(ret));

	ret = nyoci_outbound_add_option_uint(
		COAP_OPTION_CONTENT_TYPE,
		accept_type
	);

	require_noerr(ret, bail);

	ret = nyoci_outbound_add_option_uint(COAP_OPTION_MAX_AGE, (self->refresh_period)/MSEC_PER_SEC + 1);

	require_noerr(ret, bail);

	if (NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED == accept_type) {
		char* out_content_ptr;
		coap_size_t out_content_max_len;
		int len_encoded;

		out_content_ptr = nyoci_outbound_get_content_ptr(&out_content_max_len);

		require(out_content_ptr != NULL, bail);

		*out_content_ptr++ = 'v';
		*out_content_ptr++ = '=';
		out_content_max_len -= 2;

		buffer[buffer_len] = 0;
		len_encoded = url_encode_cstr(out_content_ptr, (char*)buffer, out_content_max_len);

		out_content_ptr += len_encoded;
		out_content_max_len -= len_encoded;

		ret = nyoci_outbound_set_content_len((coap_size_t)(len_encoded + 2));
// TODO: Add JSON

	} else {

		ret = nyoci_outbound_append_content((char*)buffer, (coap_size_t)buffer_len);
	}

	require_noerr(ret, bail);

	// Send the response we hae created, passing the return value
	// to our caller.
	ret = nyoci_outbound_send();

	require_noerr(ret, bail);

bail:

	if (write_fd >= 0) {
		close(write_fd);
	}

	return ret;
}

void
ud_var_node_dealloc(ud_var_node_t x) {
	close(x->fd);
	free((void*)x->path);
	free(x);
}

ud_var_node_t
ud_var_node_alloc() {
	ud_var_node_t ret = (ud_var_node_t)calloc(sizeof(struct ud_var_node_s), 1);

	ret->node.finalize = (void (*)(nyoci_node_t)) &ud_var_node_dealloc;
	return ret;
}

ud_var_node_t
ud_var_node_init(
	ud_var_node_t self,
	nyoci_node_t parent,
	const char* name,
	const char* path
) {
	int fd = -1;

	NYOCI_LIBRARY_VERSION_CHECK();

	require(path != NULL, bail);
	require(path[0] != 0, bail);
	require(name != NULL, bail);

	fd = open(path, O_RDONLY | O_NONBLOCK);

	require(fd >= 0, bail);
	require(self || (self = ud_var_node_alloc()), bail);
	require(nyoci_node_init(
			&self->node,
			(void*)parent,
			name
	), bail);

	((nyoci_node_t)&self->node)->request_handler = (void*)&ud_var_node_request_handler;

	self->path = strdup(path);
	self->fd = fd;
	self->node.is_observable = 1;

	// TODO: Figure out how to set these from the configuration.
	self->refresh_period = 30*MSEC_PER_SEC;
	self->poll_period = MSEC_PER_SEC/30;

	fd = -1;

bail:
	if (fd >= 0) {
		close(fd);
	}
	return self;
}

nyoci_status_t
ud_var_node_update_fdset(
	ud_var_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	nyoci_cms_t *timeout
) {
//	syslog(LOG_DEBUG, "ud_var_node_update_fdset: %d observers", nyoci_observable_observer_count(&self->observable, 0));

	if (nyoci_observable_observer_count(&self->observable, 0)) {

		if (error_fd_set) {
			FD_SET(self->fd, error_fd_set);
		}

		if (fd_count) {
			*fd_count = MAX(*fd_count, self->fd + 1);
		}

		if (timeout) {
			nyoci_cms_t next_refresh = nyoci_plat_timestamp_to_cms(self->next_refresh);
			nyoci_cms_t next_poll = nyoci_plat_timestamp_to_cms(self->next_poll);

			if (next_refresh > self->refresh_period) {
				next_refresh = self->refresh_period;
				self->next_refresh = nyoci_plat_cms_to_timestamp(next_refresh);
			}

			if (next_poll > self->poll_period) {
				next_poll = self->poll_period;
				self->next_poll = nyoci_plat_cms_to_timestamp(next_poll);
			}

			*timeout = MIN(*timeout, next_refresh);
			*timeout = MIN(*timeout, next_poll);
		}
	}

	return NYOCI_STATUS_OK;
}

nyoci_status_t
ud_var_node_process(ud_var_node_t self) {
	bool trigger_it = false;

//	syslog(LOG_DEBUG, "ud_var_node_process: %d observers", nyoci_observable_observer_count(&self->observable, 0));

	if (nyoci_observable_observer_count(&self->observable, 0)) {
		nyoci_cms_t next_refresh = nyoci_plat_timestamp_to_cms(self->next_refresh);
		nyoci_cms_t next_poll = nyoci_plat_timestamp_to_cms(self->next_poll);

		struct pollfd fdset[1];
		uint8_t flags = 0;

		if (next_refresh <= 0 || next_refresh > self->refresh_period) {
			trigger_it = true;
			flags = NYOCI_OBS_TRIGGER_FLAG_NO_INCREMENT;
		}

		fdset[0].fd = self->fd;
		fdset[0].events = POLLPRI|POLLERR;
		fdset[0].revents = 0;

		if (poll(fdset, 1, 0) > 0) {
			if ( ((fdset[0].revents & POLLPRI) == POLLPRI)
			  || ((fdset[0].revents & POLLIN)  == POLLERR)
			) {
				trigger_it = true;
				flags &= ~NYOCI_OBS_TRIGGER_FLAG_NO_INCREMENT;
			}
		}

		if (next_poll <= 0 || next_poll > self->poll_period) {
			uint8_t buffer[256];
			coap_ssize_t buffer_len = 0;
			uint32_t etag;

			self->next_poll = nyoci_plat_cms_to_timestamp(self->poll_period);

			buffer_len = ud_var_node_get_content(self, (char*)buffer, sizeof(buffer));

			check_string(buffer_len >= 0, strerror(errno));

			if (buffer_len >= 0) {
				etag = ud_var_node_calc_etag((const char*)buffer, buffer_len);

				if (etag != self->last_etag) {
					self->last_etag = etag;
					trigger_it = true;
				}
			}
		}

		if (trigger_it) {
			self->next_refresh = nyoci_plat_cms_to_timestamp(self->refresh_period);
			nyoci_observable_trigger(
				&self->observable,
				0,
				flags
			);
		}
	}
	return NYOCI_STATUS_OK;
}



nyoci_status_t
SMCPD_module__ud_var_node_process(ud_var_node_t self) {
	return ud_var_node_process(self);
}

nyoci_status_t
SMCPD_module__ud_var_node_update_fdset(
	ud_var_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	nyoci_cms_t *timeout
) {
	return ud_var_node_update_fdset(self, read_fd_set, write_fd_set, error_fd_set, fd_count, timeout);
}

ud_var_node_t
SMCPD_module__ud_var_node_init(
	ud_var_node_t	self,
	nyoci_node_t			parent,
	const char*			name,
	const char*			cmd
) {
	return ud_var_node_init(self, parent, name, cmd);
}
