/*	@file ud-var-node.h
**	@brief Unix-Domain Variable Node Header
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


#ifndef ud_var_node_h
#define ud_var_node_h

#include <libnyoci/libnyoci.h>

struct ud_var_node_s;

typedef struct ud_var_node_s* ud_var_node_t;

extern nyoci_status_t
SMCPD_module__ud_var_node_process(ud_var_node_t self);

extern nyoci_status_t
SMCPD_module__ud_var_node_update_fdset(
	ud_var_node_t self,
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	nyoci_cms_t *timeout
);

extern ud_var_node_t
SMCPD_module__ud_var_node_init(
	ud_var_node_t	self,
	nyoci_node_t			parent,
	const char*			name,
	const char*			cmd
);


#endif /* ud_var_node_h */
