/*!	@file smcp-groups.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Multicast Group Support (RFC7390)
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

#ifndef __SMCP_GROUPS_H__
#define __SMCP_GROUPS_H__ 1

#include <libnyoci/libnyoci.h>
#include <libnyociextra/libnyociextra.h>

__BEGIN_DECLS

/*!	@addtogroup smcp-extras
**	@{
*/

/*!	@defgroup smcp-groups Multicast Groups Subsystem
**	@{
**
*/

#if SMCP_CONF_MAX_GROUPS

struct smcp_group_mgr_s;
typedef struct smcp_group_mgr_s *smcp_group_mgr_t;

struct smcp_group_s;
typedef struct smcp_group_s *smcp_group_t;

struct smcp_group_s {
	struct nyoci_var_handler_s var_handler;

	char fqdn[128]; // TODO: make sure FQDN length is appropriate
	nyoci_sockaddr_t addr;

	uint8_t index;
	bool stable:1;
	bool enabled:1;
	bool in_use:1;
};

struct smcp_group_mgr_s {
	struct nyoci_observable_s observable;
	struct smcp_group_s group_table[SMCP_CONF_MAX_GROUPS];

#if !NYOCI_SINGLETON
	nyoci_t nyoci_instance;
#endif

	// This function pointer should commit all stable
	// groups to non-volatile memory. When the app starts up,
	// it should retrieve those groupss and recreate them.
	void (*commit_stable_groups)(void* context, smcp_group_mgr_t mgr);
	void *context;
};

NYOCI_API_EXTERN smcp_group_mgr_t smcp_group_mgr_init(
	smcp_group_mgr_t self,
	nyoci_t nyoci_instance
);

NYOCI_API_EXTERN nyoci_status_t smcp_group_mgr_request_handler(
	smcp_group_mgr_t self
);

NYOCI_API_EXTERN smcp_group_t smcp_group_mgr_new_group(
	smcp_group_mgr_t self,
	const char* fqdn,
	const nyoci_sockaddr_t* addr,
	uint8_t i
);

NYOCI_API_EXTERN smcp_group_t smcp_group_mgr_groups_begin(
	smcp_group_mgr_t self
);

NYOCI_API_EXTERN smcp_group_t smcp_group_mgr_groups_next(
	smcp_group_mgr_t self,
	smcp_group_t prev
);

NYOCI_API_EXTERN uint8_t smcp_group_get_id(smcp_group_t self);

NYOCI_API_EXTERN bool smcp_group_get_stable(smcp_group_t self);

NYOCI_API_EXTERN nyoci_status_t smcp_group_set_stable(smcp_group_t self, bool x);

NYOCI_API_EXTERN bool smcp_group_get_enabled(smcp_group_t self);

NYOCI_API_EXTERN nyoci_status_t smcp_group_set_enabled(smcp_group_t self, bool x);

NYOCI_API_EXTERN const char* smcp_group_get_fqdn(smcp_group_t self);

NYOCI_API_EXTERN const nyoci_sockaddr_t* smcp_group_get_addr(smcp_group_t self);

NYOCI_API_EXTERN void smcp_group_mgr_delete(
	smcp_group_mgr_t self,
	smcp_group_t group
);

#endif // SMCP_CONF_MAX_GROUPS > 0

/*!	@} */
/*!	@} */

__END_DECLS

#endif //__SMCP_GROUP_H__
