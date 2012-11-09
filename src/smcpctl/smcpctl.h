/*
 *  smcpctl.h
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 10/8/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#ifndef __SMCPCTL_H__
#define __SMCPCTL_H__ 1

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <smcp/smcp.h>

#define ERRORCODE_OK            (0)
#define ERRORCODE_HELP          (1)
#define ERRORCODE_BADARG        (2)
#define ERRORCODE_NOCOMMAND     (3)
#define ERRORCODE_UNKNOWN       (4)
#define ERRORCODE_BADCOMMAND    (5)
#define ERRORCODE_NOREADLINE    (6)
#define ERRORCODE_QUIT          (7)
#define ERRORCODE_INTERRUPT     (8)
#define ERRORCODE_TIMEOUT       (9)
#define ERRORCODE_COAP_ERROR    (10)


#define ERRORCODE_INPROGRESS    (127)

extern int exec_command(
	smcp_t smcp, int argc, char * argv[]);

extern bool show_headers;

#endif // __SMCPCTL_H__
