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

#define ERRORCODE_OK            (0)
#define ERRORCODE_HELP          (1)
#define ERRORCODE_BADARG        (2)
#define ERRORCODE_NOCOMMAND     (3)
#define ERRORCODE_UNKNOWN       (4)
#define ERRORCODE_BADCOMMAND    (5)
#define ERRORCODE_NOREADLINE    (6)
#define ERRORCODE_QUIT          (7)
#define ERRORCODE_INTERRUPT     (8)


#define ERRORCODE_INPROGRESS    (127)

extern int exec_command(
	smcp_daemon_t smcp_daemon, int argc, char * argv[]);

extern bool show_headers;

#endif // __SMCPCTL_H__
