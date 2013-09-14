/*	@file main.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@author Ilya Dmitrichenko <errordeveloper@gmail.com>
**
**	Copyright (C) 2011,2012 Robert Quattlebaum
**	Copyright (C) 2013 Ilya Dmitrichenko
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

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#define HAVE_FGETLN 0

#include <smcp/assert-macros.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <poll.h>
#include <sys/select.h>
#include <libgen.h>
#include <syslog.h>

#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>
//#include <smcp/smcp-pairing.h>
#include <missing/fgetln.h>
#include "help.h"

//#include "curl_proxy.h"

#if HAVE_DLFCN_H
#include <dlfcn.h>
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT  ((void*)0)
#endif
#ifndef RTLD_NEXT
#define RTLD_NEXT     ((void*)-1l)
#endif
#endif

#include <smcp/smcp-curl_proxy.h>

#define ERRORCODE_OK            (0)
#define ERRORCODE_HELP          (1)
#define ERRORCODE_BADARG        (2)
#define ERRORCODE_NOCOMMAND     (3)
#define ERRORCODE_UNKNOWN       (4)
#define ERRORCODE_BADCOMMAND    (5)
#define ERRORCODE_NOREADLINE    (6)
#define ERRORCODE_QUIT          (7)
#define ERRORCODE_BADCONFIG	(8)

#define ERRORCODE_INTERRUPT     (128+SIGINT)
#define ERRORCODE_SIGHUP	(128+SIGHUP)

#define strcaseequal(x,y)	(strcasecmp(x,y)==0)

static arg_list_item_t option_list[] = {
        { 'h', "help",	NULL, "Print Help"				},
        { 'd', "debug", NULL, "Enable debugging mode"	},
        { 'p', "port",	NULL, "Port number"				},
        { 0 }
};

static smcp_t smcp;
static struct smcp_node_s root_node;
static int gRet;

static const char* gProcessName = "foxy";
static const char* gPIDFilename = NULL;

static sig_t gPreviousHandlerForSIGINT;
static sig_t gPreviousHandlerForSIGTERM;

static void
signal_SIGINT(int sig) {
        gRet = ERRORCODE_INTERRUPT;
        syslog(LOG_NOTICE,"Caught SIGINT!");
        signal(SIGINT, gPreviousHandlerForSIGINT);
}

static void
signal_SIGTERM(int sig) {
        gRet = ERRORCODE_INTERRUPT;
        syslog(LOG_NOTICE,"Caught SIGTERM!");
        signal(SIGTERM, gPreviousHandlerForSIGTERM);
}

static void
signal_SIGHUP(int sig) {
        gRet = ERRORCODE_SIGHUP;
        syslog(LOG_NOTICE,"Caught SIGHUP!");
}

#define SMCPD_MAX_ASYNC_IO_MODULES	30
struct {
        smcp_node_t node;
        smcp_status_t (*update_fdset)(
                smcp_node_t node,
                fd_set *read_fd_set,
                fd_set *write_fd_set,
                fd_set *error_fd_set,
                int *max_fd,
                cms_t *timeout
        );
        smcp_status_t (*process)(smcp_node_t node);
} async_io_module[SMCPD_MAX_ASYNC_IO_MODULES];
int async_io_module_count;

smcp_status_t
smcpd_modules_update_fdset(
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *max_fd,
    cms_t *timeout
) {
        int i;
        for(i=0;i<async_io_module_count;i++) {
                if(async_io_module[i].update_fdset)
                        async_io_module[i].update_fdset(
                                async_io_module[i].node,
                                read_fd_set,
                                write_fd_set,
                                error_fd_set,
                                max_fd,
                                timeout
                        );
        }
        return SMCP_STATUS_OK;
}

smcp_status_t
smcpd_modules_process() {
        smcp_status_t status = 0;
        int i;
        for(i=0;i<async_io_module_count && !status;i++) {
                if(async_io_module[i].process)
                        status = async_io_module[i].process(async_io_module[i].node);
        }
        return status;
}

smcp_node_t foxy_make_node() {
        smcp_node_t ret = NULL;
        smcp_node_t (*init_func)(smcp_node_t self, smcp_node_t parent, const char* name, const char* argument) = NULL;
        smcp_status_t (*process_func)(smcp_node_t self) = NULL;
        smcp_status_t (*update_fdset_func)(
                smcp_node_t node,
                fd_set *read_fd_set,
                fd_set *write_fd_set,
                fd_set *error_fd_set,
                int *max_fd,
                cms_t *timeout
        ) = NULL;

        init_func = &smcp_curl_singleton_proxy_node_init;
        update_fdset_func = &smcp_curl_proxy_node_update_fdset;
        process_func = &smcp_curl_proxy_node_process;

        if(init_func) {
                ret = (*init_func)( NULL, &root_node, "proxy", NULL );
                if(!ret) {
                        syslog(LOG_WARNING,"Init method failed");
                }
        }

        if(ret && (process_func || update_fdset_func)) {
                async_io_module[async_io_module_count].node = ret;
                async_io_module[async_io_module_count].update_fdset = update_fdset_func;
                async_io_module[async_io_module_count].process = process_func;
                async_io_module_count++;
        }

        check_noerr(init_func);

        return ret;
}

int
main(
        int argc, char * argv[]
) {
        int i, debug_mode = 0;
        int port = 0;

        openlog(basename(argv[0]),LOG_PERROR|LOG_PID|LOG_CONS,LOG_DAEMON);

        gPreviousHandlerForSIGINT = signal(SIGINT, &signal_SIGINT);
        gPreviousHandlerForSIGTERM = signal(SIGINT, &signal_SIGTERM);
        signal(SIGHUP, &signal_SIGHUP);

        srandom(time(NULL));

        if(argc && argv[0][0])
                gProcessName = basename(argv[0]);

        BEGIN_LONG_ARGUMENTS(gRet)
        HANDLE_LONG_ARGUMENT("port") port = strtol(argv[++i], NULL, 0);
        HANDLE_LONG_ARGUMENT("debug") debug_mode++;
        HANDLE_LONG_ARGUMENT("help") {
                print_arg_list_help(
                        option_list,
                        argv[0],
                        "[options]"
                );
                gRet = ERRORCODE_HELP;
                goto bail;
        }
        BEGIN_SHORT_ARGUMENTS(gRet)
        HANDLE_SHORT_ARGUMENT('p') port = strtol(argv[++i], NULL, 0);
        HANDLE_SHORT_ARGUMENT('d') debug_mode++;
        HANDLE_SHORT_ARGUMENT2('h', '?') {
                print_arg_list_help(
                        option_list,
                        argv[0],
                        "[options]"
                );
                gRet = ERRORCODE_HELP;
                goto bail;
        }
        HANDLE_OTHER_ARGUMENT() {
                print_arg_list_help(
                        option_list,
                        argv[0],
                        "[options]"
                );
                gRet = ERRORCODE_HELP;
                goto bail;
        }
        END_ARGUMENTS

        syslog(LOG_NOTICE,"Starting foxy...");

        smcp = smcp_create(port);

        if(!smcp) {
                syslog(LOG_CRIT,"Unable to initialize SMCP instance.");
                gRet = ERRORCODE_UNKNOWN;
                goto bail;
        }

        // Set up the root node.
        smcp_node_init(&root_node,NULL,NULL);

        // Set up the node router.
        smcp_set_default_request_handler(smcp, &smcp_node_router_handler, &root_node);

        //smcp_set_proxy_url(smcp,getenv("COAP_PROXY_URL"));
        foxy_make_node();

        syslog(LOG_NOTICE,"Daemon started. Listening on port %d.",smcp_get_port(smcp));

        while(!gRet) {
                int fds_ready = 0, max_fd = -1;
                fd_set read_fd_set,write_fd_set,error_fd_set;
                long cms_timeout = 600000;
                struct timeval timeout = {};

                FD_ZERO(&read_fd_set);
                FD_ZERO(&write_fd_set);
                FD_ZERO(&error_fd_set);
                smcpd_modules_update_fdset(
                        &read_fd_set,
                        &write_fd_set,
                        &error_fd_set,
                        &max_fd,
                        &cms_timeout
                );

                cms_timeout = MIN(smcp_get_timeout(smcp),cms_timeout);
                max_fd = MAX(smcp_get_fd(smcp),max_fd);
                FD_SET(smcp_get_fd(smcp),&read_fd_set);
                FD_SET(smcp_get_fd(smcp),&error_fd_set);

                timeout.tv_sec = cms_timeout/1000;
                timeout.tv_usec = (cms_timeout%1000)*1000;

                fds_ready = select(max_fd+1,&read_fd_set,&write_fd_set,&error_fd_set,&timeout);
                if(fds_ready < 0 && errno!=EINTR) {
                        syslog(LOG_ERR,"select() errno=\"%s\" (%d)",strerror(errno),errno);
                        break;
                }

                smcp_process(smcp, 0);

                if(smcpd_modules_process()!=SMCP_STATUS_OK) {
                        syslog(LOG_ERR,"Module process error.");
                        gRet = ERRORCODE_UNKNOWN;
                }

                if(gRet == ERRORCODE_SIGHUP) {
                        gRet = 0;
                        /* read_configuration(smcp,config_file); */
                }
        }

bail:

        if(gRet == ERRORCODE_QUIT)
                gRet = 0;

        if(smcp) {
                syslog(LOG_NOTICE,"Stopping smcpd . . .");

                if(gPIDFilename)
                        unlink(gPIDFilename);

                smcp_release(smcp);

                syslog(LOG_NOTICE,"Stopped.");
        }
        return gRet;
}
