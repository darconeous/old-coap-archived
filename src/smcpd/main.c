/*	@file main.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#define HAVE_FGETLN 0

#include <smcp/assert-macros.h>

#include <smcp/smcp-internal.h>
#include <smcp/smcp-missing.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <poll.h>
#include <sys/select.h>
#include <libgen.h>
#include <syslog.h>

#include <smcp/smcp.h>
#include <smcp/smcp-node-router.h>
#include <missing/fgetln.h>
#include "help.h"

#if HAVE_DLFCN_H
#include <dlfcn.h>
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT	((void*)0)
#endif
#ifndef RTLD_NEXT
#define RTLD_NEXT		((void*)-1l)
#endif
#endif

#include "cgi-node.h"
#include "system-node.h"
#include "ud-var-node.h"
#include "pairing-node.h"

#if HAVE_LIBCURL
#include <smcp/smcp-curl_proxy.h>
#endif

#ifndef PREFIX
#define PREFIX "/usr/local/"
#endif

#ifndef ETC_PREFIX
#define ETC_PREFIX PREFIX"etc/"
#endif

#define ERRORCODE_OK            (0)
#define ERRORCODE_HELP          (1)
#define ERRORCODE_BADARG        (2)
#define ERRORCODE_NOCOMMAND     (3)
#define ERRORCODE_UNKNOWN       (4)
#define ERRORCODE_BADCOMMAND    (5)
#define ERRORCODE_NOREADLINE    (6)
#define ERRORCODE_QUIT          (7)
#define ERRORCODE_BADCONFIG		(8)

#define ERRORCODE_INTERRUPT     (128+SIGINT)
#define ERRORCODE_SIGHUP		(128+SIGHUP)

#define strcaseequal(x,y)	(strcasecmp(x,y)==0)

static arg_list_item_t option_list[] = {
	{ 'h', "help",	NULL, "Print Help"				},
	{ 'd', "debug", NULL, "Enable debugging mode"	},
	{ 'p', "port",	NULL, "Port number"				},
	{ 'c', "config",NULL, "Config File"				},
	{ 0 }
};

static smcp_t smcp;
static struct smcp_node_s root_node;
static int gRet;

static const char* gProcessName = "smcpd";
static const char* gPIDFilename = NULL;

static sig_t gPreviousHandlerForSIGINT;
static sig_t gPreviousHandlerForSIGTERM;

static void
signal_SIGINT(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	syslog(LOG_NOTICE,"Caught SIGINT!");
	signal(SIGINT, gPreviousHandlerForSIGINT);
	gPreviousHandlerForSIGINT = NULL;
}

static void
signal_SIGTERM(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	syslog(LOG_NOTICE,"Caught SIGTERM!");
	signal(SIGTERM, gPreviousHandlerForSIGTERM);
	gPreviousHandlerForSIGTERM = NULL;
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
		int *fd_count,
		smcp_cms_t *timeout
	);
	smcp_status_t (*process)(smcp_node_t node);
} async_io_module[SMCPD_MAX_ASYNC_IO_MODULES];
int async_io_module_count;

smcp_status_t
smcpd_modules_update_fdset(
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
    smcp_cms_t *timeout
) {
	int i;
	for(i=0;i<async_io_module_count;i++) {
		if(async_io_module[i].update_fdset)
			async_io_module[i].update_fdset(
				async_io_module[i].node,
				read_fd_set,
				write_fd_set,
				error_fd_set,
				fd_count,
				timeout
			);
	}
	return SMCP_STATUS_OK;
}

smcp_status_t
smcpd_modules_process()
{
	smcp_status_t status = 0;
	int i;
	for(i=0;i<async_io_module_count && !status;i++) {
		if(async_io_module[i].process) {
			status = async_io_module[i].process(async_io_module[i].node);
		}
	}
	return status;
}

smcp_node_t smcpd_make_node(const char* type, smcp_node_t parent, const char* name, const char* argument)
{
	smcp_node_t ret = NULL;

	typedef smcp_node_t (*init_func_t)(smcp_node_t self, smcp_node_t parent, const char* name, const char* argument);
	typedef smcp_status_t (*process_func_t)(smcp_node_t self);
	typedef smcp_status_t (*update_fdset_func_t)(
		smcp_node_t node,
		fd_set *read_fd_set,
		fd_set *write_fd_set,
		fd_set *error_fd_set,
		int *fd_count,
		smcp_cms_t *timeout
	);

	init_func_t init_func = NULL;
	process_func_t process_func = NULL;
	update_fdset_func_t update_fdset_func = NULL;


	syslog(LOG_INFO,"MAKE t=\"%s\" n=\"%s\" a=\"%s\"",type, name, argument);

	if(!type || strcaseequal(type,"node")) {
		init_func = (init_func_t)&smcp_node_init;
#if HAVE_LIBCURL
	} else if(strcaseequal(type,"curl_proxy")) {
		init_func = (init_func_t)&smcp_curl_proxy_node_init;
		update_fdset_func = (update_fdset_func_t)&smcp_curl_proxy_node_update_fdset;
		process_func = (process_func_t)&smcp_curl_proxy_node_process;
#endif
	} else if(strcaseequal(type,"system_node")) {
		init_func = (init_func_t)&SMCPD_module__system_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__system_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__system_node_process;
	} else if(strcaseequal(type,"cgi_node")) {
		init_func = (init_func_t)&SMCPD_module__cgi_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__cgi_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__cgi_node_process;
	} else if(strcaseequal(type,"ud_var_node")) {
		init_func = (init_func_t)&SMCPD_module__ud_var_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__ud_var_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__ud_var_node_process;
	} else if(strcaseequal(type,"pairing_node")) {
		init_func = (init_func_t)&SMCPD_module__pairing_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__pairing_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__pairing_node_process;
#if HAVE_DLFCN_H
	} else if(type) {
		char symbol_name[100];

		snprintf(symbol_name,sizeof(symbol_name),"SMCPD_module__%s_node_init",type);
		init_func = dlsym(RTLD_DEFAULT,symbol_name);
		if(!init_func) {
			snprintf(symbol_name,sizeof(symbol_name),"smcp_%s_node_init",type);
			init_func = dlsym(RTLD_DEFAULT,symbol_name);
		}

		snprintf(symbol_name,sizeof(symbol_name),"SMCPD_module__%s_node_update_fdset",type);
		update_fdset_func = dlsym(RTLD_DEFAULT,symbol_name);
		if(!update_fdset_func) {
			snprintf(symbol_name,sizeof(symbol_name),"smcp_%s_node_update_fdset",type);
			update_fdset_func = dlsym(RTLD_DEFAULT,symbol_name);
		}

		snprintf(symbol_name,sizeof(symbol_name),"SMCPD_module__%s_node_process",type);
		process_func = dlsym(RTLD_DEFAULT,symbol_name);
		if(!process_func) {
			snprintf(symbol_name,sizeof(symbol_name),"smcp_%s_node_process",type);
			process_func = dlsym(RTLD_DEFAULT,symbol_name);
		}
#endif
	}

	if (init_func) {
		ret = (*init_func)(
			NULL,
			parent,
			strdup(name),
			argument?strdup(argument):NULL
		);
		if (ret == NULL) {
			syslog(LOG_WARNING,"Init method failed for node type \"%s\"",type);
		}
	} else {
		syslog(LOG_NOTICE,"Can't find init method for node type \"%s\"",type);
	}

	if (ret && (process_func || update_fdset_func)) {
		async_io_module[async_io_module_count].node = ret;
		async_io_module[async_io_module_count].update_fdset = update_fdset_func;
		async_io_module[async_io_module_count].process = process_func;
		async_io_module_count++;
	}

	check(ret != NULL);

	return ret;
}

char*
get_next_arg(char *buf, char **rest) {
	char* ret = NULL;

	while(*buf && isspace(*buf)) buf++;

	if(!*buf || *buf == '#')
		goto bail;

	ret = buf;

	char quote_type = 0;
	char* write_iter = ret;

	while(*buf) {
		if(quote_type && *buf==quote_type) {
			quote_type = 0;
			buf++;
			continue;
		}
		if(*buf == '"' || *buf == '\'') {
			quote_type = *buf++;
			continue;
		}

		if(!quote_type && isspace(*buf)) {
			buf++;
			break;
		}

		if(buf[0]=='\\' && buf[1]) buf++;

		*write_iter++ = *buf++;
	}

	*write_iter = 0;

bail:
	if(rest)
		*rest = buf;
	return ret;
}

static int
strlinelen(const char* line) {
	int ret = 0;
	for(;line[0] && line[0]!='\n';line++,ret++);
	return ret;
}

static int
read_configuration(smcp_t smcp,const char* filename) {
	int ret = 1;
	syslog(LOG_INFO,"Reading configuration from \"%s\" . . .",filename);

	FILE* file = fopen(filename,"r");
	char* line = NULL;
	size_t line_len = 0;
	smcp_node_t node = &root_node;
	int line_number = 0;
	smcp_status_t status = 0;

	require(file!=NULL,bail);

	while(!feof(file) && (line=fgetln(file,&line_len))) {
		char *cmd = get_next_arg(line,&line);
		line_number++;
		if(!cmd) {
			continue;
		} else if(strcaseequal(cmd,"Port")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}

			if (smcp_plat_bind_to_port(smcp, SMCP_SESSION_TYPE_UDP, atoi(arg)) != SMCP_STATUS_OK) {
				syslog(LOG_ERR,"Unable to bind to port! \"%s\" (%d)",strerror(errno),errno);
			}


			if(smcp_plat_get_port(smcp)!=atoi(arg)) {
				syslog(LOG_ERR,"ListenPort doesn't match current listening port.");
			}
		} else if(strcaseequal(cmd,"PIDFile")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}
			if(gPIDFilename) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" can only appear once.",filename,line_number,cmd);
				goto bail;
			}
			gPIDFilename = strdup(arg);
			unlink(gPIDFilename);
			FILE* pidfile = fopen(gPIDFilename,"w");
			if(!pidfile) {
				syslog(LOG_ERR,"%s:%d: Unable to open PID file \"%s\".",filename,line_number,gPIDFilename);
			}
			fprintf(pidfile,"%d\n",getpid());
			fclose(pidfile);
		} else if(strcaseequal(cmd,"CoAPProxyURL")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}
			smcp_set_proxy_url(smcp,arg);
		} else if(strcaseequal(cmd,"<node")) {
			// Fix trailing '>'
			int linelen = strlinelen(line);
			bool oneline = false;

			while(isspace(line[linelen-1])) line[--linelen]=0;
			if (line[linelen-1]=='>') {
				line[--linelen] = 0;
				if (line[linelen-1] == '/') {
					oneline = true;
					line[--linelen] = 0;
				}
			} else {
				syslog(LOG_ERR,"%s:%d: Missing '>'",filename,line_number);
				goto bail;
			}

			char* arg = get_next_arg(line,&line);
			char* arg2 = get_next_arg(line,&line);
			char* arg3 = get_next_arg(line,&line);

			if (!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}

			smcp_node_t next_node = smcp_node_find(node,arg,strlen(arg));

			if(!next_node) {
				next_node = smcpd_make_node(arg2?arg2:"node",node,arg,arg3);
			}

			if (!next_node) {
				syslog(LOG_ERR,"Node creation failed for node \"%s\"",arg);
			} else if (next_node->parent != node) {
				syslog(LOG_ERR,"BUG: Node parent relationship is busted for \"%s\"",arg);
				goto bail;
			} else {
				syslog(LOG_DEBUG,"Created node \"%s\".", arg);
				if (!oneline) {
					node = next_node;
				}
			}
		} else if(strcaseequal(cmd,"</node>")) {
			if(!node->parent) {
				syslog(LOG_ERR,"Unmatched \"%s\".",cmd);
				goto bail;
			}
			node = node->parent;
		} else {
			syslog(LOG_ERR,"Unrecognised config option \"%s\".",cmd);
		}
	}

	if(node->parent) {
		syslog(LOG_ERR,"Unmatched \"<node>\" \"%s\".", node->name);
		goto bail;
	}

	ret = 0;

bail:
	return ret;
}

static void
syslog_dump_select_info(int loglevel, fd_set *read_fd_set, fd_set *write_fd_set, fd_set *error_fd_set, int fd_count, smcp_cms_t timeout)
{
#define DUMP_FD_SET(l, x) do {\
		int i; \
		char buffer[90] = ""; \
		for (i = 0; i < fd_count; i++) { \
			if (!FD_ISSET(i, x)) { \
				continue; \
			} \
			if (strlen(buffer) != 0) { \
				strlcat(buffer, ", ", sizeof(buffer)); \
			} \
			snprintf(buffer+strlen(buffer), sizeof(buffer)-strlen(buffer), "%d", i); \
		} \
		syslog(l, "SELECT:     %s: %s", #x, buffer); \
	} while (0)

	// Check the log level preemptively to avoid wasted CPU.
	if((setlogmask(0)&LOG_MASK(loglevel))) {
		syslog(loglevel, "SELECT: fd_count=%d cms_timeout=%d", fd_count, timeout);

		DUMP_FD_SET(loglevel, read_fd_set);
		DUMP_FD_SET(loglevel, write_fd_set);
		//DUMP_FD_SET(loglevel, error_fd_set); // Commented out to reduce log volume
	}
}

int
main(
	int argc, char * argv[]
) {
	int i, debug_mode = 0;
	int port = 0;
	const char* config_file = ETC_PREFIX "smcp.conf";

	openlog(basename(argv[0]),LOG_PERROR|LOG_PID|LOG_CONS,LOG_DAEMON);

	gPreviousHandlerForSIGINT = signal(SIGINT, &signal_SIGINT);
	gPreviousHandlerForSIGTERM = signal(SIGINT, &signal_SIGTERM);
	signal(SIGHUP, &signal_SIGHUP);

	srandom(time(NULL));

	if (argc && argv[0][0]) {
		gProcessName = basename(argv[0]);
	}

	BEGIN_LONG_ARGUMENTS(gRet)
	HANDLE_LONG_ARGUMENT("port") port = strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("config") config_file = argv[++i];
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
	HANDLE_SHORT_ARGUMENT('c') config_file = argv[++i];
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

	SMCP_LIBRARY_VERSION_CHECK();

	if (debug_mode >= 2) {
		setlogmask(LOG_UPTO(LOG_DEBUG));
	} else if (debug_mode == 1) {
		setlogmask(LOG_UPTO(LOG_INFO));
	} else if (debug_mode == 0) {
		setlogmask(LOG_UPTO(LOG_NOTICE));
	}

	syslog(LOG_NOTICE,"Starting smcpd . . .");

#if HAVE_LIBCURL
	syslog(LOG_NOTICE,"Built with libcurl support.");
#endif

	smcp = smcp_create();

	if(!smcp) {
		syslog(LOG_CRIT,"Unable to initialize SMCP instance.");
		gRet = ERRORCODE_UNKNOWN;
		goto bail;
	}

	if (port) {
		if (smcp_plat_bind_to_port(smcp, SMCP_SESSION_TYPE_UDP, port) != SMCP_STATUS_OK) {
			fprintf(stderr,"%s: FATAL-ERROR: Unable to bind to port! \"%s\" (%d)\n",argv[0],strerror(errno),errno);
			goto bail;
		}
	}

	if (smcp_plat_get_port(smcp) == 0) {
		if (smcp_plat_bind_to_port(smcp, SMCP_SESSION_TYPE_UDP, COAP_DEFAULT_PORT) != SMCP_STATUS_OK) {
			fprintf(stderr,"%s: FATAL-ERROR: Unable to bind to port! \"%s\" (%d)\n",argv[0],strerror(errno),errno);
			goto bail;
		}
	}

	smcp_set_current_instance(smcp);

	// Set up the root node.
	smcp_node_init(&root_node,NULL,NULL);

	// Set up the node router.
	smcp_set_default_request_handler(smcp, &smcp_node_router_handler, &root_node);

	smcp_set_proxy_url(smcp,getenv("COAP_PROXY_URL"));

	if(0!=read_configuration(smcp,config_file)) {
		syslog(LOG_NOTICE,"Error processing configuration file!");
		gRet = ERRORCODE_BADCONFIG;
	} else {
		syslog(LOG_NOTICE,"Daemon started. Listening on port %d.",smcp_plat_get_port(smcp));
	}

	while (!gRet) {
		int fds_ready = 0, fd_count = 0;
		fd_set read_fd_set,write_fd_set,error_fd_set;
		smcp_cms_t cms_timeout = 60 * MSEC_PER_SEC;
		struct timeval timeout = {};

		FD_ZERO(&read_fd_set);
		FD_ZERO(&write_fd_set);
		FD_ZERO(&error_fd_set);
		smcpd_modules_update_fdset(
			&read_fd_set,
			&write_fd_set,
			&error_fd_set,
			&fd_count,
			&cms_timeout
		);

		cms_timeout = MIN(smcp_get_timeout(smcp),cms_timeout);
		fd_count = MAX(smcp_plat_get_fd(smcp)+1,fd_count);
		FD_SET(smcp_plat_get_fd(smcp),&read_fd_set);
		FD_SET(smcp_plat_get_fd(smcp),&error_fd_set);

		//syslog_dump_select_info(LOG_INFO, &read_fd_set,&write_fd_set,&error_fd_set, fd_count, cms_timeout);

		if (cms_timeout < 0) {
			cms_timeout = 0;
		}

		timeout.tv_sec = cms_timeout / MSEC_PER_SEC;
		timeout.tv_usec = (cms_timeout % MSEC_PER_SEC) * USEC_PER_MSEC;

		fds_ready = select(fd_count,&read_fd_set,&write_fd_set,&error_fd_set,&timeout);

		if(fds_ready < 0 && errno!=EINTR) {
			syslog(LOG_ERR,"select() errno=\"%s\" (%d)",strerror(errno),errno);
			break;
		}

		if (gRet) {
			break;
		}

		smcp_plat_process(smcp);

		if (smcpd_modules_process() != SMCP_STATUS_OK) {
			syslog(LOG_ERR,"Module process error.");
			gRet = ERRORCODE_UNKNOWN;
		}

		if (gRet == ERRORCODE_SIGHUP) {
			gRet = 0;
			read_configuration(smcp,config_file);
		}
	}

bail:

	if (gRet == ERRORCODE_QUIT) {
		gRet = 0;
	}

	if (smcp) {
		syslog(LOG_NOTICE,"Stopping smcpd . . .");

		if (gPIDFilename) {
			unlink(gPIDFilename);
		}

		smcp_release(smcp);

		syslog(LOG_NOTICE,"Stopped.");
	}
	return gRet;
}
