
#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

#define HAVE_FGETLN 0

#include <smcp/assert_macros.h>

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
#include <smcp/smcp-node.h>
#include <smcp/smcp-pairing.h>
#include <missing/fgetln.h>
#include <smcp/smcp-timer_node.h>
#include "help.h"

#ifndef HAVE_DLFCN_H
#define HAVE_DLFCN_H	1
#endif

#if HAVE_DLFCN_H
#include <dlfcn.h>
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT	((void*)0)
#endif
#ifndef RTLD_NEXT
#define RTLD_NEXT		((void*)-1l)
#endif
#endif

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

smcp_node_t smcpd_make_node(const char* type, smcp_node_t parent, const char* name) {
	smcp_node_t ret = NULL;
	smcp_node_t (*init_func)(smcp_node_t self, smcp_node_t parent, const char* name) = NULL;
	smcp_status_t (*process_func)(smcp_node_t self) = NULL;
	smcp_status_t (*update_fdset_func)(
		smcp_node_t node,
		fd_set *read_fd_set,
		fd_set *write_fd_set,
		fd_set *error_fd_set,
		int *max_fd,
		cms_t *timeout
	) = NULL;

	if(!type || strcaseequal(type,"node")) {
		init_func = &smcp_node_init;
	} else if(strcaseequal(type,"timer")) {
		init_func = &smcp_timer_node_init;
#if HAVE_LIBCURL
	} else if(strcaseequal(type,"curl_proxy")) {
		init_func = &smcp_curl_proxy_node_init;
		update_fdset_func = &smcp_curl_proxy_node_update_fdset;
		process_func = &smcp_curl_proxy_node_process;
#endif
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

	if(init_func)
		ret = (*init_func)(
			NULL,
			parent,
			strdup(name)
		);

	if(ret && (process_func || update_fdset_func)) {
		async_io_module[async_io_module_count].node = ret;
		async_io_module[async_io_module_count].update_fdset = update_fdset_func;
		async_io_module[async_io_module_count].process = process_func;
		async_io_module_count++;
	}

	check_noerr(init_func);

	return ret;
}

static char* get_next_arg(char *buf, char **rest) {
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
	smcp_node_t node = smcp_get_root_node(smcp);
	int line_number = 0;
	smcp_status_t status = 0;

	require(file!=NULL,bail);

	while(!feof(file) && (line=fgetln(file,&line_len))) {
		char *cmd = get_next_arg(line,&line);
		line_number++;
		if(!cmd)
			continue;
		else if(strcaseequal(cmd,"Port")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}
			// Not really supported at the moment.
			if(smcp_get_port(smcp)!=atoi(arg))
				syslog(LOG_ERR,"ListenPort doesn't match current listening port.");
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
		} else if(strcaseequal(cmd,"Pair")) {
			char* src_arg = get_next_arg(line,&line);
			char* dest_arg = get_next_arg(line,&line);
			if(!src_arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}
			if(!dest_arg) {
				dest_arg = src_arg;
				src_arg = ".";
			}
			if(url_is_absolute(src_arg)) {
				syslog(LOG_ERR,"%s:%d: Source path cannot contain an absolute URL: \"%s\"",filename,line_number,src_arg);
				goto bail;
			}
			char dest_path[2000];
			char src_path[2000];
			smcp_node_get_path(
				node,
				dest_path,
				sizeof(dest_path)
			);
			memcpy(src_path,dest_path,sizeof(dest_path));

			url_change(dest_path,dest_arg);
			url_change(src_path,src_arg);

			syslog(LOG_INFO,"%s:%d: Pairing \"%s\" -> \"%s\"",filename,line_number,src_path,dest_path);

			status = smcp_pair_with_uri(
				smcp,
				src_path,
				dest_path,
				SMCP_PARING_FLAG_RELIABILITY_PART,
				NULL
			);
			if(status) {
				syslog(LOG_ERR,"%s:%d: Unable to add pairing, error %d \"%s\"",filename,line_number,status,smcp_status_to_cstr(status));
				goto bail;
			}
		} else if(strcaseequal(cmd,"<node")) {
			// Fix trailing '>'
			int linelen = strlinelen(line);
			//syslog(LOG_DEBUG,"LINE-BEFORE: \"%s\"",line);
			while(isspace(line[linelen-1])) line[--linelen]=0;
			if(line[linelen-1]=='>') {
				line[--linelen]=0;
			} else {
				syslog(LOG_ERR,"%s:%d: Missing '>'",filename,line_number);
				goto bail;
			}
			//syslog(LOG_DEBUG,"LINE-AFTER: \"%s\"",line);
			char* arg = get_next_arg(line,&line);
			char* arg2 = get_next_arg(line,&line);
			//syslog(LOG_DEBUG,"ARG1: \"%s\"",arg);
			//syslog(LOG_DEBUG,"ARG2: \"%s\"",arg2);
			if(!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}

			smcp_node_t next_node = smcp_node_find(node,arg,strlen(arg));

			if(!next_node) {
				next_node = smcpd_make_node(arg2?arg2:"node",node,arg);
			}

			if(!next_node || next_node->parent!=node) {
				syslog(LOG_ERR,"Node creation failed for node \"%s\"",arg);
				goto bail;
			} else {
				syslog(LOG_DEBUG,"Created node \"%s\".",arg);
				node = next_node;
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
		syslog(LOG_ERR,"Unmatched \"<node>\".");
		goto bail;
	}

	ret = 0;

bail:
	return ret;
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

	if(argc && argv[0][0])
		gProcessName = basename(argv[0]);

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

	syslog(LOG_NOTICE,"Starting smcpd . . .");

#if HAVE_LIBCURL
	syslog(LOG_NOTICE,"Built with libcurl support.");
#endif

	smcp = smcp_create(port);

	if(!smcp) {
		syslog(LOG_CRIT,"Unable to initialize SMCP instance.");
		gRet = ERRORCODE_UNKNOWN;
		goto bail;
	}

	smcp_pairing_init(
		smcp_get_root_node(smcp),
		SMCP_PAIRING_DEFAULT_ROOT_PATH
	);

	smcp_set_proxy_url(smcp,getenv("COAP_PROXY_URL"));

	if(0!=read_configuration(smcp,config_file)) {
		syslog(LOG_NOTICE,"Error processing configuration file!");
		gRet = ERRORCODE_BADCONFIG;
	} else {
		syslog(LOG_NOTICE,"Daemon started. Listening on port %d.",smcp_get_port(smcp));
	}

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
			read_configuration(smcp,config_file);
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
