#define HAVE_FGETLN 0

#ifndef ASSERT_MACROS_USE_SYSLOG
#define ASSERT_MACROS_USE_SYSLOG 1
#endif

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
#include <libgen.h>
#include <syslog.h>

#include <smcp/smcp.h>
#include <smcp/smcp-node.h>
#include <missing/fgetln.h>
#include <smcp/smcp-timer_node.h>
#include "help.h"

#if HAS_LIBCURL
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
#define ERRORCODE_INTERRUPT     (8)
#define ERRORCODE_SIGHUP		(9)

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

static sig_t gPreviousHandlerForSIGINT;

static void
signal_SIGINT(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	syslog(LOG_NOTICE,"Caught SIGINT!");
	signal(SIGINT, gPreviousHandlerForSIGINT);
}

static void
signal_SIGHUP(int sig) {
	gRet = ERRORCODE_SIGHUP;
	syslog(LOG_NOTICE,"Caught SIGHUP!");
}

#if HAS_LIBCURL
static smcp_curl_proxy_node_t curl_proxy_node;

static CURLM*
get_curl_multi_handle() {
	static CURLM* curl_multi_handle;

	if(!curl_multi_handle) {
		curl_global_init(CURL_GLOBAL_ALL);
		curl_multi_handle = curl_multi_init();
	}
	return curl_multi_handle;
}
#endif

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
#define strcaseequal(x,y)	(strcasecmp(x,y)==0)

static int
read_configuration(smcp_t smcp,const char* filename) {
	int ret = 1;
	syslog(LOG_INFO,"Reading configuration from \"%s\" . . .",filename);

	FILE* file = fopen(filename,"r");
	char* line = NULL;
	size_t line_len = 0;
	smcp_node_t node = smcp_get_root_node(smcp);
	int line_number = 0;

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

			if(arg2) {
				if(strcaseequal(arg2,"timer")) {
					if(!next_node) next_node = smcp_timer_node_init(NULL,node,strdup(arg));
#if HAS_LIBCURL
				} else if(strcaseequal(arg2,"curl-proxy")) {
					if(curl_proxy_node && curl_proxy_node!=next_node) {
						syslog(LOG_ERR,"%s:%d: You may only have one instance of \"%s\".",filename,line_number,arg2);
						goto bail;
					}
					else if(!next_node) {
						curl_proxy_node = smcp_curl_proxy_node_init(
							NULL,
							node,
							strdup(arg),
							get_curl_multi_handle()
						);
						next_node = (smcp_node_t)curl_proxy_node;
					}
#endif //HAS_LIBCURL
				} else {
					syslog(LOG_ERR,"%s:%d: Unknown node type \"%s\".",filename,line_number,arg2);
					goto bail;
				}
			} else {
				if(!next_node) next_node = smcp_node_init(NULL,node,strdup(arg));
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
	int port = 5684;
	const char* config_file = ETC_PREFIX "smcp.conf";

	openlog(basename(argv[0]),LOG_PERROR|LOG_PID|LOG_CONS,LOG_DAEMON);

	gPreviousHandlerForSIGINT = signal(SIGINT, &signal_SIGINT);
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

#if HAS_LIBCURL
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

	read_configuration(smcp,config_file);

	syslog(LOG_NOTICE,"Daemon started. Listening on port %d.",smcp_get_port(smcp));


	do {
		int fds_ready = 0, max_fd = -1;
		struct fd_set read_fd_set,write_fd_set,error_fd_set;
		long cms_timeout = 600000;
		struct timeval timeout = {};

		FD_ZERO(&read_fd_set);
		FD_ZERO(&write_fd_set);
		FD_ZERO(&error_fd_set);
#if HAS_LIBCURL
		if(curl_proxy_node) {
			curl_multi_fdset(
				curl_proxy_node->curl_multi_handle,
				&read_fd_set,
				&write_fd_set,
				&error_fd_set,
				&max_fd
			);
			curl_multi_timeout(
				curl_proxy_node->curl_multi_handle,
				&cms_timeout
			);

			if(cms_timeout==-1)
				cms_timeout = 600000;
		}
#endif
		cms_timeout = MIN(smcp_get_timeout(smcp),cms_timeout);
		max_fd = MAX(smcp_get_fd(smcp),max_fd);
		FD_SET(smcp_get_fd(smcp),&read_fd_set);
		FD_SET(smcp_get_fd(smcp),&error_fd_set);

		timeout.tv_sec = cms_timeout/1000;
		timeout.tv_usec = (cms_timeout%1000)*1000;

		fds_ready = select(max_fd+1,&read_fd_set,&write_fd_set,&error_fd_set,&timeout);
		if(fds_ready < 0 && errno!=EINTR)
			break;

		smcp_process(smcp, 0);

#if HAS_LIBCURL
		if(curl_proxy_node) {
			int running_curl_handles;
			curl_multi_perform(curl_proxy_node->curl_multi_handle, &running_curl_handles);
		}
#endif

		if(gRet == ERRORCODE_SIGHUP) {
			gRet = 0;
			read_configuration(smcp,config_file);
		}
	} while(!gRet);

bail:

	if(gRet == ERRORCODE_QUIT)
		gRet = 0;

	if(smcp) {
		syslog(LOG_NOTICE,"Stopping smcpd . . .");

		smcp_release(smcp);

		syslog(LOG_NOTICE,"Stopped.");
	}
	return gRet;
}
