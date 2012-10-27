
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

#define strcaseequal(x,y)	(strcasecmp(x,y)==0)

static int
read_configuration(smcp_t smcp,const char* filename) {
	int ret = 1;
	syslog(LOG_INFO,"Reading configuration from \"%s\" . . .",filename);

	FILE* file = fopen(filename,"r");
	char* line = NULL;
	size_t line_len = 0;
	smcp_node_t node = smcp_get_root_node(smcp);

	require(file!=NULL,bail);

	while(!feof(file) && (line=fgetln(file,&line_len))) {
		char *cmd = get_next_arg(line,&line);
		if(!cmd)
			continue;
		else if(strcaseequal(cmd,"Port")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"Config option \"%s\" requires an argument.",cmd);
				goto bail;
			}
			// Not really supported at the moment.
			if(smcp_get_port(smcp)!=atoi(arg))
				syslog(LOG_ERR,"ListenPort doesn't match current listening port.");
		} else if(strcaseequal(cmd,"CoAPProxyURL")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"Config option \"%s\" requires an argument.",cmd);
				goto bail;
			}
			smcp_set_proxy_url(smcp,arg);
		} else if(strcaseequal(cmd,"<node")) {
			// Fix trailing '>'
			int linelen = strlen(line);
			while(isspace(line[linelen-1])) line[--linelen]=0;
			if(line[linelen-1]=='>') {
				line[linelen-1]=0;
			} else {
				syslog(LOG_ERR,"Missing '>'");
				goto bail;
			}
			char* arg = get_next_arg(line,&line);
			char* arg2 = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"Config option \"%s\" requires an argument.",cmd);
				goto bail;
			}

			smcp_node_t next_node = smcp_node_find(node,arg,strlen(arg));

			if(arg2) {
				if(strcaseequal(arg2,"timer")) {
					if(!next_node) next_node = smcp_timer_node_init(NULL,node,strdup(arg));
				} else {
					syslog(LOG_ERR,"Unknown node type \"%s\".",arg2);
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

	smcp = smcp_create(port);

	if(!smcp) {
		syslog(LOG_CRIT,"Unable to initialize SMCP instance.");
		gRet = ERRORCODE_UNKNOWN;
		goto bail;
	}

	smcp_set_proxy_url(smcp,getenv("COAP_PROXY_URL"));

	read_configuration(smcp,config_file);

	syslog(LOG_NOTICE,"Daemon started. Listening on port %d.",smcp_get_port(smcp));

	do {
		while(!gRet) {
			smcp_process(smcp, 1000);
		}

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
