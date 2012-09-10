
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

#include <smcp/smcp.h>
//#include <smcp/url-helpers.h>

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
	fprintf(stderr,"%s: Caught SIGINT!\n",gProcessName);
	signal(SIGINT, gPreviousHandlerForSIGINT);
}

static void
signal_SIGHUP(int sig) {
	gRet = ERRORCODE_SIGHUP;
	fprintf(stderr,"%s: Caught SIGHUP!\n",gProcessName);
}

static int
read_configuration(smcp_t smcp,const char* filename) {
	fprintf(stderr,"%s: Reading configuration from \"%s\"...\n",gProcessName,filename);

	return 0;
}

int
main(
	int argc, char * argv[]
) {
	int i, debug_mode = 0;
	int port = 5684;
	const char* config_file = ETC_PREFIX "smcp.conf";

	gPreviousHandlerForSIGINT = signal(SIGINT, &signal_SIGINT);
	signal(SIGHUP, &signal_SIGHUP);

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

	fprintf(stderr,"%s: Starting smcpd...\n",gProcessName);

	smcp = smcp_create(port);

	if(!smcp) {
		fprintf(stderr,"%s: error: Unable to initialize SMCP.\n",gProcessName);
		gRet = ERRORCODE_UNKNOWN;
		goto bail;
	}

	smcp_set_proxy_url(smcp,getenv("COAP_PROXY_URL"));

	read_configuration(smcp,config_file);

	fprintf(stderr,"%s: smcpd started. Listening on port %d.\n",gProcessName,smcp_get_port(smcp));

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
		fprintf(stderr,"%s: Stopping smcpd...\n",gProcessName);

		smcp_release(smcp);

		fprintf(stderr,"%s: Stopped.\n",gProcessName);
	}
	return gRet;
}
