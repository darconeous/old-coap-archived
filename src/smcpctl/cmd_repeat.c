/*
 *  cmd_repeat.c
 *  SMCP
 *
 *  Created by Robert Quattlebaum on 10/27/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

#include <smcp/assert_macros.h>
#include <smcp/smcp.h>
#include <smcp/smcp_timer.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include <signal.h>
#include "cmd_repeat.h"
#include "smcpctl.h"

static arg_list_item_t option_list[] = {
	{ 'h', "help",	   NULL,   "Print Help"			  },
	{ 'i', "interval", "msec",
	  "Milliseconds to wait between executions." },
	{ 'c', "count",	   "i",	   "Number of iterations" },
	{ 0 }
};

static void
show_help() {
	print_arg_list_help(option_list, "repeat [args] command [...]");
}

static int ret = 0;
static sig_t previous_sigint_handler;

static void
signal_interrupt(int sig) {
	ret = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

int
tool_cmd_repeat(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	ret = 0;
	int i = 0;
	cms_t interval = 5 * MSEC_PER_SEC;
	uint32_t count = 0xFFFFFFFF;

	previous_sigint_handler = signal(SIGINT, &signal_interrupt);

	for(i = 1; i < argc; i++) {
		if(argv[i][0] == '-' && argv[i][1] == '-') {
			if(strcmp(argv[i] + 2, "help") == 0) {
				show_help();
				ret = ERRORCODE_HELP;
				goto bail;
			} else if(strcmp(argv[i] + 2, "interval") == 0) {
				interval = atoi(argv[++i]);
			} else if(strcmp(argv[i] + 2, "count") == 0) {
				count = atoi(argv[++i]);
			} else {
				fprintf(stderr,
					"%s: error: Unknown command line argument \"%s\".\n",
					argv[0],
					argv[i]);
				ret = ERRORCODE_BADARG;
				goto bail;
			}
		} else if(argv[i][0] == '-') {
			int j;
			int ii = i;
			for(j = 1; j && argv[ii][j]; j++) {
				switch(argv[ii][j]) {
				case 'i':
					interval = atoi(argv[++i]);
					break;
				case 'c':
					count = atoi(argv[++i]);
					break;
				case '?':
				case 'h':
					show_help();
					ret = ERRORCODE_HELP;
					goto bail;
					break;
				default:
					fprintf(
						stderr,
						"%s: error: Unknown command line argument \"-%c\".\n",
						argv[0],
						argv[ii][j]);
					ret = ERRORCODE_BADARG;
					goto bail;
				}
			}
		} else {
			break;
		}
	}

	require_action(i < argc, bail, show_help());

	if((0 == strcmp(argv[i], "repeat"))
	    || (0 == strcmp(argv[i], "cd"))
	    || (0 == strcmp(argv[i], "quit"))
	    || (0 == strcmp(argv[i], "test"))
	    || (0 == strcmp(argv[i], "help"))
	) {
		fprintf(stderr,
			"%s: error: Not allowed to repeat command \"%s\".\n",
			argv[0],
			argv[i]);
		ret = ERRORCODE_BADARG;
		goto bail;
	}

	while(count-- && (ret == 0)) {
		ret = exec_command(smcp, argc - i, argv + i);

		struct timeval continue_time;

		convert_cms_to_timeval(&continue_time, interval);

		do {
			smcp_daemon_process(smcp,
				count ? convert_timeval_to_cms(&continue_time) : 0);
		} while(count && (ret == 0) &&
		        (convert_timeval_to_cms(&continue_time) > 0));
	}

bail:
	signal(SIGINT, previous_sigint_handler);
	return ret;
}
