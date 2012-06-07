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
#include <smcp/smcp-timer.h>
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
	{ 'h', "help",	   NULL,				 "Print Help"			},
	{ 'i', "interval", "msec",
	  "Milliseconds to wait between executions." },
	{ 'c', "count",	   "i",					 "Number of iterations" },
	{ 0,   "prefix",   "[formatted string]", "writeme"				},
	{ 0 }
};

static int ret = 0;
static sig_t previous_sigint_handler;

static void
signal_interrupt(int sig) {
	ret = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

int
tool_cmd_repeat(
	smcp_t smcp, int argc, char* argv[]
) {
	ret = 0;
	int i = 0;
	cms_t interval = 5 * MSEC_PER_SEC;
	uint32_t count = 0xFFFFFFFF;
	const char* prefix_string = NULL;

	previous_sigint_handler = signal(SIGINT, &signal_interrupt);

	BEGIN_LONG_ARGUMENTS(ret)
	HANDLE_LONG_ARGUMENT("interval") interval = strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("count") count = strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("prefix") prefix_string = argv[++i];

	HANDLE_LONG_ARGUMENT("help") {
		print_arg_list_help(option_list, argv[0], "[args] command [...]");
		ret = ERRORCODE_HELP;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(ret)
	HANDLE_SHORT_ARGUMENT('i') interval = strtol(argv[++i], NULL, 0);
	HANDLE_SHORT_ARGUMENT('c') count = strtol(argv[++i], NULL, 0);

	HANDLE_SHORT_ARGUMENT2('h', '?') {
		print_arg_list_help(option_list, argv[0], "[args] command [...]");
		ret = ERRORCODE_HELP;
		goto bail;
	}
	HANDLE_OTHER_ARGUMENT() {
		break;
	}
	END_ARGUMENTS

	require_action(
		i < argc, bail, { print_arg_list_help(option_list,
				argv[0],
				"[args] command [...]"); ret = ERRORCODE_HELP; });

	if((0 == strcmp(argv[i], "repeat"))
	    || (0 == strcmp(argv[i], "cd"))
	    || (0 == strcmp(argv[i], "quit"))
	    || (0 == strcmp(argv[i], "q"))
	    || (0 == strcmp(argv[i], "exit"))
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
		if(prefix_string) {
			char prefix_buffer[1000];
			struct timeval tv;
			gettimeofday(&tv, NULL);
			strftime(prefix_buffer,
				sizeof(prefix_buffer),
				prefix_string,
				localtime(&tv.tv_sec));
			fputs(prefix_buffer, stdout);
		}
		ret = exec_command(smcp, argc - i, argv + i);

		struct timeval continue_time;

		convert_cms_to_timeval(&continue_time, interval);

		do {
			smcp_process(smcp,
				count ? convert_timeval_to_cms(&continue_time) : 0);
		} while(count && (ret == 0) &&
		        (convert_timeval_to_cms(&continue_time) > 0));
	}

bail:
	signal(SIGINT, previous_sigint_handler);
	return ret;
}
