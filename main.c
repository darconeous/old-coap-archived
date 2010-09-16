#include "assert_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"

#include "smcp.h"

#include "cmd_list.h"
#include "cmd_test.h"
#include "cmd_get.h"
#include "cmd_post.h"


#define ERRORCODE_HELP          (1)
#define ERRORCODE_BADARG        (2)
#define ERRORCODE_NOCOMMAND     (3)
#define ERRORCODE_UNKNOWN       (4)
#define ERRORCODE_BADCOMMAND    (5)

static arg_list_item_t option_list[] = {
	{ 'h', "help",	NULL, "Print Help"			  },
	{ 'd', "debug", NULL, "Enable debugging mode" },
	{ 'p', "port",	NULL, "Port number"			  },
	{ 0 }
};


struct {
	const char* name;
	const char* desc;
	int			(*entrypoint)(
		smcp_daemon_t smcp, int argc, char* argv[]);
	int			isHidden;
} commandList[] = {
	{
		"get",
		"Fetches the value of a variable.",
		&tool_cmd_get
	},
	{
		"post",
		"Triggers an event.",
		&tool_cmd_post
	},
	{
		"list",
		"Fetches the contents of a node.",
		&tool_cmd_list
	},{ "ls",	 NULL, &tool_cmd_list, 1 },
	{
		"test",
		"TEST.",
		&tool_cmd_test
	},
	{ NULL }
};

static void
print_commands() {
	int i;

	printf("Commands:\n");
	for(i = 0; commandList[i].name; ++i) {
		if(commandList[i].isHidden)
			continue;
		printf(
			"   %s %s%s\n",
			commandList[i].name,
			"                     " + strlen(commandList[i].name),
			commandList[i].desc
		);
	}
}


int
main(
	int argc, char * argv[]
) {
	int i, debug_mode = 0;
	int port = SMCP_DEFAULT_PORT + 1;

	if(argc <= 1) {
		print_arg_list_help(option_list,
			"smcp [options] <sub-command> [args]");
		print_commands();
		return ERRORCODE_HELP;
	}
	for(i = 1; i < argc; i++) {
		if(argv[i][0] == '-' && argv[i][1] == '-') {
			if(strcmp(argv[i] + 2, "help") == 0) {
				print_arg_list_help(option_list,
					"smcp [options] <sub-command> [args]");
				print_commands();
				return ERRORCODE_HELP;
			} else if(strcmp(argv[i] + 2, "port") == 0) {
				port = atoi(argv[++i]);
			} else if(strcmp(argv[i] + 2, "debug") == 0) {
				debug_mode++;
			} else {
				fprintf(stderr,
					"%s: error: Unknown command line argument \"%s\".\n",
					argv[0],
					argv[i]);
				return ERRORCODE_BADARG;
				break;
			}
		} else if(argv[i][0] == '-') {
			int j;
			int ii = i;
			for(j = 1; j && argv[ii][j]; j++) {
				switch(argv[ii][j]) {
				case 'p':
					port = atoi(argv[++i]);
					break;
				case '?':
				case 'h':
					print_arg_list_help(option_list,
						"smcp [options] <sub-command> [args]");
					print_commands();
					return ERRORCODE_HELP;
					break;
				case 'd':
					debug_mode++;
					break;
				default:
					fprintf(
						stderr,
						"%s: error: Unknown command line argument \"-%c\".\n",
						argv[0],
						argv[ii][j]);
					return ERRORCODE_BADARG;
					break;
				}
			}
		} else {
			break;
		}
	}

	if(i >= argc) {
		fprintf(stderr, "%s: error: Missing command.\n", argv[0]);
		return ERRORCODE_NOCOMMAND;
	}

	// The 'help' command is a special case.
	if(strcmp(argv[i], "help") == 0) {
		print_arg_list_help(option_list,
			"smcp [options] <sub-command> [args]");
		print_commands();
		return ERRORCODE_HELP;
	}


	int j;
	for(j = 0; commandList[j].name; ++j) {
		if(strcmp(argv[i], commandList[j].name) == 0) {
			if(commandList[j].entrypoint) {
				int ret;
				smcp_daemon_t smcp_daemon = smcp_daemon_create(port);
				ret = commandList[j].entrypoint(smcp_daemon,
					argc - i,
					argv + i);
				smcp_daemon_release(smcp_daemon);
				return ret;
			} else {
				fprintf(stderr,
					"The command \"%s\" is not yet implemented.\n",
					commandList[j].name);
				return ERRORCODE_NOCOMMAND;
			}
		}
	}

	fprintf(stderr, "The command \"%s\" is not recognised.\n", argv[i]);

	return ERRORCODE_BADCOMMAND;
}
