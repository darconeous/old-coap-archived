#define HAS_LIBREADLINE 1

#include <smcp/assert_macros.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include <unistd.h>
#include <signal.h>

#if HAS_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#include <poll.h>

#include <smcp/smcp.h>

#include "cmd_list.h"
#include "cmd_test.h"
#include "cmd_get.h"
#include "cmd_post.h"
#include "cmd_pair.h"
#include "cmd_repeat.h"

#include "smcpctl.h"

#include <smcp/url-helpers.h>


static arg_list_item_t option_list[] = {
	{ 'h', "help",	NULL, "Print Help"				},
	{ 'd', "debug", NULL, "Enable debugging mode"	},
	{ 'p', "port",	NULL, "Port number"				},
	{ 'f', NULL,	NULL, "Read commands from file" },
	{ 0 }
};

void print_commands();

static int
tool_cmd_help(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	print_arg_list_help(option_list, "smcp [options] <sub-command> [args]");
	print_commands();
	return ERRORCODE_HELP;
}


static int
tool_cmd_cd(
	smcp_daemon_t smcp, int argc, char* argv[]
) {
	if(argc == 1) {
		printf("%s\n", getenv("SMCP_CURRENT_PATH"));
		return 0;
	}

	if(argc == 2) {
		char url[1000];
		strcpy(url, getenv("SMCP_CURRENT_PATH"));
		if(url_change(url, argv[1]))
			setenv("SMCP_CURRENT_PATH", url, 1);
		else
			return ERRORCODE_BADARG;
	}

	return 0;
}


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
	{ "cat", NULL,
	  &tool_cmd_get,
	  1 },
	{
		"post",
		"Triggers an event.",
		&tool_cmd_post
	},
	{
		"pair",
		"Pairs an event to an action",
		&tool_cmd_pair
	},
	{
		"list",
		"Displays the contents of a folder.",
		&tool_cmd_list
	},
	{ "ls",	 NULL,
	  &tool_cmd_list,
	  1 },
	{
		"test",
		"Self test mode.",
		&tool_cmd_test
	},
	{
		"repeat",
		"Repeat the specified command",
		&tool_cmd_repeat
	},

	{
		"help",
		"Display this help.",
		&tool_cmd_help
	},
	{ "?",	 NULL,
	  &tool_cmd_help,
	  1 },

	{ "cd",	 "Change current directory or URL (command mode)",
	  &tool_cmd_cd },

	{ NULL }
};

void
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
exec_command(
	smcp_daemon_t smcp_daemon, int argc, char * argv[]
) {
	int ret = 0;
	int j;

	require(argc, bail);

	if((strcmp(argv[0],
				"quit") == 0) ||
	        (strcmp(argv[0],
				"exit") == 0) || (strcmp(argv[0], "q") == 0)) {
		ret = ERRORCODE_QUIT;
		goto bail;
	}

	for(j = 0; commandList[j].name; ++j) {
		if(strcmp(argv[0], commandList[j].name) == 0) {
			if(commandList[j].entrypoint) {
				ret = commandList[j].entrypoint(smcp_daemon, argc, argv);
				goto bail;
			} else {
				fprintf(stderr,
					"The command \"%s\" is not yet implemented.\n",
					commandList[j].name);
				ret = ERRORCODE_NOCOMMAND;
				goto bail;
			}
		}
	}

	fprintf(stderr, "The command \"%s\" is not recognised.\n", argv[0]);

	ret = ERRORCODE_BADCOMMAND;

bail:
	return ret;
}

static int ret = 0;
static smcp_daemon_t smcp_daemon;
static bool istty = true;

void process_input_line(char *l) {
	char *inputstring;
	char *argv2[100];
	char **ap = argv2;
	int argc2 = 0;

	if(!l[0])
		goto bail;

	add_history(l);

	inputstring = l;

	while((*ap = strsep(&inputstring, " \t\n\r"))) {
		if(**ap == '#')    // Ignore everything after a comment symbol.
			break;
		if(**ap != '\0') {
			ap++;
			argc2++;
		}
	}
	if(argc2 > 0) {
		ret = exec_command(smcp_daemon, argc2, argv2);
		if(ret == ERRORCODE_QUIT)
			return;
		else if(ret && (ret != ERRORCODE_HELP))
			printf("Error %d\n", ret);

		write_history(getenv("SMCP_HISTORY_FILE"));
	}

bail:
	if(istty) {
		char prompt[128] = {};
		char* current_smcp_path = getenv("SMCP_CURRENT_PATH");

		snprintf(prompt,
			sizeof(prompt),
			"%s> ",
			current_smcp_path ? current_smcp_path : "");
		rl_prep_terminal(0);
		rl_callback_handler_install(prompt, &process_input_line);
	}
	return;
}

int
main(
	int argc, char * argv[]
) {
	int i, debug_mode = 0;
	int port = SMCP_DEFAULT_PORT + 1;

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
#if HAS_LIBREADLINE
				case 'f':
					stdin = fopen(argv[++i], "r");
					if(!stdin) {
						fprintf(stderr,
							"%s: error: Unable to open file \"%s\".\n",
							argv[0],
							argv[i - 1]);
						return ERRORCODE_BADARG;
					}
					break;
#endif
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

	istty = isatty(fileno(stdin));


	smcp_daemon = smcp_daemon_create(port);
	setenv("SMCP_CURRENT_PATH", "smcp://localhost/", 0);

	if(i < argc) {
		if((0 !=
		        strncmp(argv[i], "smcp:",
					5)) && (0 != strncmp(argv[i], "coap:", 5))) {
			ret = exec_command(smcp_daemon, argc - i, argv + i);
#if HAS_LIBREADLINE
			if(ret || (0 != strcmp(argv[i], "cd")))
#endif
			goto bail;
		} else {
			setenv("SMCP_CURRENT_PATH", argv[i], 1);
		}
	}

	if(istty) {
#if !HAS_LIBREADLINE
		print_arg_list_help(option_list,
			"smcp [options] <sub-command> [args]");
		print_commands();
		ret = ERRORCODE_NOCOMMAND;
		goto bail;
#else   // HAS_LIBREADLINE
		char prompt[128] = {};
		char* current_smcp_path = getenv("SMCP_CURRENT_PATH");
		snprintf(prompt,
			sizeof(prompt),
			"%s> ",
			current_smcp_path ? current_smcp_path : "");

		require_action(NULL != readline, bail, ret = ERRORCODE_NOREADLINE);

		setenv("SMCP_HISTORY_FILE", tilde_expand("~/.smcp_history"), 0);
		rl_initialize();
		using_history();
		read_history(getenv("SMCP_HISTORY_FILE"));
		rl_instream = stdin;

		rl_callback_handler_install(prompt, &process_input_line);
#endif  // HAS_LIBREADLINE
	}

	// Command mode.
	while((ret != ERRORCODE_QUIT) && !feof(stdin)) {
#if HAS_LIBREADLINE
		if(istty) {
			struct pollfd polltable[2] = {
				{ fileno(stdin),				   POLLIN | POLLHUP,
				  0 },
				{ smcp_daemon_get_fd(smcp_daemon), POLLIN | POLLHUP,
				  0 },
			};

			if(poll(polltable, 2,
					smcp_daemon_get_timeout(smcp_daemon)) < 0)
				break;

			if(polltable[0].revents)
				rl_callback_read_char();
		} else
#endif  // HAS_LIBREADLINE
		{
			char linebuffer[200];
			fgets(linebuffer, sizeof(linebuffer), stdin);
			process_input_line(linebuffer);
		}

		smcp_daemon_process(smcp_daemon, 0);
	}

bail:
	if(ret == ERRORCODE_QUIT)
		ret = 0;

	smcp_daemon_release(smcp_daemon);
	return ret;
}
