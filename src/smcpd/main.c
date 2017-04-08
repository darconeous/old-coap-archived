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

#include "smcp/assert-macros.h"


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
#include <time.h>
#include <syslog.h>

#include <libnyoci/libnyoci.h>
#include <libnyociextra/libnyociextra.h>
#include <missing/fgetln.h>
#include "help.h"

#if NYOCI_PLAT_TLS_OPENSSL
#include <openssl/ssl.h>
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

#include "cgi-node.h"
#include "system-node.h"
#include "ud-var-node.h"
#include "pairing-node.h"
#include "group-node.h"

#if HAVE_LIBCURL
#include <smcp/smcp-curl_proxy.h>
#endif

#ifndef PREFIX
#define PREFIX "/usr/local"
#endif

#ifndef SYSCONFDIR
#define SYSCONFDIR PREFIX "etc"
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
#if NYOCI_PLAT_TLS_OPENSSLL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	{ 0, NULL,	"ssl-*", "SSL Configuration commands (see docs)" },
#endif
	{ 0 }
};

nyoci_t gMyNyociInstance;
static struct nyoci_node_s root_node;
static int gRet;

static const char* gProcessName = "smcpd";
static const char* gPIDFilename = NULL;

static sig_t gPreviousHandlerForSIGINT;
static sig_t gPreviousHandlerForSIGTERM;

#if NYOCI_DTLS
#if NYOCI_PLAT_TLS_OPENSSL
static SSL_CTX* gSslCtx;
#if HAVE_OPENSSL_SSL_CONF_CTX_NEW
static SSL_CONF_CTX* gSslConfCtx;
#endif
#else
static void* gSslCtx;
#endif
#endif

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
	nyoci_node_t node;
	nyoci_status_t (*update_fdset)(
		nyoci_node_t node,
		fd_set *read_fd_set,
		fd_set *write_fd_set,
		fd_set *error_fd_set,
		int *fd_count,
		nyoci_cms_t *timeout
	);
	nyoci_status_t (*process)(nyoci_node_t node);
} async_io_module[SMCPD_MAX_ASYNC_IO_MODULES];
int async_io_module_count;

nyoci_status_t
smcpd_modules_update_fdset(
    fd_set *read_fd_set,
    fd_set *write_fd_set,
    fd_set *error_fd_set,
    int *fd_count,
	nyoci_cms_t *timeout
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
	return NYOCI_STATUS_OK;
}

nyoci_status_t
smcpd_modules_process()
{
	nyoci_status_t status = 0;
	int i;
	for(i=0;i<async_io_module_count && !status;i++) {
		if(async_io_module[i].process) {
			status = async_io_module[i].process(async_io_module[i].node);
		}
	}
	return status;
}

nyoci_node_t smcpd_make_node(const char* type, nyoci_node_t parent, const char* name, const char* argument)
{
	nyoci_node_t ret = NULL;

	typedef nyoci_node_t (*init_func_t)(nyoci_node_t self, nyoci_node_t parent, const char* name, const char* argument);
	typedef nyoci_status_t (*process_func_t)(nyoci_node_t self);
	typedef nyoci_status_t (*update_fdset_func_t)(
		nyoci_node_t node,
		fd_set *read_fd_set,
		fd_set *write_fd_set,
		fd_set *error_fd_set,
		int *fd_count,
		nyoci_cms_t *timeout
	);

	init_func_t init_func = NULL;
	process_func_t process_func = NULL;
	update_fdset_func_t update_fdset_func = NULL;


	syslog(LOG_INFO,"MAKE t=\"%s\" n=\"%s\" a=\"%s\"",type, name, argument);

	if(!type || strcaseequal(type,"node")) {
		init_func = (init_func_t)&nyoci_node_init;
	} else if(strcaseequal(type,"system_node") || strcaseequal(type,"system")) {
		init_func = (init_func_t)&SMCPD_module__system_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__system_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__system_node_process;
	} else if(strcaseequal(type,"cgi_node") || strcaseequal(type,"cgi")) {
		init_func = (init_func_t)&SMCPD_module__cgi_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__cgi_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__cgi_node_process;
	} else if(strcaseequal(type,"ud_var_node") || strcaseequal(type,"ud_var")) {
		init_func = (init_func_t)&SMCPD_module__ud_var_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__ud_var_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__ud_var_node_process;
	} else if(strcaseequal(type,"pairing_node") || strcaseequal(type,"pairing")) {
		init_func = (init_func_t)&SMCPD_module__pairing_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__pairing_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__pairing_node_process;
	} else if(strcaseequal(type,"group_node") || strcaseequal(type,"group")) {
		init_func = (init_func_t)&SMCPD_module__group_node_init;
		update_fdset_func = (update_fdset_func_t)&SMCPD_module__group_node_update_fdset;
		process_func = (process_func_t)&SMCPD_module__group_node_process;
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
read_configuration(nyoci_t smcp,const char* filename) {
	int ret = 1;
	syslog(LOG_INFO,"Reading configuration from \"%s\" . . .",filename);

	FILE* file = fopen(filename,"r");
	char* line = NULL;
	size_t line_len = 0;
	nyoci_node_t node = &root_node;
	int line_number = 0;
	int ssl_ret;

	(void)ssl_ret;
	require(file != NULL,bail);

	while(!feof(file) && (line=fgetln(file,&line_len))) {
		char *cmd = get_next_arg(line,&line);
		line_number++;
		if(!cmd) {
			continue;
		}
#if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
		// Handle OpenSSL configuration options from configuration file
		else if ((ssl_ret = SSL_CONF_cmd(gSslConfCtx, cmd, line)) != -2) {
			if (ssl_ret > 0) {
			} else if (ssl_ret == 0) {
				syslog(LOG_ERR,"%s:%d: OpenSSL rejected command %s",filename,line_number,cmd);
				goto bail;
			} else if (ssl_ret < 0) {
				syslog(LOG_ERR,"%s:%d: OpenSSL rejected command %s",filename,line_number,cmd);
				goto bail;
			}
		}
#endif
#if NYOCI_DTLS
		else if(strcaseequal(cmd,"DTLSPort")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}

			nyoci_plat_ssl_set_context(smcp, (void*)gSslCtx);

			if (nyoci_plat_bind_to_port(smcp, NYOCI_SESSION_TYPE_DTLS, (uint16_t)atoi(arg)) != NYOCI_STATUS_OK) {
				syslog(LOG_ERR,"Unable to bind to port! \"%s\" (%d)",strerror(errno),errno);
			}
		}
#endif
		else if(strcaseequal(cmd,"Port")) {
			char* arg = get_next_arg(line,&line);
			if(!arg) {
				syslog(LOG_ERR,"%s:%d: Config option \"%s\" requires an argument.",filename,line_number,cmd);
				goto bail;
			}
			if(nyoci_plat_get_port(smcp)!=atoi(arg)) {
				if (nyoci_plat_bind_to_port(smcp, NYOCI_SESSION_TYPE_UDP, (uint16_t)atoi(arg)) != NYOCI_STATUS_OK) {
					syslog(LOG_ERR,"Unable to bind to port! \"%s\" (%d)",strerror(errno),errno);
				}


				if(nyoci_plat_get_port(smcp)!=atoi(arg)) {
					syslog(LOG_ERR,"ListenPort doesn't match current listening port.");
				}
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
			nyoci_set_proxy_url(smcp,arg);
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

			nyoci_node_t next_node = nyoci_node_find(node,arg,strlen(arg));

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
syslog_dump_select_info(int loglevel, fd_set *read_fd_set, fd_set *write_fd_set, fd_set *error_fd_set, int fd_count, nyoci_cms_t timeout)
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
	int argc, char * argv[], char * envp[]
) {
	int i, debug_mode = 0, ssl_ret;
	uint16_t port = 0;
	const char* config_file = SYSCONFDIR "/smcp.conf";

	(void)ssl_ret;
	(void)syslog_dump_select_info;

	openlog(basename(argv[0]),LOG_PERROR|LOG_PID|LOG_CONS,LOG_DAEMON);

#if NYOCI_DTLS
#if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	gSslConfCtx = SSL_CONF_CTX_new();
#if HAVE_OPENSSL_DTLS_METHOD
	gSslCtx = SSL_CTX_new(DTLS_method());
#else
	gSslCtx = SSL_CTX_new(DTLSv1_method());
#endif
	SSL_CONF_CTX_set_ssl_ctx(gSslConfCtx, gSslCtx);
	SSL_CONF_CTX_set_flags(gSslConfCtx, SSL_CONF_FLAG_CLIENT|SSL_CONF_FLAG_SERVER|SSL_CONF_FLAG_CERTIFICATE|SSL_CONF_FLAG_SHOW_ERRORS);
#ifdef SSL_CONF_FLAG_REQUIRE_PRIVATE
	SSL_CONF_CTX_set_flags(gSslConfCtx, SSL_CONF_FLAG_REQUIRE_PRIVATE);
#endif
	SSL_CONF_CTX_set_flags(gSslConfCtx, SSL_CONF_FLAG_FILE);
	SSL_CONF_CTX_set1_prefix(gSslConfCtx, "SMCPD_SSL_");

	for (i = 0; envp[i]; i++) {
		char key[256] = {};
		char* value = key;
		strlcpy(key, envp[i], sizeof(key));
		strsep(&value, "=");

		ssl_ret = SSL_CONF_cmd(gSslConfCtx, key, value);
		switch(ssl_ret) {
		case 1:
		case 2:
			syslog(LOG_DEBUG,"ENV OpenSSL => %s", envp[i]);
			break;
		case -2:
			// Skippit.
			break;
		default:
			syslog(LOG_ERR,"OpenSSL Rejected ENV %s", envp[i]);
			break;
		}
	}

	SSL_CONF_CTX_clear_flags(gSslConfCtx, SSL_CONF_FLAG_FILE);
	SSL_CONF_CTX_set_flags(gSslConfCtx, SSL_CONF_FLAG_CMDLINE);
	SSL_CONF_CTX_set1_prefix(gSslConfCtx, "--ssl-");
#else
	void* ssl_ctx = NULL;
#endif
#endif

	gPreviousHandlerForSIGINT = signal(SIGINT, &signal_SIGINT);
	gPreviousHandlerForSIGTERM = signal(SIGINT, &signal_SIGTERM);
	signal(SIGHUP, &signal_SIGHUP);

	srandom(time(NULL));

	if (argc && argv[0][0]) {
		gProcessName = basename(argv[0]);
	}

	BEGIN_LONG_ARGUMENTS(gRet)
#if NYOCI_PLAT_TLS_OPENSSLL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	// Handle OpenSSL configuration options on the command line
    else if ((ssl_ret = SSL_CONF_cmd(gSslConfCtx, argv[i], argv[i+1])) != -2) {
		if (ssl_ret == 2) {
			i++;
		} else if (ssl_ret == 0) {
			fprintf(stderr,
				"%s: error: Argument rejected: %s\n",
				argv[0],
				argv[i]);
			return ERRORCODE_BADARG;
		} else if (ssl_ret < 0) {
			fprintf(stderr,
				"%s: error: OpenSSL runtime error for: %s\n",
				argv[0],
				argv[i]);
			return ERRORCODE_BADARG;
		}
	}
#endif
	HANDLE_LONG_ARGUMENT("port") port = (uint16_t)strtol(argv[++i], NULL, 0);
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
	HANDLE_SHORT_ARGUMENT('p') port = (uint16_t)strtol(argv[++i], NULL, 0);
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

	NYOCI_LIBRARY_VERSION_CHECK();

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

	gMyNyociInstance = nyoci_create();

	if (!gMyNyociInstance) {
		syslog(LOG_CRIT,"Unable to initialize SMCP instance.");
		gRet = ERRORCODE_UNKNOWN;
		goto bail;
	}

	if (port) {
		if (nyoci_plat_bind_to_port(gMyNyociInstance, NYOCI_SESSION_TYPE_UDP, port) != NYOCI_STATUS_OK) {
			fprintf(stderr,"%s: FATAL-ERROR: Unable to bind to port! \"%s\" (%d)\n",argv[0],strerror(errno),errno);
			goto bail;
		}
	}

	if (nyoci_plat_get_port(gMyNyociInstance) == 0) {
		if (nyoci_plat_bind_to_port(gMyNyociInstance, NYOCI_SESSION_TYPE_UDP, COAP_DEFAULT_PORT) != NYOCI_STATUS_OK) {
			fprintf(stderr,"%s: FATAL-ERROR: Unable to bind to port! \"%s\" (%d)\n",argv[0],strerror(errno),errno);
			goto bail;
		}
	}

	nyoci_plat_join_standard_groups(gMyNyociInstance, NYOCI_ANY_INTERFACE);

	nyoci_set_current_instance(gMyNyociInstance);

	// Set up the root node.
	nyoci_node_init(&root_node,NULL,NULL);

	// Set up the node router.
	nyoci_set_default_request_handler(gMyNyociInstance, &nyoci_node_router_handler, &root_node);

	nyoci_set_proxy_url(gMyNyociInstance, getenv("COAP_PROXY_URL"));

#if NYOCI_PLAT_TLS_OPENSSL && HAVE_OPENSSL_SSL_CONF_CTX_NEW
	SSL_CONF_CTX_clear_flags(gSslConfCtx, SSL_CONF_FLAG_CMDLINE);
	SSL_CONF_CTX_set_flags(gSslConfCtx, SSL_CONF_FLAG_FILE);
	SSL_CONF_CTX_set1_prefix(gSslConfCtx, "SSL");
#endif

	if (0 != read_configuration(gMyNyociInstance,config_file)) {
		syslog(LOG_NOTICE,"Error processing configuration file!");
		gRet = ERRORCODE_BADCONFIG;
	} else {
		syslog(LOG_NOTICE,"Daemon started. Listening on port %d.",nyoci_plat_get_port(gMyNyociInstance));
	}

	while (!gRet) {
		int fds_ready = 0, fd_count = 0;
		fd_set read_fd_set,write_fd_set,error_fd_set;
		nyoci_cms_t cms_timeout = 60 * MSEC_PER_SEC;
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

		nyoci_plat_update_fdsets(
			gMyNyociInstance,
			&read_fd_set,
			&write_fd_set,
			&error_fd_set,
			&fd_count,
			&cms_timeout
		);

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

		nyoci_plat_process(gMyNyociInstance);

		if (smcpd_modules_process() != NYOCI_STATUS_OK) {
			syslog(LOG_ERR,"Module process error.");
			gRet = ERRORCODE_UNKNOWN;
		}

		if (gRet == ERRORCODE_SIGHUP) {
			gRet = 0;
			read_configuration(gMyNyociInstance, config_file);
		}
	}

bail:

	if (gRet == ERRORCODE_QUIT) {
		gRet = 0;
	}

	if (gMyNyociInstance) {
		syslog(LOG_NOTICE,"Stopping smcpd . . .");

		if (gPIDFilename) {
			unlink(gPIDFilename);
		}

		nyoci_release(gMyNyociInstance);

		syslog(LOG_NOTICE,"Stopped.");
	}
	return gRet;
}
