/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "../include/config.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "sheep_priv.h"
#include "trace/trace.h"

#define EPOLL_SIZE 4096
#define DEFAULT_OBJECT_DIR "/tmp"
#define LOG_FILE_NAME "sheep.log"

LIST_HEAD(cluster_drivers);
static char program_name[] = "sheep";

static struct option const long_options[] = {
	{"cluster", required_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{"directio", no_argument, NULL, 'D'},
	{"foreground", no_argument, NULL, 'f'},
	{"gateway", no_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"loglevel", required_argument, NULL, 'l'},
	{"myaddr", required_argument, NULL, 'y'},
	{"stdout", no_argument, NULL, 'o'},
	{"port", required_argument, NULL, 'p'},
	{"vnodes", required_argument, NULL, 'v'},
	{"enable-cache", no_argument, NULL, 'w'},
	{"zone", required_argument, NULL, 'z'},
	{"pidfile", required_argument, NULL, 'P'},
	{NULL, 0, NULL, 0},
};

static const char *short_options = "c:dDfghl:op:P:v:wy:z:";

static void usage(int status)
{
	if (status)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else
		printf("\
Sheepdog daemon (version %s)\n\
Usage: %s [OPTION]... [PATH]\n\
Options:\n\
  -c, --cluster           specify the cluster driver\n\
  -d, --debug             include debug messages in the log\n\
  -D, --directio          use direct IO when accessing the object from object cache\n\
  -f, --foreground        make the program run in the foreground\n\
  -g, --gateway           make the progam run as a gateway mode (same as '-v 0')\n\
  -h, --help              display this help and exit\n\
  -l, --loglevel          specify the level of logging detail\n\
  -o, --stdout            log to stdout instead of shared logger\n\
  -p, --port              specify the TCP port on which to listen\n\
  -P, --pidfile           create a pid file\n\
  -v, --vnodes            specify the number of virtual nodes\n\
  -w, --enable-cache      enable object cache\n\
  -y, --myaddr            specify the address advertised to other sheep\n\
  -z, --zone              specify the zone id\n\
", PACKAGE_VERSION, program_name);
	exit(status);
}

static void sdlog_help(void)
{
	printf("\
Available log levels:\n\
  #    Level           Description\n\
  0    SDOG_EMERG      system has failed and is unusable\n\
  1    SDOG_ALERT      action must be taken immediately\n\
  2    SDOG_CRIT       critical conditions\n\
  3    SDOG_ERR        error conditions\n\
  4    SDOG_WARNING    warning conditions\n\
  5    SDOG_NOTICE     normal but significant conditions\n\
  6    SDOG_INFO       informational notices\n\
  7    SDOG_DEBUG      debugging messages\n");
}

static int create_pidfile(const char *filename)
{
	int fd = -1;
	int len;
	char buffer[128];

	if ((fd = open(filename, O_RDWR|O_CREAT|O_SYNC, 0600)) == -1) {
		return -1;
	}

	if (lockf(fd, F_TLOCK, 0) == -1) {
		close(fd);
		return -1;
	}

	len = snprintf(buffer, sizeof(buffer), "%d\n", getpid());
	if (write(fd, buffer, len) != len) {
		close(fd);
		return -1;
	}

	/* keep pidfile open & locked forever */
	return 0;
}

static struct cluster_info __sys;
struct cluster_info *sys = &__sys;

int main(int argc, char **argv)
{
	int ch, longindex;
	int ret, port = SD_LISTEN_PORT;
	const char *dir = DEFAULT_OBJECT_DIR;
	int is_daemon = 1;
	int to_stdout = 0;
	int log_level = SDOG_INFO;
	char path[PATH_MAX];
	int64_t zone = -1;
	int nr_vnodes = SD_DEFAULT_VNODES;
	bool explicit_addr = false;
	int af;
	char *p;
	struct cluster_driver *cdrv;
	int enable_write_cache = 0; /* disabled by default */
	char *pid_file = NULL;

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			port = strtol(optarg, &p, 10);
			if (optarg == p || port < 1 || port > UINT16_MAX) {
				fprintf(stderr, "Invalid port number '%s'\n",
					optarg);
				exit(1);
			}
			break;
		case 'P':
			pid_file = optarg;
			break;
		case 'f':
			is_daemon = 0;
			break;
		case 'l':
			log_level = strtol(optarg, &p, 10);
			if (optarg == p || log_level < SDOG_EMERG ||
			    log_level > SDOG_DEBUG) {
				fprintf(stderr, "Invalid log level '%s'\n",
					optarg);
				sdlog_help();
				exit(1);
			}
			break;
		case 'y':
			af = strstr(optarg, ":") ? AF_INET6 : AF_INET;
			if (!str_to_addr(af, optarg, sys->this_node.nid.addr)) {
				fprintf(stderr,
					"Invalid address: '%s'\n",
					optarg);
				sdlog_help();
				exit(1);
			}
			explicit_addr = true;
			break;
		case 'd':
			/* removed soon. use loglevel instead */
			log_level = SDOG_DEBUG;
			break;
		case 'D':
			dprintf("direct IO mode\n");
			sys->use_directio = 1;
			break;
		case 'g':
			/* same as '-v 0' */
			nr_vnodes = 0;
			break;
		case 'o':
			to_stdout = 1;
			break;
		case 'z':
			zone = strtol(optarg, &p, 10);
			if (optarg == p || zone < 0 || UINT32_MAX < zone) {
				fprintf(stderr, "Invalid zone id '%s': "
					"must be an integer between 0 and %u\n",
					optarg, UINT32_MAX);
				exit(1);
			}
			sys->this_node.zone = zone;
			break;
		case 'w':
			vprintf(SDOG_INFO, "enable write cache\n");
			enable_write_cache = 1;
			break;
		case 'v':
			nr_vnodes = strtol(optarg, &p, 10);
			if (optarg == p || nr_vnodes < 0 || SD_MAX_VNODES < nr_vnodes) {
				fprintf(stderr, "Invalid number of virtual nodes '%s': "
					"must be an integer between 0 and %u\n",
					optarg, SD_MAX_VNODES);
				exit(1);
			}
			break;
		case 'c':
			sys->cdrv = find_cdrv(optarg);
			if (!sys->cdrv) {
				fprintf(stderr, "Invalid cluster driver '%s'\n", optarg);
				fprintf(stderr, "Supported drivers:");
				FOR_EACH_CLUSTER_DRIVER(cdrv) {
					fprintf(stderr, " %s", cdrv->name);
				}
				fprintf(stderr, "\n");
				exit(1);
			}

			sys->cdrv_option = get_cdrv_option(sys->cdrv, optarg);
			break;
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}
	if (nr_vnodes == 0)
		sys->gateway_only = 1;

	if (optind != argc)
		dir = argv[optind];

	snprintf(path, sizeof(path), "%s/" LOG_FILE_NAME, dir);

	srandom(port);

	if (is_daemon && daemon(0, 0))
		exit(1);

	ret = init_base_path(dir);
	if (ret)
		exit(1);

	ret = log_init(program_name, LOG_SPACE_SIZE, to_stdout, log_level, path);
	if (ret)
		exit(1);

	ret = init_store(dir, enable_write_cache);
	if (ret)
		exit(1);

	ret = init_event(EPOLL_SIZE);
	if (ret)
		exit(1);

	ret = create_listen_port(port, sys);
	if (ret)
		exit(1);

	ret = create_cluster(port, zone, nr_vnodes, explicit_addr);
	if (ret) {
		eprintf("failed to create sheepdog cluster\n");
		exit(1);
	}

	local_req_init();

	sys->gateway_wqueue = init_work_queue("gateway", false);
	sys->io_wqueue = init_work_queue("io", false);
	sys->recovery_wqueue = init_work_queue("recovery", true);
	sys->deletion_wqueue = init_work_queue("deletion", true);
	sys->block_wqueue = init_work_queue("block", true);
	if (!sys->gateway_wqueue || !sys->io_wqueue ||!sys->recovery_wqueue ||
	    !sys->deletion_wqueue || !sys->block_wqueue)
		exit(1);

	ret = init_signal();
	if (ret)
		exit(1);

	ret = trace_init();
	if (ret)
		exit(1);

	if (pid_file && (create_pidfile(pid_file) != 0)) {
		fprintf(stderr, "failed to pid file '%s' - %s\n", pid_file,
			strerror(errno));
		exit(1);
	}

	if (chdir(dir) < 0) {
		fprintf(stderr, "failed to chdir to %s: %m\n", dir);
		exit(1);
	}

	vprintf(SDOG_NOTICE, "sheepdog daemon (version %s) started\n", PACKAGE_VERSION);

	while (sys->nr_outstanding_reqs != 0 ||
	       (sys->status != SD_STATUS_KILLED &&
		sys->status != SD_STATUS_SHUTDOWN))
		event_loop(-1);

	vprintf(SDOG_INFO, "shutdown\n");

	leave_cluster();
	log_close();

	if (pid_file)
		unlink(pid_file);

	return 0;
}
