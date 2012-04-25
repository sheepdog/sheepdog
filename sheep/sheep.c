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

#include "sheep_priv.h"
#include "trace/trace.h"

#define EPOLL_SIZE 4096
#define DEFAULT_OBJECT_DIR "/tmp"
#define LOG_FILE_NAME "sheep.log"

static unsigned nr_io_worker = 4;
static unsigned nr_gateway_worker = 4;

LIST_HEAD(cluster_drivers);
static char program_name[] = "sheep";

static struct option const long_options[] = {
	{"asyncflush", no_argument, NULL, 'a'},
	{"cluster", required_argument, NULL, 'c'},
	{"debug", no_argument, NULL, 'd'},
	{"directio", no_argument, NULL, 'D'},
	{"foreground", no_argument, NULL, 'f'},
	{"nr_gateway_worker", required_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"nr_io_worker", required_argument, NULL, 'i'},
	{"loglevel", required_argument, NULL, 'l'},
	{"stdout", no_argument, NULL, 'o'},
	{"port", required_argument, NULL, 'p'},
	{"vnodes", required_argument, NULL, 'v'},
	{"zone", required_argument, NULL, 'z'},
	{NULL, 0, NULL, 0},
};

static const char *short_options = "ac:dDfg:hi:l:op:v:z:";

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
  -a, --asyncflush        flush the object cache asynchronously\n\
  -c, --cluster           specify the cluster driver\n\
  -d, --debug             include debug messages in the log\n\
  -D, --directio          use direct IO when accessing the object from object cache\n\
  -f, --foreground        make the program run in the foreground\n\
  -g, --nr_gateway_worker set the number of workers for Guests' requests (default 4)\n\
  -h, --help              display this help and exit\n\
  -i, --nr_io_worker      set the number of workers for sheep internal requests (default 4)\n\
  -l, --loglevel          specify the level of logging detail\n\
  -p, --port              specify the TCP port on which to listen\n\
  -v, --vnodes            specify the number of virtual nodes\n\
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
	char *p;
	struct cluster_driver *cdrv;

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
		case 'd':
			/* removed soon. use loglevel instead */
			log_level = SDOG_DEBUG;
			break;
		case 'D':
			dprintf("direct IO mode\n");
			sys->use_directio = 1;
			break;
		case 'a':
			sys->async_flush = 1;
			break;
		case 'g':
			nr_gateway_worker = strtol(optarg, &p, 10);
			if (optarg == p || nr_gateway_worker < 4 || nr_gateway_worker > UINT32_MAX) {
				fprintf(stderr, "Invalid number of gateway workers '%s': "
					"must be an integer between 4 and %u\n",
					optarg, UINT32_MAX);
				exit(1);
			}
			break;
		case 'i':
			nr_io_worker = strtol(optarg, &p, 10);
			if (optarg == p || nr_io_worker < 4 || nr_io_worker > UINT32_MAX) {
				fprintf(stderr, "Invalid number of internal IO workers '%s': "
					"must be an integer between 4 and %u\n",
					optarg, UINT32_MAX);
				exit(1);
			}
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

	ret = init_store(dir);
	if (ret)
		exit(1);

	ret = init_event(EPOLL_SIZE);
	if (ret)
		exit(1);

	ret = create_listen_port(port, sys);
	if (ret)
		exit(1);

	ret = create_cluster(port, zone, nr_vnodes);
	if (ret) {
		eprintf("failed to create sheepdog cluster\n");
		exit(1);
	}

	sys->event_wqueue = init_work_queue(1);
	sys->gateway_wqueue = init_work_queue(nr_gateway_worker);
	sys->io_wqueue = init_work_queue(nr_io_worker);
	sys->recovery_wqueue = init_work_queue(1);
	sys->deletion_wqueue = init_work_queue(1);
	sys->flush_wqueue = init_work_queue(1);
	if (!sys->event_wqueue || !sys->gateway_wqueue || !sys->io_wqueue ||
	    !sys->recovery_wqueue || !sys->deletion_wqueue ||
	    !sys->flush_wqueue)
		exit(1);

	ret = init_signal();
	if (ret)
		exit(1);

	ret = trace_init();
	if (ret)
		exit(1);

	vprintf(SDOG_NOTICE, "sheepdog daemon (version %s) started\n", PACKAGE_VERSION);

	while (!sys_stat_shutdown() || sys->nr_outstanding_reqs != 0)
		event_loop(-1);

	vprintf(SDOG_INFO, "shutdown\n");

	log_close();

	return 0;
}
