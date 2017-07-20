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

#include <sys/resource.h>
#include <malloc.h>

#include "sheep_priv.h"
#include "trace/trace.h"
#include "option.h"

#ifdef HAVE_ACCELIO
#include "xio.h"
#endif

#define EPOLL_SIZE 4096
#define DEFAULT_OBJECT_DIR "/tmp"
#define LOG_FILE_NAME "sheep.log"

LIST_HEAD(cluster_drivers);
static const char program_name[] = "sheep";

static const char bind_help[] =
"Example:\n\t$ sheep -b 192.168.1.1 ...\n"
"This tries to teach sheep listen to NIC of 192.168.1.1.\n"
"\nExample:\n\t$ sheep -b 0.0.0.0 ...\n"
"This tries to teach sheep listen to all the NICs available. It can be useful\n"
"when you want sheep to response dog without specified address and port.\n";

static const char ioaddr_help[] =
"Example:\n\t$ sheep -i host=192.168.1.1,port=7002 ...\n"
"This tries to add a dedicated IO NIC of 192.168.1.1:7002 to transfer data.\n"
"If IO NIC is down, sheep will fallback to non IO NIC to transfer data.\n";

static const char journal_help[] =
"Available arguments:\n"
"\tsize=: size of the journal in megabyes\n"
"\tdir=: path to the location of the journal (default: $STORE)\n"
"\tskip: if specified, skip the recovery at startup\n"
"\nExample:\n\t$ sheep -j dir=/journal,size=1G\n"
"This tries to use /journal as the journal storage of the size 1G\n";

#ifdef HAVE_HTTP
static const char http_help[] =
"Available arguments:\n"
"\thost=: specify a host to communicate with http server (default: localhost)\n"
"\tport=: specify a port to communicate with http server (default: 8000)\n"
"\tbuffer=: specify buffer size for http request (default: 32M)\n"
"\tswift: enable swift API\n"
"Example:\n\t$ sheep -r host=localhost,port=7001,buffer=64M,swift ...\n"
"This tries to enable Swift API and use localhost:7001 to\n"
"communicate with http server, using 64MB buffer.\n";
#endif

static const char myaddr_help[] =
"Example:\n\t$ sheep -y 192.168.1.1 ...\n"
"This tries to tell other nodes through what address they can talk to this\n"
"sheep.\n";

static const char zone_help[] =
"Example:\n\t$ sheep -z 1 ...\n"
"This tries to set the zone ID of this sheep to 1 and sheepdog won't store\n"
"more than one copy of any object into this same zone\n";

static const char cluster_help[] =
"Available arguments:\n"
"\tlocal: use local driver\n"
"\tcorosync: use corosync driver\n"
"\tzookeeper: use zookeeper driver, need extra arguments\n"
"\n\tzookeeper arguments: connection-string,timeout=value (default as 3000)\n"
"\nExample:\n\t"
"$ sheep -c zookeeper:IP1:PORT1,IP2:PORT2,IP3:PORT3[/cluster_id][,timeout=1000] ...\n"
"This tries to use 3 node zookeeper cluster, which can be reached by\n"
"IP1:PORT1, IP2:PORT2, IP3:PORT3 to manage membership and broadcast message\n"
"and set the timeout of node heartbeat as 1000 milliseconds.\n"
"cluster_id is used to identify which cluster it belongs to,\n"
"if not set, /sheepdog is used internally as default.\n";

static const char log_help[] =
"Example:\n\t$ sheep -l dir=/var/log/,level=debug,format=server ...\n"
"Available arguments:\n"
"\tdir=: path to the location of sheep.log\n"
"\tlevel=: log level of sheep.log\n"
"\tformat=: log format type\n"
"\tdst=: log destination type\n\n"
"if dir is not specified, use metastore directory\n\n"
"Available log levels:\n"
"  Level      Description\n"
"  emerg      system has failed and is unusable\n"
"  alert      action must be taken immediately\n"
"  crit       critical conditions\n"
"  err        error conditions\n"
"  warning    warning conditions\n"
"  notice     normal but significant conditions\n"
"  info       informational notices\n"
"  debug      debugging messages\n"
"default log level is info\n\n"
"Available log format:\n"
"  FormatType      Description\n"
"  default         raw format\n"
"  server          raw format with timestamp\n"
"  json            json format\n\n"
"Available log destination:\n"
"  DestinationType    Description\n"
"  default            dedicated file in a directory used by sheep\n"
"  syslog             syslog of the system\n"
"  stdout             standard output\n";

static const char recovery_help[] =
"Available arguments:\n"
"\tmax=: object recovery process maximum count of each interval\n"
"\tinterval=: object recovery interval time (millisec)\n"
"Example:\n\t$ sheep -R max=50,interval=1000 ...\n";

static const char vnodes_help[] =
"Example:\n\t$ sheep -V 128\n"
"\tset number of vnodes\n";

static struct sd_option sheep_options[] = {
	{'b', "bindaddr", true, "specify IP address of interface to listen on",
	 bind_help},
	{'c', "cluster", true,
	 "specify the cluster driver (default: "DEFAULT_CLUSTER_DRIVER")",
	 cluster_help},
	{'D', "directio", false, "use direct IO for backend store"},
	{'f', "foreground", false, "make the program run in foreground"},
	{'g', "gateway", false, "make the program run as a gateway mode"},
	{'h', "help", false, "display this help and exit"},
	{'i', "ioaddr", true, "use separate network card to handle IO requests"
	 " (default: disabled)", ioaddr_help},
	{'j', "journal", true, "use journal file to log all the write "
	 "operations. (default: disabled)", journal_help},
	{'l', "log", true,
	 "specify the log level, the log directory and the log format"
	 "(log level default: 6 [SDOG_INFO])", log_help},
	{'n', "nosync", false, "drop O_SYNC for write of backend"},
	{'p', "port", true, "specify the TCP port on which to listen "
	 "(default: 7000)"},
	{'P', "pidfile", true, "create a pid file"},
#ifdef HAVE_HTTP
	{'r', "http", true, "enable http service. (default: disabled)",
	 http_help},
#endif
	{'R', "recovery", true, "specify the recovery speed throttling",
	 recovery_help},
	{'u', "upgrade", false, "upgrade to the latest data layout"},
	{'v', "version", false, "show the version"},
	{'V', "vnodes", true, "set number of vnodes", vnodes_help},
	{'w', "wq-threads", true, "specify a number of threads for workqueue"},
	{'W', "wildcard-recovery", false, "wildcard recovery for first time"},
	{'x', "max-dynamic-threads", true,
	 "specify the maximum number of threads for dynamic workqueue"},
	{'y', "myaddr", true, "specify the address advertised to other sheep",
	 myaddr_help},
	{'z', "zone", true,
	 "specify the zone id (default: determined by listen address)",
	 zone_help},
	{ 0, NULL, false, NULL },
};

static void usage(int status)
{
	if (status) {
		const char *help = option_get_help(sheep_options, optopt);

		if (help) {
			printf("%s", help);
			goto out;
		}

		sd_err("Try '%s --help' for more information.", program_name);
	} else {
		struct sd_option *opt;

		printf("Sheepdog daemon (version %s)\n"
		       "Usage: %s [OPTION]... [PATH] (default: /tmp)\n"
		       "Options:\n", PACKAGE_VERSION, program_name);

		sd_for_each_option(opt, sheep_options) {
			printf("  -%c, --%-18s%s\n", opt->ch, opt->name,
			       opt->desc);
		}

		printf("\nTry '%s <option>', e.g., '%s -w', to get more detail "
		       "about specific option\n", program_name, program_name);
	}
out:
	exit(status);
}

static void sdlog_help(void)
{
	printf("Available log levels:\n"
	       "  Level      Description\n"
	       "  emerg      system has failed and is unusable\n"
	       "  alert      action must be taken immediately\n"
	       "  crit       critical conditions\n"
	       "  err        error conditions\n"
	       "  warning    warning conditions\n"
	       "  notice     normal but significant conditions\n"
	       "  info       informational notices\n"
	       "  debug      debugging messages\n");
}

static int create_pidfile(const char *filename)
{
	int fd;
	int len;
	char buffer[128];

	fd = open(filename, O_RDWR|O_CREAT|O_SYNC, 0600);
	if (fd == -1)
		return -1;

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

static int sigfd;

static void signal_handler(int listen_fd, int events, void *data)
{
	struct signalfd_siginfo siginfo;
	int uninitialized_var(ret);

	ret = read(sigfd, &siginfo, sizeof(siginfo));
	sd_assert(ret == sizeof(siginfo));
	sd_debug("signal %d, ssi pid %d", siginfo.ssi_signo, siginfo.ssi_pid);
	switch (siginfo.ssi_signo) {
	case SIGTERM:
		sys->cinfo.status = SD_STATUS_KILLED;
		break;
	default:
		sd_err("signal %d unhandled", siginfo.ssi_signo);
		break;
	}
}

static int init_signal(void)
{
	sigset_t mask;
	int ret;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	sigfd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (sigfd < 0) {
		sd_err("failed to create a signal fd: %m");
		return -1;
	}

	ret = register_event(sigfd, signal_handler, NULL);
	if (ret) {
		sd_err("failed to register signal handler (%d)", ret);
		return -1;
	}

	sd_debug("register signal_handler for %d", sigfd);

	return 0;
}

static void crash_handler(int signo, siginfo_t *info, void *context)
{
	sd_emerg("sheep exits unexpectedly (%s), "
		"si pid %d, uid %d, errno %d, code %d",
		strsignal(signo), info->si_pid, info->si_uid,
		info->si_errno, info->si_code);

	sd_backtrace();
	sd_dump_variable(__sys);

	reraise_crash_signal(signo, 1);
}

static struct system_info __sys;
struct system_info *sys = &__sys;

static int log_level = SDOG_INFO;

static int log_level_parser(const char *s)
{
	int level = loglevel_str2num(s);

	if (level < 0) {
		sd_err("Invalid log level '%s'", s);
		sdlog_help();
		return -1;
	}

	log_level = level;
	return 0;
}

static char *logdir;

static int log_dir_parser(const char *s)
{
	logdir = realpath(s, NULL);
	if (!logdir) {
		sd_err("%m");
		exit(1);
	}
	return 0;
}

static const char *log_format = "server";

static int log_format_parser(const char *s)
{
	log_format = s;
	return 0;
}

static const char *log_dst = "default"; /* default: dedicated file */

static int log_dst_parser(const char *s)
{
	log_dst = s;
	return 0;
}

static struct option_parser log_parsers[] = {
	{ "level=", log_level_parser },
	{ "dir=", log_dir_parser },
	{ "format=", log_format_parser },
	{ "dst=", log_dst_parser },
	{ NULL, NULL },
};

static int wq_net_threads;
static int wq_net_parser(const char *s)
{
	wq_net_threads = atoi(s);
	return 0;
}

static int wq_gway_threads;
static int wq_gway_parser(const char *s)
{
	wq_gway_threads = atoi(s);
	return 0;
}

static int wq_io_threads;
static int wq_io_parser(const char *s)
{
	wq_io_threads = atoi(s);
	return 0;
}

static int wq_peer_threads;
static int wq_peer_parser(const char *s)
{
	wq_peer_threads = atoi(s);
	return 0;
}

static int wq_reclaim_threads;
static int wq_reclaim_parser(const char *s)
{
	wq_reclaim_threads = atoi(s);
	return 0;
}

static int wq_gway_fwd_threads;
static int wq_gway_fwd_parser(const char *s)
{
	wq_gway_fwd_threads = atoi(s);
	return 0;
}

static int wq_remove_threads;
static int wq_remove_parser(const char *s)
{
	wq_remove_threads = atoi(s);
	return 0;
}

static int wq_remove_peer_threads;
static int wq_remove_peer_parser(const char *s)
{
	wq_remove_peer_threads = atoi(s);
	return 0;
}

static int wq_recovery_threads;
static int wq_recovery_parser(const char *s)
{
	wq_recovery_threads = atoi(s);
	return 0;
}

static int wq_async_threads;
static int wq_async_parser(const char *s)
{
	wq_async_threads = atoi(s);
	return 0;
}

static struct option_parser wq_parsers[] = {
	{ "net=", wq_net_parser },
	{ "gway=", wq_gway_parser },
	{ "io=", wq_io_parser },
	{ "peer=", wq_peer_parser },
	{ "reclaim=", wq_reclaim_parser },
	{ "gway_fwd=", wq_gway_fwd_parser },
	{ "remove=", wq_remove_parser },
	{ "remove_peer=", wq_remove_peer_parser },
	{ "recovery=", wq_recovery_parser },
	{ "async=", wq_async_parser },
};

static const char *io_addr, *io_pt;
static int ionic_host_parser(const char *s)
{
	io_addr = s;
	return 0;
}

static int ionic_port_parser(const char *s)
{
	io_pt = s;
	return 0;
}

#ifdef HAVE_ACCELIO
static const char *io_transport;
static int ionic_transport_parser(const char *s)
{
	io_transport = s;
	return 0;
}
#endif

static struct option_parser ionic_parsers[] = {
	{ "host=", ionic_host_parser },
	{ "port=", ionic_port_parser },
#ifdef HAVE_ACCELIO
	{ "transport=", ionic_transport_parser },
#endif
	{ NULL, NULL },
};

static char jpath[PATH_MAX];
static bool jskip;
static uint64_t jsize;

static int journal_dir_parser(const char *s)
{
	snprintf(jpath, sizeof(jpath), "%s", s);
	return 0;
}

static int journal_size_parser(const char *s)
{
	if (option_parse_size(s, &jsize) < 0)
		return -1;
#define MIN_JOURNAL_SIZE (64*1024*1024) /* 64M */
	if (jsize < MIN_JOURNAL_SIZE) {
		sd_err("invalid size %s, must be bigger than %u(M)",
		       s, MIN_JOURNAL_SIZE/1024/1024);
		return -1;
	}
	return 0;
}

static int journal_skip_parser(const char *s)
{
	jskip = true;
	return 0;
}

static struct option_parser journal_parsers[] = {
	{ "dir=", journal_dir_parser },
	{ "size=", journal_size_parser },
	{ "skip", journal_skip_parser },
	{ NULL, NULL },
};

static uint32_t max_exec_count;
static uint64_t queue_work_interval;
static int max_exec_count_parser(const char *s)
{
	max_exec_count = strtol(s, NULL, 10);
	return 0;
}

static int queue_work_interval_parser(const char *s)
{
	queue_work_interval = strtol(s, NULL, 10);
	return 0;
}

static struct option_parser recovery_parsers[] = {
	{ "max=", max_exec_count_parser },
	{ "interval=", queue_work_interval_parser },
	{ NULL, NULL },
};

static size_t get_nr_nodes(void)
{
	struct vnode_info *vinfo;
	size_t nr = 1;

	vinfo = get_vnode_info();
	if (vinfo != NULL)
		nr = vinfo->nr_nodes;
	put_vnode_info(vinfo);

	return nr;
}

static int create_work_queues(void)
{
	struct work_queue *util_wq;

	if (init_work_queue(get_nr_nodes))
		return -1;

	if (wq_net_threads) {
		sd_info("# of threads in net workqueue: %d", wq_net_threads);
		sys->net_wqueue = create_fixed_work_queue("net", wq_net_threads);
	} else {
		sd_info("net workqueue is created as dynamic");
		sys->net_wqueue = create_work_queue("net", WQ_DYNAMIC);
	}
	if (wq_gway_threads) {
		sd_info("# of threads in gway workqueue: %d", wq_gway_threads);
		sys->gateway_wqueue = create_fixed_work_queue("gway", wq_gway_threads);
	} else {
		sd_info("gway workqueue is created as dynamic");
		sys->gateway_wqueue = create_work_queue("gway", WQ_DYNAMIC);
	}
	if (wq_io_threads) {
		sd_info("# of threads in io workqueue: %d", wq_io_threads);
		sys->io_wqueue = create_fixed_work_queue("io", wq_io_threads);
	} else {
		sd_info("io workqueue is created as dynamic");
		sys->io_wqueue = create_work_queue("io", WQ_DYNAMIC);
	}
	if (wq_peer_threads) {
		sd_info("# of threads in peer workqueue: %d", wq_peer_threads);
		sys->peer_wqueue = create_fixed_work_queue("peer", wq_peer_threads);
	} else {
		sd_info("peer workqueue is created as dynamic");
		sys->peer_wqueue = create_work_queue("peer", WQ_DYNAMIC);
	}
	if (wq_reclaim_threads) {
		sd_info("# of threads in reclaim workqueue: %d", wq_reclaim_threads);
		sys->reclaim_wqueue = create_fixed_work_queue("reclaim", wq_reclaim_threads);
	} else {
		sd_info("reclaim workqueue is created as dynamic");
		sys->reclaim_wqueue = create_work_queue("reclaim", WQ_DYNAMIC);
	}
	if (wq_gway_fwd_threads) {
		sd_info("# of threads in gway_fwd workqueue: %d", wq_gway_fwd_threads);
		sys->gateway_fwd_wqueue = create_fixed_work_queue("gway_fwd", wq_gway_fwd_threads);
	} else {
		sd_info("gway_fwd workqueue is created as dynamic");
		sys->gateway_fwd_wqueue = create_work_queue("gway_fwd", WQ_DYNAMIC);
	}
	if (wq_remove_threads) {
		sd_info("# of threads in remove workqueue: %d", wq_remove_threads);
		sys->remove_wqueue = create_fixed_work_queue("remove", wq_remove_threads);
	} else {
		sd_info("remove workqueue is created as dynamic");
		sys->remove_wqueue = create_work_queue("remove", WQ_DYNAMIC);
	}
	if (wq_remove_peer_threads) {
		sd_info("# of threads in remove_peer workqueue: %d", wq_remove_peer_threads);
		sys->remove_peer_wqueue = create_fixed_work_queue("remove_peer", wq_remove_peer_threads);
	} else {
		sd_info("remove_peer workqueue is created as dynamic");
		sys->remove_peer_wqueue = create_work_queue("remove_peer", WQ_DYNAMIC);
	}
	if (wq_recovery_threads) {
		sd_info("# of threads in rw workqueue: %d", wq_recovery_threads);
		sys->recovery_wqueue = create_fixed_work_queue("rw", wq_recovery_threads);
	} else {
		sd_info("recovery workqueue is created as dynamic");
		sys->recovery_wqueue = create_work_queue("rw", WQ_DYNAMIC);
	}
	sys->deletion_wqueue = create_ordered_work_queue("deletion");
	sys->block_wqueue = create_ordered_work_queue("block");
	sys->md_wqueue = create_ordered_work_queue("md");
	if (wq_async_threads) {
		sd_info("# of threads in async_req workqueue: %d", wq_async_threads);
		sys->areq_wqueue = create_fixed_work_queue("async_req", wq_async_threads);
	} else {
		sd_info("async_req workqueue is created as dynamic");
		sys->areq_wqueue = create_work_queue("async_req", WQ_DYNAMIC);
	}
	if (!sys->gateway_wqueue || !sys->io_wqueue || !sys->recovery_wqueue ||
	    !sys->deletion_wqueue || !sys->block_wqueue || !sys->md_wqueue ||
	    !sys->areq_wqueue || !sys->peer_wqueue || !sys->reclaim_wqueue ||
	    !sys->gateway_fwd_wqueue)
			return -1;

	util_wq = create_ordered_work_queue("util");
	if (!util_wq)
		return -1;
	register_util_wq(util_wq);

	return 0;
}

/*
 * FIXME: Teach sheep handle EMFILE gracefully.
 *
 * For now we only set a large enough value to run sheep safely.
 *
 * We just estimate we at most run 100 VMs for each node and each VM consumes 10
 * FDs at peak rush hour.
 */
#define SD_RLIM_NOFILE (SD_MAX_NODES * 100 * 10)

static void check_host_env(void)
{
	struct rlimit r;

	if (getrlimit(RLIMIT_NOFILE, &r) < 0)
		sd_err("failed to get nofile %m");
	else if (r.rlim_cur < SD_RLIM_NOFILE) {
		r.rlim_cur = SD_RLIM_NOFILE;
		r.rlim_max = SD_RLIM_NOFILE;
		if (setrlimit(RLIMIT_NOFILE, &r) != 0) {
			sd_err("failed to set nofile to suggested %lu, %m",
			       r.rlim_cur);
			sd_err("please increase nofile via sysctl fs.nr_open");
		} else {
			sd_info("allowed open files set to suggested %lu",
				r.rlim_cur);
		}
	}

	if (getrlimit(RLIMIT_CORE, &r) < 0)
		sd_debug("failed to get core %m");
	else if (r.rlim_cur < RLIM_INFINITY)
		sd_debug("allowed core file size %lu, suggested unlimited",
			 r.rlim_cur);

	/*
	 * Disable glibc's dynamic mmap threshold and set it as 512k.
	 *
	 * We have to disable dynamic threshold because its inefficiency to
	 * release freed memory back to OS. Setting it as 512k practically means
	 * allocation larger than or equal to 512k will use mmap() for malloc()
	 * and munmap() for free(), guaranteeing allocated memory will not be
	 * cached in the glibc's ptmalloc internal pool.
	 *
	 * 512k is not a well tested optimal value for IO request size, I choose
	 * it because it is default value for disk drive that it can transfer at
	 * a time. So default installation of guest will issue at most 512K
	 * sized request.
	 */
	mallopt(M_MMAP_THRESHOLD, 512 * 1024);
}

static int lock_and_daemon(bool daemonize, const char *base_dir)
{
	int ret, devnull_fd = 0, status = 0;
	int pipefd[2];

	ret = pipe(pipefd);
	if (ret < 0)
		panic("pipe() for passing exit status failed: %m");

	if (daemonize) {
		switch (fork()) {
		case 0:
			break;
		case -1:
			panic("fork() failed during daemonize: %m");
			break;
		default:
			ret = read(pipefd[0], &status, sizeof(status));
			if (ret != sizeof(status))
				panic("read exit status failed: %m");

			_exit(status);
			break;
		}

		if (setsid() == -1) {
			sd_err("becoming a leader of a new session failed: %m");
			status = 1;
			goto end;
		}

		switch (fork()) {
		case 0:
			break;
		case -1:
			sd_err("fork() failed during daemonize: %m");
			status = 1;
			goto end;
		default:
			_exit(0);
			break;
		}

		if (chdir("/")) {
			sd_err("chdir to / failed: %m");
			status = 1;
			goto end;
		}

		devnull_fd = open("/dev/null", O_RDWR);
		if (devnull_fd < 0) {
			sd_err("opening /dev/null failed: %m");
			status = 1;
			goto end;
		}
	}

	ret = lock_base_dir(base_dir);
	if (ret < 0) {
		sd_err("locking directory: %s failed", base_dir);
		status = 1;
		goto end;
	}

	if (daemonize) {
		/*
		 * now we can use base_dir/sheep.log for logging error messages,
		 * we can close 0, 1, and 2 safely
		 */
		dup2(devnull_fd, 0);
		dup2(devnull_fd, 1);
		dup2(devnull_fd, 2);

		close(devnull_fd);
	}

end:
	ret = write(pipefd[1], &status, sizeof(status));
	if (ret != sizeof(status))
		panic("writing exit status failed: %m");

	return status;
}

static void sighup_handler(int signo, siginfo_t *info, void *context)
{
	if (unlikely(logger_pid == -1))
		return;

	/* forward SIGHUP for log rotating */
	kill(logger_pid, SIGHUP);
}

static void show_features(int feat) /* feat: 0; show cdrv only */
{
	struct cluster_driver *cdrv;

	fprintf(stdout, "\nSupported features:\n");
	/* show cluster driver */
	if (!sys->cdrv) {
		fprintf(stdout, "\tCluster drivers:");
		FOR_EACH_CLUSTER_DRIVER(cdrv) {
			fprintf(stdout, " %s", cdrv->name);
		}
		fprintf(stdout, "\n");
	}

	if (feat) {
		/* show other features */
		fprintf(stdout, "\tMiscellaneous:");
		int have_feats = 0;
#ifdef HAVE_HTTP
		fprintf(stdout, " http");
		have_feats = 1;
#endif
#ifdef HAVE_NFS
		fprintf(stdout, " nfs");
		have_feats = 1;
#endif
#ifdef HAVE_DISKVNODES
		fprintf(stdout, " diskvnodes");
		have_feats = 1;
#endif
#ifdef HAVE_LTTNG_UST
		fprintf(stdout, " lttng-ust");
		have_feats = 1;
#endif
#ifdef HAVE_ACCELIO
		fprintf(stdout, " accelio");
		have_feats = 1;
#endif
#ifdef HAVE_TRACE
		fprintf(stdout, " trace");
		have_feats = 1;
#endif
		if (!have_feats)
			fprintf(stdout, " none");
		fprintf(stdout, "\n");
	}
}

int main(int argc, char **argv)
{
	int ch, longindex, ret, port = SD_LISTEN_PORT, io_port = SD_LISTEN_PORT;
	int rc = 1;
	const char *dirp = DEFAULT_OBJECT_DIR, *short_options;
	char *dir, *pid_file = NULL, *bindaddr = NULL, log_path[PATH_MAX],
	     *argp = NULL;
	bool explicit_addr = false;
	bool daemonize = true;
	int32_t nr_vnodes = -1;
	int64_t zone = -1;
	uint32_t max_dynamic_threads = 0;
	struct option *long_options;
#ifdef HAVE_HTTP
	const char *http_options = NULL;
#endif
	static struct logger_user_info sheep_info;
	struct stat logdir_st;
	enum log_dst_type log_dst_type;

	sys->cinfo.flags |= SD_CLUSTER_FLAG_AUTO_VNODES;
	sys->node_status = SD_NODE_STATUS_INITIALIZATION;

	sys->rthrottling.max_exec_count = 0;
	sys->rthrottling.queue_work_interval = 0;
	sys->rthrottling.throttling = false;

	install_crash_handler(crash_handler);
	signal(SIGPIPE, SIG_IGN);

	install_sighandler(SIGHUP, sighup_handler, false);

	long_options = build_long_options(sheep_options);
	short_options = build_short_options(sheep_options);
	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			port = str_to_u16(optarg);
			if (errno != 0 || port < 1) {
				sd_err("Invalid port number '%s'", optarg);
				exit(1);
			}
			break;
		case 'P':
			pid_file = optarg;
			break;
#ifdef HAVE_HTTP
		case 'r':
			http_options = optarg;
			break;
#endif
		case 'l':
			if (option_parse(optarg, ",", log_parsers) < 0)
				exit(1);
			break;
		case 'n':
			sys->nosync = true;
			break;
		case 'y':
			if (!str_to_addr(optarg, sys->this_node.nid.addr)) {
				sd_err("Invalid address: '%s'", optarg);
				exit(1);
			}
			explicit_addr = true;
			break;
		case 'D':
			sys->backend_dio = true;
			break;
		case 'f':
			daemonize = false;
			break;
		case 'g':
			if (nr_vnodes > 0) {
				sd_err("Options '-g' and '-V' can not be both specified");
				exit(1);
			}
			nr_vnodes = 0;
			break;
		case 'z':
			zone = str_to_u32(optarg);
			if (errno != 0) {
				sd_err("Invalid zone id '%s': must be "
				       "an integer between 0 and %u", optarg,
				       UINT32_MAX);
				exit(1);
			}
			sys->this_node.zone = zone;
			break;
		case 'u':
			sys->upgrade = true;
			break;
		case 'c':
			sys->cdrv = find_cdrv(optarg);
			if (!sys->cdrv) {
				sd_err("Invalid cluster driver '%s'", optarg);
				show_features(0);
				exit(1);
			}

			sys->cdrv_option = get_cdrv_option(sys->cdrv, optarg);
			break;
		case 'i':
			if (option_parse(optarg, ",", ionic_parsers) < 0)
				exit(1);

			if (!str_to_addr(io_addr, sys->this_node.nid.io_addr)) {
				sd_err("Bad addr: '%s'", io_addr);
				exit(1);
			}

			if (io_pt)
				if (sscanf(io_pt, "%u", &io_port) != 1) {
					sd_err("Bad port '%s'", io_pt);
					exit(1);
				}
			sys->this_node.nid.io_port = io_port;
#ifdef HAVE_ACCELIO
			if (!strcmp(io_transport, "tcp"))
				sys->this_node.nid.io_transport_type =
					IO_TRANSPORT_TYPE_TCP;
			else if (!strcmp(io_transport, "rdma"))
				sys->this_node.nid.io_transport_type =
					IO_TRANSPORT_TYPE_RDMA;
			else {
				sd_err("unknown transport type: %s",
				       io_transport);
				exit(1);
			}
#endif
			break;
		case 'j':
			uatomic_set_true(&sys->use_journal);
			if (option_parse(optarg, ",", journal_parsers) < 0)
				exit(1);
			if (!jsize) {
				sd_err("you must specify size for journal");
				exit(1);
			}
			break;
		case 'b':
			if (!inetaddr_is_valid(optarg))
				exit(1);
			bindaddr = optarg;
			break;
		case 'h':
			usage(0);
			break;
		case 'R':
			if (option_parse(optarg, ",", recovery_parsers) < 0)
				exit(1);
			sys->rthrottling.max_exec_count = max_exec_count;
			sys->rthrottling.queue_work_interval
						 = queue_work_interval;
			if (max_exec_count > 0 && queue_work_interval > 0)
				sys->rthrottling.throttling = true;
			break;
		case 'v':
			fprintf(stdout, "Sheepdog daemon version %s\n",
				PACKAGE_VERSION);
			show_features(1);
			exit(0);
			break;
		case 'V':
			sys->cinfo.flags &= ~SD_CLUSTER_FLAG_AUTO_VNODES;
			if (nr_vnodes == 0) {
				sd_err("Options '-g' and '-V' can not be both specified");
				exit(1);
			}
			nr_vnodes = str_to_u16(optarg);
			if (errno != 0 || nr_vnodes < 1) {
				sd_err("Invalid number of vnodes '%s': must be "
					"an integer between 1 and %u",
					optarg, UINT16_MAX);
				exit(1);
			}
			break;
		case 'W':
			wildcard_recovery = true;
			break;
		case 'w':
			if (option_parse(optarg, ",", wq_parsers) < 0)
				exit(1);
			break;
		case 'x':
			max_dynamic_threads = str_to_u32(optarg);
			if (errno != 0 || max_dynamic_threads < 1) {
				sd_err("Invalid number of threads '%s': "
				       "must be an integer between 1 and %"PRIu32,
				       optarg, UINT32_MAX);
				exit(1);
			}
			set_max_dynamic_threads((size_t)max_dynamic_threads);
			break;
		default:
			usage(1);
			break;
		}
	}

	#ifdef HAVE_DISKVNODES
	sys->cinfo.flags |= SD_CLUSTER_FLAG_DISKMODE;
	#endif

	sheep_info.port = port;
	early_log_init(log_format, &sheep_info);

	if (nr_vnodes == 0) {
		sys->gateway_only = true;
		sys->disk_space = 0;
	} else if (nr_vnodes == -1)
		nr_vnodes = SD_DEFAULT_VNODES;

	if (optind != argc) {
		argp = strdup(argv[optind]);
		dirp = strtok(argv[optind], ",");
	}

	ret = sd_inode_actor_init(sheep_bnode_writer, sheep_bnode_reader);
	if (ret)
		exit(1);

	if (!strcmp(log_dst, "default"))
		log_dst_type = LOG_DST_DEFAULT;
	else if (!strcmp(log_dst, "stdout"))
		log_dst_type = LOG_DST_STDOUT;
	else if (!strcmp(log_dst, "syslog"))
		log_dst_type = LOG_DST_SYSLOG;
	else {
		sd_err("invalid type of log destination: %s", log_dst);
		exit(1);
	}

	if (logdir) {
		if (log_dst_type != LOG_DST_DEFAULT) {
			sd_err("logdir (%s) is specified but logging"
			       " destination is %s", logdir,
			       log_dst_type == LOG_DST_STDOUT
			       ? "stdout" : "syslog");
			exit(1);
		}

		memset(&logdir_st, 0, sizeof(logdir_st));
		ret = stat(logdir, &logdir_st);
		if (ret < 0) {
			sd_err("stat() failed on %s, %m", logdir);
			exit(1);
		}

		if (!S_ISDIR(logdir_st.st_mode)) {
			sd_err("log dir: %s is not a directory", logdir);
			exit(1);
		}
	}

	ret = init_base_path(dirp);
	if (ret)
		exit(1);

	dir = realpath(dirp, NULL);
	if (!dir) {
		sd_err("%m");
		exit(1);
	}

	snprintf(log_path, sizeof(log_path), "%s/" LOG_FILE_NAME,
		 logdir ?: dir);

	free(logdir);

	srandom(port);

	if (daemonize && log_dst_type == LOG_DST_STDOUT)
		daemonize = false;

	if (lock_and_daemon(daemonize, dir)) {
		free(argp);
		goto cleanup_dir;
	}

#ifdef HAVE_ACCELIO
	sd_xio_init();
	xio_init_main_ctx();
#endif

	ret = log_init(program_name, log_dst_type, log_level, log_path);
	if (ret) {
		free(argp);
		goto cleanup_dir;
	}

	ret = init_global_pathnames(dir, argp);
	free(argp);
	if (ret)
		goto cleanup_log;

	ret = init_event(EPOLL_SIZE);
	if (ret)
		goto cleanup_log;

	ret = init_node_config_file();
	if (ret)
		goto cleanup_log;

	ret = init_config_file();
	if (ret)
		goto cleanup_log;

	ret = create_listen_port(bindaddr, port);
	if (ret)
		goto cleanup_log;

#ifndef HAVE_ACCELIO
	if (io_addr && create_listen_port(io_addr, io_port))
		goto cleanup_log;
#else
	if (io_addr) {
		bool rdma;

		if (!strcmp(io_transport, "rdma"))
			rdma = true;
		else {
			sd_assert(!strcmp(io_transport, "tcp"));
			rdma = false;
		}

		if (xio_create_listen_port(io_addr, io_port, rdma))
			goto cleanup_log;
	} else {
		sd_err("accelio is enabled but io address (-i) isn't passed, exiting");
		goto cleanup_log;
	}
#endif

	ret = init_unix_domain_socket(dir);
	if (ret)
		goto cleanup_log;

	local_request_init();

	ret = init_signal();
	if (ret)
		goto cleanup_log;

	/* This function must be called before create_cluster() */
	ret = init_disk_space(dir);
	if (ret)
		goto cleanup_log;

	ret = create_cluster(port, zone, nr_vnodes, explicit_addr);
	if (ret) {
		sd_err("failed to create sheepdog cluster");
		goto cleanup_log;
	}

	ret = start_node_connectivity_monitor();
	if (ret)
		goto cleanup_journal;

	/* We should init trace for work queue before journal init */
	ret = wq_trace_init();
	if (ret) {
		sd_err("failed to init trace for work queue");
		goto cleanup_log;
	}

	/* We should init journal file before backend init */
	if (uatomic_is_true(&sys->use_journal)) {
		if (!strlen(jpath))
			/* internal journal */
			memcpy(jpath, dir, strlen(dir));
		sd_debug("%s, %"PRIu64", %d", jpath, jsize, jskip);
		ret = journal_file_init(jpath, jsize, jskip);
		if (ret)
			goto cleanup_cluster;
	}

	init_fec();

	/*
	 * After this function, we are multi-threaded.
	 *
	 * Put those init functions that need single threaded environment, for
	 * e.g, signal handling, above this call and those need multi-threaded
	 * environment, for e.g, work queues below.
	 */
	ret = create_work_queues();
	if (ret)
		goto cleanup_journal;

	ret = sockfd_init();
	if (ret)
		goto cleanup_journal;

	ret = init_store_driver(sys->gateway_only);
	if (ret)
		goto cleanup_journal;

	ret = trace_init();
	if (ret)
		goto cleanup_journal;

	#ifdef HAVE_HTTP
	if (http_options && http_init(http_options) != 0)
		goto cleanup_journal;
	#endif

	#ifdef HAVE_NFS
	ret = nfs_init(NULL);
	if (ret)
		goto cleanup_journal;
	#endif

	if (pid_file && (create_pidfile(pid_file) != 0)) {
		sd_err("failed to pid file '%s' - %m", pid_file);
		goto cleanup_journal;
	}

	if (chdir(dir) < 0) {
		sd_err("failed to chdir to %s: %m", dir);
		goto cleanup_pid_file;
	}

	check_host_env();
	sd_info("sheepdog daemon (version %s) started", PACKAGE_VERSION);

	while (sys->nr_outstanding_reqs != 0 ||
	       (sys->cinfo.status != SD_STATUS_KILLED &&
		sys->cinfo.status != SD_STATUS_SHUTDOWN))
		event_loop(-1);

	rc = 0;
	sd_info("shutdown");

cleanup_pid_file:
	if (pid_file)
		unlink(pid_file);

cleanup_journal:
	if (uatomic_is_true(&sys->use_journal)) {
		sd_info("cleaning journal file");
		clean_journal_file(jpath);
	}

cleanup_cluster:
	leave_cluster();

cleanup_log:
	log_close();

cleanup_dir:
	free(dir);

	return rc;
}
