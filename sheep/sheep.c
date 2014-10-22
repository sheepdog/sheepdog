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

static const char http_help[] =
"Available arguments:\n"
"\thost=: specify a host to communicate with http server (default: localhost)\n"
"\tport=: specify a port to communicate with http server (default: 8000)\n"
"\tbuffer=: specify buffer size for http request (default: 32M)\n"
"\tswift: enable swift API\n"
"Example:\n\t$ sheep -r host=localhost,port=7001,buffer=64M,swift ...\n"
"This tries to enable Swift API and use localhost:7001 to\n"
"communicate with http server, using 64MB buffer.\n";

static const char myaddr_help[] =
"Example:\n\t$ sheep -y 192.168.1.1:7000 ...\n"
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
"\n\tzookeeper arguments: address-list,timeout=value (default as 3000)\n"
"\nExample:\n\t"
"$ sheep -c zookeeper:IP1:PORT1,IP2:PORT2,IP3:PORT3,timeout=1000 ...\n"
"This tries to use 3 node zookeeper cluster, which can be reached by\n"
"IP1:PORT1, IP2:PORT2, IP3:PORT3 to manage membership and broadcast message\n"
"and set the timeout of node heartbeat as 1000 milliseconds\n";

static const char cache_help[] =
"Available arguments:\n"
"\tsize=: size of the cache in megabytes\n"
"\tdir=: path to the location of the cache (default: $STORE/cache)\n"
"\tdirectio: use directio mode for cache IO, "
"if not specified use buffered IO\n"
"\nExample:\n\t$ sheep -w size=200G,dir=/my_ssd,directio ...\n"
"This tries to use /my_ssd as the cache storage with 200G allocted to the\n"
"cache in directio mode\n";

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

static struct sd_option sheep_options[] = {
	{'b', "bindaddr", true, "specify IP address of interface to listen on",
	 bind_help},
	{'c', "cluster", true,
	 "specify the cluster driver (default: "DEFAULT_CLUSTER_DRIVER")",
	 cluster_help},
	{'D', "directio", false, "use direct IO for backend store"},
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
	{'r', "http", true, "enable http service. (default: disabled)",
	 http_help},
	{'u', "upgrade", false, "upgrade to the latest data layout"},
	{'v', "version", false, "show the version"},
	{'w', "cache", true, "enable object cache", cache_help},
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
	assert(ret == sizeof(siginfo));
	sd_debug("signal %d", siginfo.ssi_signo);
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

static void crash_handler(int signo)
{
	sd_emerg("sheep exits unexpectedly (%s).", strsignal(signo));

	sd_backtrace();
	sd_dump_variable(__sys);

	reraise_crash_signal(signo, 1);
}

static struct system_info __sys;
struct system_info *sys = &__sys;

static int cache_size_parser(const char *s)
{
	const uint64_t max_cache_size = ((uint64_t)UINT32_MAX + 1)*1024*1024;
	uint64_t cache_size;

	if (option_parse_size(s, &cache_size) < 0)
		return -1;
#define MIN_CACHE_SIZE (10*1024*1024) /* 10M */
	if (cache_size < MIN_CACHE_SIZE || cache_size > max_cache_size) {
		sd_err("Invalid cache option '%s': size must be between "
		       "between %uM and %" PRIu64 "G", s,
		       MIN_CACHE_SIZE/1024/1024, max_cache_size/1024/1024/1024);
		return -1;
	}

	sys->object_cache_size = cache_size / 1024 / 1024;
	return 0;
}

static int cache_directio_parser(const char *s)
{
	sys->object_cache_directio = true;
	return 0;
}

static char ocpath[PATH_MAX];

static int cache_dir_parser(const char *s)
{
	snprintf(ocpath, sizeof(ocpath), "%s", s);
	return 0;
}

static struct option_parser cache_parsers[] = {
	{ "size=", cache_size_parser },
	{ "directio", cache_directio_parser },
	{ "dir=", cache_dir_parser },
	{ NULL, NULL },
};

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

static struct option_parser ionic_parsers[] = {
	{ "host=", ionic_host_parser },
	{ "port=", ionic_port_parser },
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

	sys->net_wqueue = create_work_queue("net", WQ_UNLIMITED);
	sys->gateway_wqueue = create_work_queue("gway", WQ_UNLIMITED);
	sys->io_wqueue = create_work_queue("io", WQ_UNLIMITED);
	sys->recovery_wqueue = create_work_queue("rw", WQ_UNLIMITED);
	sys->deletion_wqueue = create_ordered_work_queue("deletion");
	sys->block_wqueue = create_ordered_work_queue("block");
	sys->md_wqueue = create_ordered_work_queue("md");
	sys->areq_wqueue = create_work_queue("async_req", WQ_UNLIMITED);
	if (sys->enable_object_cache) {
		sys->oc_reclaim_wqueue =
			create_ordered_work_queue("oc_reclaim");
		sys->oc_push_wqueue = create_work_queue("oc_push", WQ_DYNAMIC);
		if (!sys->oc_reclaim_wqueue || !sys->oc_push_wqueue)
			return -1;
	}
	if (!sys->gateway_wqueue || !sys->io_wqueue || !sys->recovery_wqueue ||
	    !sys->deletion_wqueue || !sys->block_wqueue || !sys->md_wqueue ||
	    !sys->areq_wqueue)
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
	/*
	 * 1024 is default for NOFILE on most distributions, which is very
	 * dangerous to run Sheepdog cluster.
	 */
	else if (r.rlim_cur == 1024)
		sd_warn("Allowed open files 1024 too small, suggested %u",
			SD_RLIM_NOFILE);
	else if (r.rlim_cur < SD_RLIM_NOFILE)
		sd_info("Allowed open files %lu, suggested %u", r.rlim_cur,
			SD_RLIM_NOFILE);

	if (getrlimit(RLIMIT_CORE, &r) < 0)
		sd_debug("failed to get core %m");
	else if (r.rlim_cur < RLIM_INFINITY)
		sd_debug("Allowed core file size %lu, suggested unlimited",
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

			exit(status);
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
			exit(0);
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

static void sighup_handler(int signum)
{
	if (unlikely(logger_pid == -1))
		return;

	/* forward SIGHUP for log rotating */
	kill(logger_pid, SIGHUP);
}

int main(int argc, char **argv)
{
	int ch, longindex, ret, port = SD_LISTEN_PORT, io_port = SD_LISTEN_PORT;
	int nr_vnodes = SD_DEFAULT_VNODES, rc = 1;
	const char *dirp = DEFAULT_OBJECT_DIR, *short_options;
	char *dir, *p, *pid_file = NULL, *bindaddr = NULL, log_path[PATH_MAX],
	     *argp = NULL;
	bool explicit_addr = false;
	int64_t zone = -1;
	struct cluster_driver *cdrv;
	struct option *long_options;
	const char *http_options = NULL;
	static struct logger_user_info sheep_info;
	struct stat logdir_st;
	enum log_dst_type log_dst_type;

	sys->node_status = SD_NODE_STATUS_INITIALIZATION;

	install_crash_handler(crash_handler);
	signal(SIGPIPE, SIG_IGN);

	install_sighandler(SIGHUP, sighup_handler, false);

	long_options = build_long_options(sheep_options);
	short_options = build_short_options(sheep_options);
	while ((ch = getopt_long(argc, argv, short_options, long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'p':
			port = strtol(optarg, &p, 10);
			if (optarg == p || port < 1 || UINT16_MAX < port
				|| *p != '\0') {
				sd_err("Invalid port number '%s'", optarg);
				exit(1);
			}
			break;
		case 'P':
			pid_file = optarg;
			break;
		case 'r':
			http_options = optarg;
			break;
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
		case 'g':
			/* same as '-v 0' */
			nr_vnodes = 0;
			break;
		case 'z':
			zone = strtol(optarg, &p, 10);
			if (optarg == p || zone < 0 || UINT32_MAX < zone
				|| *p != '\0') {
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
				fprintf(stderr, "Supported drivers:");
				FOR_EACH_CLUSTER_DRIVER(cdrv) {
					fprintf(stderr, " %s", cdrv->name);
				}
				fprintf(stderr, "\n");
				exit(1);
			}

			sys->cdrv_option = get_cdrv_option(sys->cdrv, optarg);
			break;
		case 'w':
			sys->enable_object_cache = true;
			sys->object_cache_size = 0;

			if (option_parse(optarg, ",", cache_parsers) < 0)
				exit(1);

			if (sys->object_cache_size == 0) {
				sd_err("object cache size is not set");
				exit(1);
			}
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
		case 'v':
			fprintf(stdout, "Sheepdog daemon version %s\n",
				PACKAGE_VERSION);
			exit(0);
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
	}

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

	if (lock_and_daemon(log_dst_type != LOG_DST_STDOUT, dir)) {
		free(argp);
		goto cleanup_dir;
	}

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

	ret = init_config_file();
	if (ret)
		goto cleanup_log;

	ret = create_listen_port(bindaddr, port);
	if (ret)
		goto cleanup_log;

	if (io_addr && create_listen_port(io_addr, io_port))
		goto cleanup_log;

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

	if (sys->enable_object_cache) {
		if (!strlen(ocpath))
			/* use object cache internally */
			memcpy(ocpath, dir, strlen(dir));
		ret = object_cache_init(ocpath);
		if (ret)
			goto cleanup_journal;
	}

	ret = trace_init();
	if (ret)
		goto cleanup_journal;

	if (http_options && http_init(http_options) != 0)
		goto cleanup_journal;

	ret = nfs_init(NULL);
	if (ret)
		goto cleanup_journal;

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
