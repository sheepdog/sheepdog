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

#include <sys/signalfd.h>
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
"\nExample:\n\t$ sheep -j dir=/journal,size=1024\n"
"This tries to use /journal as the journal storage of the size 1024M\n";

static const char loglevel_help[] =
"Available log levels:\n"
"  #    Level           Description\n"
"  0    SDOG_EMERG      system has failed and is unusable\n"
"  1    SDOG_ALERT      action must be taken immediately\n"
"  2    SDOG_CRIT       critical conditions\n"
"  3    SDOG_ERR        error conditions\n"
"  4    SDOG_WARNING    warning conditions\n"
"  5    SDOG_NOTICE     normal but significant conditions\n"
"  6    SDOG_INFO       informational notices\n"
"  7    SDOG_DEBUG      debugging messages\n"
"\nExample:\n\t$ sheep -l 4 ...\n"
"This only allows logs with level smaller than SDOG_WARNING to be logged\n";

static const char http_help[] =
"Example:\n\t$ sheep -r localhost:7001 ...\n"
"This tries to enable sheep as http service backend and use localhost:7001 to\n"
"communicate with http server. Not fully implemented yet.\n";

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
"\tcorosync: use corosync driver (default)\n"
"\tzookeeper: use zookeeper driver, need extra arguments\n"
"\n\tzookeeper arguments: address-list,tiemout=value (default as 3000)\n"
"\nExample:\n\t"
"$ sheep -c zookeeperr:IP1:PORT1,IP2:PORT2,IP3:PORT3,timeout=1000 ...\n"
"This tries to use 3 node zookeeper cluster, which can be reached by\n"
"IP1:PORT1, IP2:PORT2, IP3:PORT3 to manage membership and broadcast message\n"
"and set the timeout of node heartbeat as 1000 milliseconds\n";

static const char cache_help[] =
"Available arguments:\n"
"\tsize=: size of the cache in megabyes\n"
"\tdir=: path to the location of the cache (default: $STORE/cache)\n"
"\tdirectio: use directio mode for cache IO, "
"if not specified use buffered IO\n"
"\nExample:\n\t$ sheep -w size=200000,dir=/my_ssd,directio ...\n"
"This tries to use /my_ssd as the cache storage with 200G allocted to the\n"
"cache in directio mode\n";

static struct sd_option sheep_options[] = {
	{'b', "bindaddr", true, "specify IP address of interface to listen on",
	 bind_help},
	{'c', "cluster", true,
	 "specify the cluster driver (default: "DEFAULT_CLUSTER_DRIVER")",
	 cluster_help},
	{'d', "debug", false, "include debug messages in the log"},
	{'D', "directio", false, "use direct IO for backend store"},
	{'f', "foreground", false, "make the program run in the foreground"},
	{'F', "log-format", true, "specify log format"},
	{'g', "gateway", false, "make the progam run as a gateway mode"},
	{'h', "help", false, "display this help and exit"},
	{'i', "ioaddr", true, "use separate network card to handle IO requests",
	 ioaddr_help},
	{'j', "journal", true, "use jouranl file to log all the write "
	 "operations", journal_help},
	{'l', "loglevel", true, "specify the level of logging detail "
	 "(default: 6 [SDOG_INFO])", loglevel_help},
	{'n', "nosync", false, "drop O_SYNC for write of backend"},
	{'o', "stdout", false, "log to stdout instead of shared logger"},
	{'p', "port", true, "specify the TCP port on which to listen "
	 "(default: 7000)"},
	{'P', "pidfile", true, "create a pid file"},
	{'r', "http", true, "enable http service", http_help},
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
	       "  #    Level           Description\n"
	       "  0    SDOG_EMERG      system has failed and is unusable\n"
	       "  1    SDOG_ALERT      action must be taken immediately\n"
	       "  2    SDOG_CRIT       critical conditions\n"
	       "  3    SDOG_ERR        error conditions\n"
	       "  4    SDOG_WARNING    warning conditions\n"
	       "  5    SDOG_NOTICE     normal but significant conditions\n"
	       "  6    SDOG_INFO       informational notices\n"
	       "  7    SDOG_DEBUG      debugging messages\n");
}

static int create_pidfile(const char *filename)
{
	int fd = -1;
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

static void parse_arg(char *arg, const char *delim, void (*fn)(char *))
{
	char *savep, *s;

	s = strtok_r(arg, delim, &savep);
	do {
		fn(s);
	} while ((s = strtok_r(NULL, delim, &savep)));
}

static void object_cache_size_set(char *s)
{
	const char *header = "size=";
	int len = strlen(header);
	char *size, *p;
	uint64_t cache_size;
	const uint32_t max_cache_size = UINT32_MAX;

	assert(!strncmp(s, header, len));

	size = s + len;
	cache_size = strtoull(size, &p, 10);
	if (size == p || max_cache_size < cache_size)
		goto err;

	sys->object_cache_size = cache_size;
	return;

err:
	sd_err("Invalid object cache option '%s': size must be an integer "
	       "between 1 and %" PRIu32 " inclusive", s, max_cache_size);
	exit(1);
}

static void object_cache_directio_set(char *s)
{
	assert(!strcmp(s, "directio"));
	sys->object_cache_directio = true;
}

static char ocpath[PATH_MAX];
static void object_cache_dir_set(char *s)
{
	char *p = s;

	p = p + strlen("dir=");
	snprintf(ocpath, sizeof(ocpath), "%s", p);
}

static void _object_cache_set(char *s)
{
	int i;

	struct object_cache_arg {
		const char *name;
		void (*set)(char *);
	};

	struct object_cache_arg object_cache_args[] = {
		{ "size=", object_cache_size_set },
		{ "directio", object_cache_directio_set },
		{ "dir=", object_cache_dir_set },
		{ NULL, NULL },
	};

	for (i = 0; object_cache_args[i].name; i++) {
		const char *n = object_cache_args[i].name;

		if (!strncmp(s, n, strlen(n))) {
			object_cache_args[i].set(s);
			return;
		}
	}

	sd_err("invalid object cache arg: %s", s);
	exit(1);
}

static void object_cache_set(char *arg)
{
	sys->enable_object_cache = true;
	sys->object_cache_size = 0;

	parse_arg(arg, ",", _object_cache_set);

	if (sys->object_cache_size == 0) {
		sd_err("object cache size is not set");
		exit(1);
	}
}

static char jpath[PATH_MAX];
static bool jskip;
static ssize_t jsize;
#define MIN_JOURNAL_SIZE (64) /* 64M */

static void init_journal_arg(char *arg)
{
	const char *d = "dir=", *sz = "size=", *sp = "skip";
	int dl = strlen(d), szl = strlen(sz), spl = strlen(sp);

	if (!strncmp(d, arg, dl)) {
		arg += dl;
		snprintf(jpath, sizeof(jpath), "%s", arg);
	} else if (!strncmp(sz, arg, szl)) {
		arg += szl;
		jsize = strtoll(arg, NULL, 10);
		if (jsize < MIN_JOURNAL_SIZE || jsize == LLONG_MAX) {
			sd_err("invalid size %s, must be bigger than %u(M)",
			       arg,
				MIN_JOURNAL_SIZE);
			exit(1);
		}
	} else if (!strncmp(sp, arg, spl)) {
		jskip = true;
	} else {
		sd_err("invalid paramters %s", arg);
		exit(1);
	}
}

static char *io_addr, *io_pt;
static void init_io_arg(char *arg)
{
	const char *host = "host=", *port = "port=";
	int hl = strlen(host), pl = strlen(port);

	if (!strncmp(host, arg, hl)) {
		arg += hl;
		io_addr = arg;
	} else if (!strncmp(port, arg, pl)) {
		arg += hl;
		io_pt = arg;
	} else {
		sd_err("invalid paramters %s. Use '-i host=a.b.c.d,port=xxx'",
		       arg);
		exit(1);
	}
}

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
	if (init_work_queue(get_nr_nodes))
		return -1;

	sys->gateway_wqueue = create_work_queue("gway", WQ_UNLIMITED);
	sys->io_wqueue = create_work_queue("io", WQ_UNLIMITED);
	sys->recovery_wqueue = create_ordered_work_queue("rw");
	sys->deletion_wqueue = create_ordered_work_queue("deletion");
	sys->block_wqueue = create_ordered_work_queue("block");
	sys->md_wqueue = create_ordered_work_queue("md");
	if (sys->enable_object_cache) {
		sys->oc_reclaim_wqueue =
			create_ordered_work_queue("oc_reclaim");
		sys->oc_push_wqueue = create_work_queue("oc_push", WQ_DYNAMIC);
		if (!sys->oc_reclaim_wqueue || !sys->oc_push_wqueue)
			return -1;
	}
	if (!sys->gateway_wqueue || !sys->io_wqueue || !sys->recovery_wqueue ||
	    !sys->deletion_wqueue || !sys->block_wqueue || !sys->md_wqueue)
			return -1;

	return 0;
}

/*
 * FIXME: Teach sheep handle EMFILE gracefully.
 *
 * For now we only set a large enough vaule to run sheep safely.
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
		sd_err("WARN: Allowed open files 1024 too small, suggested %u",
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

int main(int argc, char **argv)
{
	int ch, longindex, ret, port = SD_LISTEN_PORT, io_port = SD_LISTEN_PORT;
	int log_level = SDOG_INFO, nr_vnodes = SD_DEFAULT_VNODES;
	const char *dirp = DEFAULT_OBJECT_DIR, *short_options;
	char *dir, *p, *pid_file = NULL, *bindaddr = NULL, path[PATH_MAX],
	     *argp = NULL;
	bool is_daemon = true, to_stdout = false, explicit_addr = false;
	int64_t zone = -1;
	struct cluster_driver *cdrv;
	struct option *long_options;
	const char *log_format = "server", *http_address = NULL;
	static struct logger_user_info sheep_info;

	install_crash_handler(crash_handler);
	signal(SIGPIPE, SIG_IGN);

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
			http_address = optarg;
			break;
		case 'f':
			is_daemon = false;
			break;
		case 'l':
			log_level = strtol(optarg, &p, 10);
			if (optarg == p || log_level < SDOG_EMERG ||
			    SDOG_DEBUG < log_level || *p != '\0') {
				sd_err("Invalid log level '%s'", optarg);
				sdlog_help();
				exit(1);
			}
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
		case 'd':
			/* removed soon. use loglevel instead */
			log_level = SDOG_DEBUG;
			break;
		case 'D':
			sys->backend_dio = true;
			break;
		case 'g':
			/* same as '-v 0' */
			nr_vnodes = 0;
			break;
		case 'o':
			to_stdout = true;
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
			object_cache_set(optarg);
			break;
		case 'i':
			parse_arg(optarg, ",", init_io_arg);
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
			parse_arg(optarg, ",", init_journal_arg);
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
		case 'F':
			log_format = optarg;
			break;
		default:
			usage(1);
			break;
		}
	}

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

	ret = init_base_path(dirp);
	if (ret)
		exit(1);

	dir = realpath(dirp, NULL);
	if (!dir) {
		sd_err("%m");
		exit(1);
	}

	snprintf(path, sizeof(path), "%s/" LOG_FILE_NAME, dir);

	srandom(port);

	if (lock_and_daemon(is_daemon, dir))
		exit(1);

	ret = log_init(program_name, to_stdout, log_level, path);
	if (ret)
		exit(1);

	ret = init_event(EPOLL_SIZE);
	if (ret)
		exit(1);

	ret = init_global_pathnames(dir, argp);
	free(argp);
	if (ret)
		exit(1);

	ret = init_config_file();
	if (ret)
		exit(1);

	ret = create_listen_port(bindaddr, port);
	if (ret)
		exit(1);

	if (io_addr && create_listen_port(io_addr, io_port))
		exit(1);

	ret = init_unix_domain_socket(dir);
	if (ret)
		exit(1);

	local_req_init();

	ret = init_signal();
	if (ret)
		exit(1);

	/* This function must be called before create_cluster() */
	ret = init_disk_space(dir);
	if (ret)
		exit(1);

	ret = create_cluster(port, zone, nr_vnodes, explicit_addr);
	if (ret) {
		sd_err("failed to create sheepdog cluster");
		exit(1);
	}

	/* We should init journal file before backend init */
	if (uatomic_is_true(&sys->use_journal)) {
		if (!strlen(jpath))
			/* internal journal */
			memcpy(jpath, dir, strlen(dir));
		sd_debug("%s, %zd, %d", jpath, jsize, jskip);
		ret = journal_file_init(jpath, jsize, jskip);
		if (ret)
			exit(1);
	}

	/*
	 * After this function, we are multi-threaded.
	 *
	 * Put those init functions that need single threaded environment, for
	 * e.g, signal handling, above this call and those need multi-threaded
	 * environment, for e.g, work queues below.
	 */
	ret = create_work_queues();
	if (ret)
		exit(1);

	ret = sockfd_init();
	if (ret)
		exit(1);

	ret = init_store_driver(sys->gateway_only);
	if (ret)
		exit(1);

	if (sys->enable_object_cache) {
		if (!strlen(ocpath))
			/* use object cache internally */
			memcpy(ocpath, dir, strlen(dir));
		ret = object_cache_init(ocpath);
		if (ret)
			exit(1);
	}

	ret = trace_init();
	if (ret)
		exit(1);

	if (http_address && http_init(http_address) != 0)
		exit(1);

	if (pid_file && (create_pidfile(pid_file) != 0)) {
		sd_err("failed to pid file '%s' - %m", pid_file);
		exit(1);
	}

	if (chdir(dir) < 0) {
		sd_err("failed to chdir to %s: %m", dir);
		exit(1);
	}

	free(dir);
	check_host_env();
	sd_info("sheepdog daemon (version %s) started", PACKAGE_VERSION);

	while (sys->nr_outstanding_reqs != 0 ||
	       (sys->cinfo.status != SD_STATUS_KILLED &&
		sys->cinfo.status != SD_STATUS_SHUTDOWN))
		event_loop(-1);

	sd_info("shutdown");

	leave_cluster();

	if (uatomic_is_true(&sys->use_journal)) {
		sd_info("cleaning journal file");
		clean_journal_file(jpath);
	}

	log_close();

	if (pid_file)
		unlink(pid_file);

	return 0;
}
