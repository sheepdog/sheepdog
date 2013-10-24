/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * This code is based on log.c from Linux target framework (tgt):
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 */
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/time.h>
#include <execinfo.h>
#include <linux/limits.h>

#include "util.h"

static bool colorize;
static const char * const log_color[] = {
	[SDOG_EMERG] = TEXT_BOLD_RED,
	[SDOG_ALERT] = TEXT_BOLD_RED,
	[SDOG_CRIT] = TEXT_BOLD_RED,
	[SDOG_ERR] = TEXT_BOLD_RED,
	[SDOG_WARNING] = TEXT_BOLD_YELLOW,
	[SDOG_NOTICE] = TEXT_BOLD_CYAN,
	[SDOG_INFO] = TEXT_CYAN,
	[SDOG_DEBUG] = TEXT_GREEN,
};

static const char * const log_prio_str[] = {
	[SDOG_EMERG]   = "EMERG",
	[SDOG_ALERT]   = "ALERT",
	[SDOG_CRIT]    = "CRIT",
	[SDOG_ERR]     = "ERROR",
	[SDOG_WARNING] = "WARN",
	[SDOG_NOTICE]  = "NOTICE",
	[SDOG_INFO]    = "INFO",
	[SDOG_DEBUG]   = "DEBUG",
};

static struct logger_user_info *logger_user_info;

static void dolog(int prio, const char *func, int line, const char *fmt,
		  va_list ap) __printf(4, 0);

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};

struct logarea {
	bool active;
	char *tail;
	char *start;
	char *end;
	int semid;
	union semun semarg;
	int fd;
};

#define FUNC_NAME_SIZE 32 /* according to C89, including '\0' */
struct logmsg {
	struct timeval tv;
	int prio;
	char func[FUNC_NAME_SIZE];
	int line;
	char worker_name[MAX_THREAD_NAME_LEN];
	int worker_idx;

	size_t str_len;
	char str[0];
};

struct log_format {
	const char *name;
	int (*formatter)(char *, size_t, const struct logmsg *);
	struct list_head list;
};

#define log_format_register(n, formatter_fn)				\
	static void __attribute__((constructor(101)))			\
	regist_ ## formatter_fn(void) {					\
		static struct log_format f =				\
			{ .name = n, .formatter = formatter_fn };	\
		list_add(&f.list, &log_formats);			\
}

static LIST_HEAD(log_formats);
static struct log_format *format;

static int log_fd = -1;
static __thread const char *worker_name;
static __thread int worker_idx;
static struct logarea *la;
static const char *log_name;
static char *log_nowname;
int sd_log_level = SDOG_INFO;
static pid_t sheep_pid;
pid_t logger_pid = -1;
static key_t semkey;
static char *log_buff;

static int64_t max_logsize = 500 * 1024 * 1024;  /*500MB*/

/*
 * block_sighup()
 *
 * used for protecting log_fd from SIGHUP rotation
 */
static void block_sighup(void)
{
	int ret;
	sigset_t new, old;

	sigemptyset(&new);
	sigemptyset(&old);
	sigaddset(&new, SIGHUP);
	ret = sigprocmask(SIG_BLOCK, &new, &old);
	if (ret < 0)
		syslog(LOG_ERR, "blocking SIGHUP failed\n");
}

static void unblock_sighup(void)
{
	int ret;
	sigset_t new, old;

	sigemptyset(&new);
	sigemptyset(&old);
	sigaddset(&new, SIGHUP);
	ret = sigprocmask(SIG_UNBLOCK, &new, &old);
	if (ret < 0)
		syslog(LOG_ERR, "unblock SIGHUP failed\n");
}

static const char *format_thread_name(char *str, size_t size, const char *name,
				      int idx)
{
	if (name && name[0] && idx)
		snprintf(str, size, "%s %d", name, idx);
	else if (name && name[0])
		snprintf(str, size, "%s", name);
	else
		snprintf(str, size, "main");

	return str;
}

/*
 * We need to set default log formatter because dog doesn't want to call
 * select_log_formatter().
 */
static void __attribute__((constructor(65535)))
init_log_formatter(void)
{
	struct log_format *f;

	list_for_each_entry(f, &log_formats, list) {
		if (!strcmp(f->name, "default")) {
			format = f;
			return;
		}
	}
	syslog(LOG_ERR, "failed to set default formatter\n");
	exit(1);
}

static int logarea_init(int size)
{
	int shmid;

	shmid = shmget(IPC_PRIVATE, sizeof(struct logarea),
		       0644 | IPC_CREAT | IPC_EXCL);
	if (shmid == -1) {
		syslog(LOG_ERR, "shmget logarea failed: %m");
		return 1;
	}

	la = shmat(shmid, NULL, 0);
	if (!la) {
		syslog(LOG_ERR, "shmat logarea failed: %m");
		return 1;
	}

	shmctl(shmid, IPC_RMID, NULL);

	if (size < MAX_MSG_SIZE)
		size = LOG_SPACE_SIZE;

	shmid = shmget(IPC_PRIVATE, size, 0644 | IPC_CREAT | IPC_EXCL);
	if (shmid == -1) {
		syslog(LOG_ERR, "shmget msg failed: %m");
		shmdt(la);
		return 1;
	}

	la->start = shmat(shmid, NULL, 0);
	if (!la->start) {
		syslog(LOG_ERR, "shmat msg failed: %m");
		shmdt(la);
		return 1;
	}
	memset(la->start, 0, size);

	shmctl(shmid, IPC_RMID, NULL);

	la->end = la->start + size;
	la->tail = la->start;

	la->semid = semget(semkey, 1, 0666 | IPC_CREAT);
	if (la->semid < 0) {
		syslog(LOG_ERR, "semget failed: %m");
		shmdt(la->start);
		shmdt(la);
		return 1;
	}

	la->semarg.val = 1;
	if (semctl(la->semid, 0, SETVAL, la->semarg) < 0) {
		syslog(LOG_ERR, "semctl failed: %m");
		shmdt(la->start);
		shmdt(la);
		return 1;
	}

	return 0;
}

static void free_logarea(void)
{
	if (log_fd >= 0)
		close(log_fd);
	semctl(la->semid, 0, IPC_RMID, la->semarg);
	shmdt(la->start);
	shmdt(la);
}

static int server_log_formatter(char *buff, size_t size,
				const struct logmsg *msg)
{
	char *p = buff;
	struct tm tm;
	size_t len;
	char thread_name[MAX_THREAD_NAME_LEN];

	localtime_r(&msg->tv.tv_sec, &tm);
	len = strftime(p, size, "%b %2d %H:%M:%S ", (const struct tm *)&tm);
	p += len;
	size -= len;

	len = snprintf(p, size, "%s%6s %s[%s] %s(%d) %s%s%s",
		       colorize ? log_color[msg->prio] : "",
		       log_prio_str[msg->prio],
		       colorize ? TEXT_YELLOW : "",
		       format_thread_name(thread_name, sizeof(thread_name),
					  msg->worker_name, msg->worker_idx),
		       msg->func, msg->line,
		       colorize ? log_color[msg->prio] : "",
		       msg->str, colorize ? TEXT_NORMAL : "");
	if (len < 0)
		len = 0;
	p += min(len, size - 1);

	return p - buff;
}
log_format_register("server", server_log_formatter);

static int default_log_formatter(char *buff, size_t size,
				 const struct logmsg *msg)
{
	size_t len = min(size, msg->str_len);

	memcpy(buff, msg->str, len);

	return len;
}
log_format_register("default", default_log_formatter);

static int json_log_formatter(char *buff, size_t size,
				const struct logmsg *msg)
{
	char *p = buff;
	size_t len;

	assert(logger_user_info);

	len = snprintf(p, size, "{ \"user_info\": "
		       "{\"program_name\": \"%s\", \"port\": %d},"
		       "\"body\": {"
		       "\"second\": %lu, \"usecond\": %lu, "
		       "\"worker_name\": \"%s\", \"worker_idx\": %d, "
		       "\"func\": \"%s\", \"line\": %d, "
		       "\"msg\": \"",
		       log_name, logger_user_info->port,
		       msg->tv.tv_sec, msg->tv.tv_usec,
		       msg->worker_name[0] ? msg->worker_name : "main",
		       msg->worker_idx, msg->func, msg->line);
	if (len < 0)
		return 0;
	len = min(len, size - 1);
	p += len;
	size -= len;

	for (int i = 0; i < msg->str_len; i++) {
		if (size <= 1)
			break;

		if (msg->str[i] == '"') {
			*p++ = '\\';
			size--;
		}

		if (size <= 1)
			break;
		*p++ = msg->str[i];
		size--;
	}

	pstrcpy(p, size, "\"} }");
	p += strlen(p);

	return p - buff;
}
log_format_register("json", json_log_formatter);

/* this one can block under memory pressure */
static void log_syslog(const struct logmsg *msg)
{
	char str[MAX_MSG_SIZE];
	int len;

	len = format->formatter(str, sizeof(str) - 1, msg);
	str[len++] = '\n';

	block_sighup();

	if (log_fd >= 0)
		xwrite(log_fd, str, len);
	else
		syslog(msg->prio, "%s", str);

	unblock_sighup();
}

static void init_logmsg(struct logmsg *msg, struct timeval *tv,
				int prio, const char *func, int line)
{
	msg->tv = *tv;
	msg->prio = prio;
	pstrcpy(msg->func, FUNC_NAME_SIZE, func);
	msg->line = line;
	if (worker_name)
		pstrcpy(msg->worker_name, MAX_THREAD_NAME_LEN, worker_name);
	else
		msg->worker_name[0] = '\0';
	msg->worker_idx = worker_idx;
}

static void dolog(int prio, const char *func, int line,
		const char *fmt, va_list ap)
{
	char buf[sizeof(struct logmsg) + MAX_MSG_SIZE];
	char *str = buf + sizeof(struct logmsg);
	struct logmsg *msg = (struct logmsg *)buf;
	int len = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	len = vsnprintf(str, MAX_MSG_SIZE, fmt, ap);
	if (len < 0) {
		syslog(LOG_ERR, "vsnprintf failed");
		return;
	}
	msg->str_len = min(len, MAX_MSG_SIZE - 1);

	if (la) {
		struct sembuf ops;

		ops.sem_num = 0;
		ops.sem_flg = SEM_UNDO;
		ops.sem_op = -1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop up failed: %m");
			return;
		}

		/* not enough space: drop msg */
		if (len + sizeof(struct logmsg) + 1 > la->end - la->tail)
			syslog(LOG_ERR, "enqueue: log area overrun, "
			       "dropping message\n");
		else {
			/* ok, we can stage the msg in the area */
			msg = (struct logmsg *)la->tail;
			init_logmsg(msg, &tv, prio, func, line);
			memcpy(msg->str, str, len + 1);
			msg->str_len = len;
			la->tail += sizeof(struct logmsg) + len + 1;
		}

		ops.sem_op = 1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop down failed: %m");
			return;
		}
	} else {
		char str_final[MAX_MSG_SIZE];

		init_logmsg(msg, &tv, prio, func, line);
		len = format->formatter(str_final, sizeof(str_final) - 1, msg);
		str_final[len++] = '\n';
		xwrite(fileno(stderr), str_final, len);
		fflush(stderr);
	}
}

static void rotate_log(void)
{
	int new_fd;

	if (access(log_nowname, R_OK) == 0) {
		char old_logfile[256];
		time_t t;
		struct tm tm;
		time(&t);
		localtime_r((const time_t *)&t, &tm);
		snprintf(old_logfile, sizeof(old_logfile),
			 "%s.%04d-%02d-%02d-%02d-%02d",
			 log_nowname, tm.tm_year + 1900, tm.tm_mon + 1,
			 tm.tm_mday, tm.tm_hour, tm.tm_min);
		rename(log_nowname, old_logfile);
	}
	new_fd = open(log_nowname, O_RDWR | O_CREAT | O_APPEND, 0644);
	if (new_fd < 0) {
		syslog(LOG_ERR, "failed to create new log file\n");
		exit(1);
	}

	if (dup2(new_fd, log_fd) < 0) {
		syslog(LOG_ERR, "failed to dup2 the log fd\n");
		exit(1);
	}
	close(new_fd);
}

void log_write(int prio, const char *func, int line, const char *fmt, ...)
{
	va_list ap;

	if (prio > sd_log_level)
		return;

	va_start(ap, fmt);
	dolog(prio, func, line, fmt, ap);
	va_end(ap);
}

static void log_flush(void)
{
	struct sembuf ops;
	size_t size, done = 0;
	const struct logmsg *msg;

	if (la->tail == la->start)
		return;

	ops.sem_num = 0;
	ops.sem_flg = SEM_UNDO;
	ops.sem_op = -1;
	if (semop(la->semid, &ops, 1) < 0) {
		syslog(LOG_ERR, "semop up failed: %m");
		exit(1);
	}

	size = la->tail - la->start;
	memcpy(log_buff, la->start, size);
	memset(la->start, 0, size);
	la->tail = la->start;

	ops.sem_op = 1;
	if (semop(la->semid, &ops, 1) < 0) {
		syslog(LOG_ERR, "semop down failed: %m");
		exit(1);
	}

	while (done < size) {
		msg = (const struct logmsg *)(log_buff + done);
		log_syslog(msg);
		done += sizeof(*msg) + msg->str_len + 1;
	}
}

static bool is_sheep_dead(int signo)
{
	return signo == SIGHUP;
}

static void crash_handler(int signo)
{
	if (is_sheep_dead(signo))
		sd_err("sheep pid %d exited unexpectedly.", sheep_pid);
	else {
		sd_err("logger pid %d exits unexpectedly (%s).", getpid(),
		       strsignal(signo));
		sd_backtrace();
	}

	log_flush();
	closelog();
	free_logarea();

	/* If the signal isn't caused by the logger crash, we simply exit. */
	if (is_sheep_dead(signo))
		exit(1);

	reraise_crash_signal(signo, 1);
}

static void sighup_handler(int signo)
{
	if (getppid() == 1)
		/*
		 * My parent (sheep process) is dead. This SIGHUP is sent
		 * because of prctl(PR_SET_PDEATHSIG, SIGHUP)
		 */
		return crash_handler(signo);

	/*
	 * My parent sheep process is still alive, this SIGHUP is a request
	 * for log rotation.
	*/
	rotate_log();
}

static void logger(char *log_dir, char *outfile)
{
	int fd;

	log_buff = xzalloc(la->end - la->start);

	log_fd = open(outfile, O_CREAT | O_RDWR | O_APPEND, 0644);
	if (log_fd < 0) {
		syslog(LOG_ERR, "failed to open %s\n", outfile);
		exit(1);
	}
	la->active = true;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		syslog(LOG_ERR, "failed to open /dev/null: %m\n");
		exit(1);
	}

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	setsid();
	if (chdir(log_dir) < 0) {
		syslog(LOG_ERR, "failed to chdir to %s: %m\n", log_dir);
		exit(1);
	}

	/* flush when either the logger or its parent dies */
	install_crash_handler(crash_handler);
	install_sighandler(SIGHUP, sighup_handler, false);

	prctl(PR_SET_PDEATHSIG, SIGHUP);

	/*
	 * we need to check the aliveness of the sheep process since
	 * it could die before the logger call prctl.
	 */
	if (kill(sheep_pid, 0) < 0)
		kill(logger_pid, SIGHUP);

	while (la->active) {
		log_flush();

		block_sighup();

		if (max_logsize) {
			off_t offset;

			offset = lseek(log_fd, 0, SEEK_END);
			if (offset < 0) {
				syslog(LOG_ERR, "sheep log error\n");
			} else {
				size_t log_size = (size_t)offset;
				if (log_size >= max_logsize)
					rotate_log();
			}
		}

		unblock_sighup();

		sleep(1);
	}

	log_flush();
	free(log_buff);
	free_logarea();
	exit(0);
}

void early_log_init(const char *format_name, struct logger_user_info *user_info)
{
	struct log_format *f;

	logger_user_info = user_info;

	list_for_each_entry(f, &log_formats, list) {
		if (!strcmp(f->name, format_name)) {
			format = f;
			return;
		}
	}

	sd_err("invalid log format: %s", format_name);
	sd_err("valid options are:");
	list_for_each_entry(f, &log_formats, list) {
		sd_err("\t%s", f->name);
	}

	exit(1);
}

int log_init(const char *program_name, bool to_stdout, int level,
		     char *outfile)
{
	char log_dir[PATH_MAX], tmp[PATH_MAX];
	int size = level == SDOG_DEBUG ? LOG_SPACE_DEBUG_SIZE : LOG_SPACE_SIZE;

	sd_log_level = level;

	log_name = program_name;
	log_nowname = outfile;
	pstrcpy(tmp, sizeof(tmp), outfile);
	pstrcpy(log_dir, sizeof(log_dir), dirname(tmp));

	semkey = random();

	if (to_stdout) {
		if (is_stdout_console())
			colorize = true;
	} else {
		if (logarea_init(size)) {
			syslog(LOG_ERR, "failed to initialize the logger\n");
			return 1;
		}

		/*
		 * Store the pid of the sheep process for use by the death
		 * signal handler.  By the time the child is notified of
		 * the parents death the parent has been reparanted to init
		 * and getppid() will always return 1.
		 */
		sheep_pid = getpid();
		logger_pid = fork();
		if (logger_pid < 0) {
			syslog(LOG_ERR, "failed to fork the logger process: %m\n");
			return 1;
		}

		if (logger_pid)
			syslog(LOG_WARNING, "logger pid %d starting\n", logger_pid);
		else
			logger(log_dir, outfile);
	}

	return 0;
}

void log_close(void)
{
	if (la) {
		la->active = false;
		waitpid(logger_pid, NULL, 0);

		syslog(LOG_WARNING, "logger pid %d stopped\n", logger_pid);
		closelog();
		free_logarea();
	}
}

void set_thread_name(const char *name, bool show_idx)
{
	worker_name = name;
	if (show_idx)
		worker_idx = gettid();
}

void get_thread_name(char *name)
{
	format_thread_name(name, MAX_THREAD_NAME_LEN, worker_name, worker_idx);
}


#define SD_MAX_STACK_DEPTH 1024

static int get_my_path(char *path, size_t size)
{
	/* readlink doesn't append '\0', so initialize here */
	memset(path, 0, size);

	return readlink("/proc/self/exe", path, size);
}

static bool check_gdb(void)
{
	return system("which gdb > /dev/null") == 0;
}

/*
 * __builtin_frame_address() returns address in frame pointer register if any
 * (e.g, in x86 it returns EBP). If no dedicated register, the frame address is
 * normally the address of the first word pushed on to the stack by the function
 *
 * For a normal subroutine setup, above the value __builtin_frame_address
 * returns, there are two addresses, which stores old EBP and old EIP, being
 * pushed on to the stack. So we have to plus 2 to get the right value for the
 * frame address, which is expected by GDB.
 *
 * This is tested on X86, other architetures aren't tested. But even if this
 * formula is wrong, GDB just doesn't procude anything useful after panic.
 */
#define FRAME_POINTER ((unsigned long *)__builtin_frame_address(0) + 2)

__attribute__ ((__noinline__))
int __sd_dump_variable(const char *var)
{
	char cmd[ARG_MAX], path[PATH_MAX], info[256];
	FILE *f = NULL;
	void *base_sp = FRAME_POINTER;

	if (!check_gdb()) {
		sd_debug("cannot find gdb");
		return -1;
	}

	if (get_my_path(path, sizeof(path)) < 0)
		return -1;

	snprintf(cmd, sizeof(cmd), "gdb -nw %s %d -batch -ex 'set width 80'"
		 " -ex 'select-frame %p' -ex 'up 1' -ex 'p %s' 2> /dev/null",
		 path, gettid(), base_sp, var);
	f = popen(cmd, "r");
	if (f == NULL) {
		sd_err("failed to run gdb");
		return -1;
	}

	/*
	 * The expected outputs of gdb are:
	 *
	 *  [some info we don't need]
	 *  $1 = {
	 *    <variable info>
	 *  }
	 */
	sd_emerg("dump %s", var);
	while (fgets(info, sizeof(info), f) != NULL) {
		if (info[0] == '$') {
			sd_emerg("%s", info);
			break;
		}
	}
	while (fgets(info, sizeof(info), f) != NULL)
		sd_emerg("%s", info);

	pclose(f);
	return 0;
}

__attribute__ ((__noinline__))
static int dump_stack_frames(void)
{
	char path[PATH_MAX];
	int i, stack_no = 0;
	void *base_sp = FRAME_POINTER;

	if (!check_gdb()) {
		sd_debug("cannot find gdb");
		return -1;
	}

	if (get_my_path(path, sizeof(path)) < 0)
		return -1;

	for (i = 1; i < SD_MAX_STACK_DEPTH; i++) {
		char cmd[ARG_MAX], info[256];
		FILE *f = NULL;
		bool found = false;

		snprintf(cmd, sizeof(cmd), "gdb -nw %s %d -batch"
			 " -ex 'set width 80' -ex 'select-frame %p'"
			 " -ex 'up %d' -ex 'info locals' 2> /dev/null",
			 path, gettid(), base_sp, i);
		f = popen(cmd, "r");
		if (f == NULL)
			return -1;
		/*
		 * The expected outputs of gdb are:
		 *
		 *  [some info we don't need]
		 *  #<stack no> <addr> in <func>(<arg>) at <file>:<line>
		 *  <line>   <source>
		 *  <local variables>
		 */
		while (fgets(info, sizeof(info), f) != NULL) {
			int no;
			if (sscanf(info, "#%d ", &no) == 1) {
				if (no <= stack_no) {
					/* reached to the end of the stacks */
					pclose(f);
					return 0;
				}
				stack_no = no;
				found = true;
				sd_emerg("%s", info);
				break;
			}
		}

		if (!found) {
			sd_info("Cannot get info from GDB");
			sd_info("Set /proc/sys/kernel/yama/ptrace_scope to"
				" zero if you are using Ubuntu.");
			pclose(f);
			return -1;
		}

		while (fgets(info, sizeof(info), f) != NULL)
			sd_emerg("%s", info);

		pclose(f);
	}

	return 0;
}

__attribute__ ((__noinline__))
void sd_backtrace(void)
{
	void *addrs[SD_MAX_STACK_DEPTH];
	int i, n = backtrace(addrs, ARRAY_SIZE(addrs));

	for (i = 1; i < n; i++) { /* addrs[0] is here, so skip it */
		void *addr = addrs[i];
		char cmd[ARG_MAX], path[PATH_MAX], info[256], **str;
		FILE *f;

		/*
		 * The called function is at the previous address
		 * because addr contains a return address
		 */
		addr = (void *)((char *)addr - 1);

		/* try to get a line number with addr2line if possible */
		if (get_my_path(path, sizeof(path)) < 0)
			goto fallback;

		snprintf(cmd, sizeof(cmd), "addr2line -s -e %s -f -i %p | "
			"perl -e '@a=<>; chomp @a; print \"$a[1]: $a[0]\"'",
			path, addr);
		f = popen(cmd, "r");
		if (!f)
			goto fallback;
		if (fgets(info, sizeof(info), f) == NULL)
			goto fallback_close;

		if (info[0] != '?' && info[0] != '\0')
			sd_emerg("%s", info);
		else
			goto fallback_close;

		pclose(f);
		continue;
		/*
		 * Failed to get a line number, so simply use
		 * backtrace_symbols instead
		 */
fallback_close:
		pclose(f);
fallback:
		str = backtrace_symbols(&addr, 1);
		sd_emerg("%s", *str);
		free(str);
	}

	/* dump the stack frames if possible*/
	dump_stack_frames();
}

void set_loglevel(int new_loglevel)
{
	assert(SDOG_EMERG <= new_loglevel && new_loglevel <= SDOG_DEBUG);
	sd_log_level = new_loglevel;
}

int get_loglevel(void)
{
	return sd_log_level;
}
