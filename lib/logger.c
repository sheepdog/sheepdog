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

#include "logger.h"
#include "util.h"

struct logger_user_info *logger_user_info;

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
static int log_level = SDOG_INFO;
static pid_t sheep_pid;
static pid_t logger_pid;
static key_t semkey;
static char *log_buff;

static int64_t max_logsize = 500 * 1024 * 1024;  /*500MB*/

static pthread_mutex_t logsize_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * We need to set default log formatter because collie doesn't want to call
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

static notrace int logarea_init(int size)
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

static void notrace free_logarea(void)
{
	if (log_fd >= 0)
		close(log_fd);
	semctl(la->semid, 0, IPC_RMID, la->semarg);
	shmdt(la->start);
	shmdt(la);
}

static notrace int default_log_formatter(char *buff, size_t size,
				const struct logmsg *msg)
{
	char *p = buff;
	struct tm tm;
	int worker_name_len = strlen(msg->worker_name);

	localtime_r(&msg->tv.tv_sec, &tm);
	strftime(p, size, "%b %2d %H:%M:%S ", (const struct tm *)&tm);
	p += strlen(p);

	if (worker_name_len && msg->worker_idx)
		snprintf(p, size, "[%s %d] ", msg->worker_name,
			msg->worker_idx);
	else if (worker_name_len)
		snprintf(p, size, "[%s] ", msg->worker_name);
	else
		pstrcpy(p, size, "[main] ");

	p += strlen(p);

	snprintf(p, size - strlen(buff), "%s(%d) ", msg->func, msg->line);
	p += strlen(p);

	snprintf(p, size - strlen(buff), "%s", (char *)msg->str);
	p += strlen(p);

	return p - buff;
}
log_format_register("default", default_log_formatter);

static notrace int json_log_formatter(char *buff, size_t size,
				const struct logmsg *msg)
{
	int i, body_len;
	char *p = buff;

	snprintf(p, size, "{ \"user_info\": {");
	p += strlen(p);

	snprintf(p, size - strlen(buff), "\"program_name\": \"%s\", ",
		log_name);
	p += strlen(p);

	assert(logger_user_info);
	snprintf(p, size - strlen(buff), "\"port\": %d",
		logger_user_info->port);
	p += strlen(p);

	snprintf(p, size - strlen(buff), "},");
	p += strlen(p);

	snprintf(p, size - strlen(buff), "\"body\": {");
	p += strlen(p);

	snprintf(p, size - strlen(buff), "\"second\": %lu", msg->tv.tv_sec);
	p += strlen(p);

	snprintf(p, size - strlen(buff), ", \"usecond\": %lu", msg->tv.tv_usec);
	p += strlen(p);

	if (strlen(msg->worker_name))
		snprintf(p, size - strlen(buff), ", \"worker_name\": \"%s\"",
			msg->worker_name);
	else
		snprintf(p, size - strlen(buff), ", \"worker_name\": \"main\"");

	p += strlen(p);

	snprintf(p, size - strlen(buff), ", \"worker_idx\": %d",
		msg->worker_idx);
	p += strlen(p);

	snprintf(p, size - strlen(buff), ", \"func\": \"%s\"", msg->func);
	p += strlen(p);

	snprintf(p, size - strlen(buff), ", \"line\": %d", msg->line);
	p += strlen(p);

	snprintf(p, size - strlen(buff), ", \"msg\": \"");
	p += strlen(p);

	body_len = strlen(msg->str) - 1;
	/* this - 1 eliminates '\n', dirty... */
	for (i = 0; i < body_len; i++) {
		if (msg->str[i] == '"')
			*p++ = '\\';
		*p++ = msg->str[i];
	}

	snprintf(p, size - strlen(buff), "\"} }\n");
	p += strlen(p);

	return p - buff;
}
log_format_register("json", json_log_formatter);

/*
 * this one can block under memory pressure
 */
static notrace void log_syslog(const struct logmsg *msg)
{
	char str[MAX_MSG_SIZE];

	memset(str, 0, MAX_MSG_SIZE);
	format->formatter(str, MAX_MSG_SIZE, msg);
	if (log_fd >= 0)
		xwrite(log_fd, str, strlen(str));
	else
		syslog(msg->prio, "%s", str);
}

static notrace void init_logmsg(struct logmsg *msg, struct timeval *tv,
				int prio, const char *func, int line)
{
	msg->tv = *tv;
	msg->prio = prio;
	pstrcpy(msg->func, FUNC_NAME_SIZE, func);
	msg->line = line;
	if (worker_name)
		pstrcpy(msg->worker_name, MAX_THREAD_NAME_LEN, worker_name);
	msg->worker_idx = worker_idx;
}

static notrace void dolog(int prio, const char *func, int line,
		const char *fmt, va_list ap)
{
	char buf[sizeof(struct logmsg) + MAX_MSG_SIZE];
	char *str = buf + sizeof(struct logmsg);
	struct logmsg *msg = (struct logmsg *)buf;
	int len = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	len = vsnprintf(str, MAX_MSG_SIZE, fmt, ap);
	if (len + 1 < MAX_MSG_SIZE && str[len - 1] != '\n') {
		str[len++] = '\n';
		str[len] = '\0';
	}

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
			la->tail += sizeof(struct logmsg) + len + 1;
		}

		ops.sem_op = 1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop down failed: %m");
			return;
		}
	} else {
		char str_final[MAX_MSG_SIZE];

		memset(str_final, 0, MAX_MSG_SIZE);
		memset(msg, 0, sizeof(struct logmsg));
		init_logmsg(msg, &tv, prio, func, line);
		len = format->formatter(str_final, MAX_MSG_SIZE, msg);
		xwrite(fileno(stderr), str_final, len);
		fflush(stderr);
	}
}

static notrace void rotate_log(void)
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

notrace void log_write(int prio, const char *func, int line, const char *fmt, ...)
{
	va_list ap;

	if (prio > log_level)
		return;

	va_start(ap, fmt);
	dolog(prio, func, line, fmt, ap);
	va_end(ap);
}

static notrace void log_flush(void)
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
		done += sizeof(*msg) + strlen(msg->str) + 1;
	}
}

static notrace void crash_handler(int signo)
{
	if (signo == SIGHUP)
		sd_printf(SDOG_ERR, "sheep pid %d exited unexpectedly.",
			  sheep_pid);
	else {
		sd_printf(SDOG_ERR, "logger pid %d exits unexpectedly (%s).",
			  getpid(), strsignal(signo));
		sd_backtrace();
	}

	log_flush();
	closelog();
	free_logarea();
	exit(1);
}

static notrace void logger(char *log_dir, char *outfile)
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
	install_sighandler(SIGHUP, crash_handler, false);

	prctl(PR_SET_PDEATHSIG, SIGHUP);

	/* we need to check the aliveness of the sheep process since
	 * it could die before the logger call prctl. */
	if (kill(sheep_pid, 0) < 0)
		kill(logger_pid, SIGHUP);

	while (la->active) {
		log_flush();

		if (max_logsize) {
			off_t offset;

			pthread_mutex_lock(&logsize_lock);
			offset = lseek(log_fd, 0, SEEK_END);
			if (offset < 0) {
				syslog(LOG_ERR, "sheep log error\n");
			} else {
				size_t log_size = (size_t)offset;
				if (log_size >= max_logsize)
					rotate_log();
			}
			pthread_mutex_unlock(&logsize_lock);
		}

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

	fprintf(stderr, "invalid log format: %s\n", format_name);
	fprintf(stderr, "valid options are:\n");
	list_for_each_entry(f, &log_formats, list) {
		fprintf(stderr, "\t%s\n", f->name);
	}

	exit(1);
}

notrace int log_init(const char *program_name, int size, bool to_stdout,
		int level, char *outfile)
{
	char log_dir[PATH_MAX], tmp[PATH_MAX];

	log_level = level;

	log_name = program_name;
	log_nowname = outfile;
	pstrcpy(tmp, sizeof(tmp), outfile);
	pstrcpy(log_dir, sizeof(log_dir), dirname(tmp));

	semkey = random();

	if (!to_stdout) {
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

notrace void log_close(void)
{
	if (la) {
		la->active = false;
		waitpid(logger_pid, NULL, 0);

		syslog(LOG_WARNING, "logger pid %d stopped\n", logger_pid);
		closelog();
		free_logarea();
	}
}

notrace void set_thread_name(const char *name, int idx)
{
	worker_name = name;
	worker_idx = idx;
}

notrace void get_thread_name(char *name)
{
	if (worker_name && worker_idx)
		snprintf(name, MAX_THREAD_NAME_LEN, "%s %d",
			 worker_name, worker_idx);
	else if (worker_name)
		snprintf(name, MAX_THREAD_NAME_LEN, "%s", worker_name);
	else
		snprintf(name, MAX_THREAD_NAME_LEN, "%s", "main");
}


#define SD_MAX_STACK_DEPTH 1024

notrace void sd_backtrace(void)
{
	void *addrs[SD_MAX_STACK_DEPTH];
	int i, n = backtrace(addrs, ARRAY_SIZE(addrs));

	for (i = 1; i < n; i++) { /* addrs[0] is here, so skip it */
		void *addr = addrs[i];
		char cmd[ARG_MAX], path[PATH_MAX] = {0}, info[256], **str;
		FILE *f;

		/* the called function is at the previous address
		 * because addr contains a return address */
		addr = (void *)((char *)addr - 1);

		/* try to get a line number with addr2line if possible */
		if (readlink("/proc/self/exe", path, sizeof(path)) < 0)
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
			sd_printf(SDOG_EMERG, "%s", info);
		else
			goto fallback_close;

		pclose(f);
		continue;
		/* failed to get a line number, so simply use
		 * backtrace_symbols instead */
fallback_close:
		pclose(f);
fallback:
		str = backtrace_symbols(&addr, 1);
		sd_printf(SDOG_EMERG, "%s", *str);
		free(str);
	}
}
