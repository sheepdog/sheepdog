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

#include "logger.h"
#include "util.h"

static int log_vsnprintf(char *buff, size_t size, int prio,
			 const char *func, int line, const char *fmt,
			 va_list ap) __attribute__ ((format (printf, 6, 0)));
static void dolog(int prio, const char *func, int line, const char *fmt,
		  va_list ap) __attribute__ ((format (printf, 4, 0)));

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

struct logmsg {
	time_t t;
	int prio;
	char str[0];
};

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

static notrace int log_vsnprintf(char *buff, size_t size, int prio,
				 const char *func, int line, const char *fmt,
				 va_list ap)
{
	char *p = buff;

	if (worker_name && worker_idx)
		snprintf(p, size, "[%s %d] ", worker_name, worker_idx);
	else if (worker_name)
		snprintf(p, size, "[%s] ", worker_name);
	else
		pstrcpy(p, size, "[main] ");

	p += strlen(p);
	snprintf(p, size - strlen(buff), "%s(%d) ", func, line);

	p += strlen(p);

	vsnprintf(p, size - strlen(buff), fmt, ap);

	p += strlen(p);

	return p - buff;
}

/*
 * this one can block under memory pressure
 */
static notrace void log_syslog(const struct logmsg *msg)
{
	char str[MAX_MSG_SIZE];
	struct tm tm;
	size_t len;

	localtime_r(&msg->t, &tm);
	len = strftime(str, sizeof(str), "%b %2d %H:%M:%S ", &tm);
	pstrcpy(str + len, sizeof(str) - len, msg->str);

	if (log_fd >= 0)
		xwrite(log_fd, str, strlen(str));
	else
		syslog(msg->prio, "%s", str);
}

static notrace void dolog(int prio, const char *func, int line,
		const char *fmt, va_list ap)
{
	char str[MAX_MSG_SIZE];
	int len;

	len = log_vsnprintf(str, sizeof(str), prio, func, line, fmt, ap);

	if (la) {
		struct sembuf ops;
		struct logmsg *msg;
		time_t t = time(NULL);

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
			msg->t = t;
			msg->prio = prio;
			memcpy(msg->str, str, len + 1);
			la->tail += sizeof(struct logmsg) + len + 1;
		}

		ops.sem_op = 1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop down failed: %m");
			return;
		}
	} else {
		xwrite(fileno(stderr), str, len);
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
		sprintf(old_logfile, "%s.%04d-%02d-%02d-%02d-%02d",
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
	if (signo == SIGSEGV) {
		vprintf(SDOG_ERR, "logger pid %d segfaulted.\n",
			getpid());
	} else if (signo == SIGHUP) {
		vprintf(SDOG_ERR, "sheep pid %d exited unexpectedly.\n",
			sheep_pid);
	} else {
		vprintf(SDOG_ERR, "logger pid %d got unexpected signal %d.\n",
			getpid(), signo);
	}

	log_flush();
	closelog();
	free_logarea();
	exit(1);
}

static notrace void logger(char *log_dir, char *outfile)
{
	struct sigaction sa_old;
	struct sigaction sa_new;
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
	sa_new.sa_handler = crash_handler;
	sa_new.sa_flags = 0;
	sigemptyset(&sa_new.sa_mask);

	sigaction(SIGSEGV, &sa_new, &sa_old);
	sigaction(SIGHUP, &sa_new, &sa_old);

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

	free(log_buff);
	exit(0);
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

		vprintf(SDOG_WARNING, "logger pid %d stopped\n", logger_pid);
		log_flush();
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
		sprintf(name, "%s %d", worker_name, worker_idx);
	else if (worker_name)
		sprintf(name, "%s", worker_name);
	else
		sprintf(name, "%s", "main");
}
