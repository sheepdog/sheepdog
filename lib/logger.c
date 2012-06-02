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
#include <pthread.h>
#include <libgen.h>

#include "logger.h"
#include "util.h"

#define LOGDBG 0

#if LOGDBG
#define logdbg(file, fmt, args...) fprintf(file, fmt, ##args)
#else
#define logdbg(file, fmt, args...) do {} while (0)
#endif

static int log_enqueue(int prio, const char *func, int line, const char *fmt,
		       va_list ap) __attribute__ ((format (printf, 4, 0)));
static void dolog(int prio, const char *func, int line, const char *fmt,
		  va_list ap) __attribute__ ((format (printf, 4, 0)));

static struct logarea *la;
static char *log_name;
static char *log_nowname;
static int log_level = SDOG_INFO;
static pid_t sheep_pid;
static pid_t logger_pid;
static key_t semkey;

static int64_t max_logsize = 500 * 1024 * 1024;  /*500MB*/

pthread_mutex_t logsize_lock = PTHREAD_MUTEX_INITIALIZER;

static notrace int logarea_init(int size)
{
	int shmid;

	logdbg(stderr, "entering logarea_init\n");

	if ((shmid = shmget(IPC_PRIVATE, sizeof(struct logarea),
			    0644 | IPC_CREAT | IPC_EXCL)) == -1) {
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

	if ((shmid = shmget(IPC_PRIVATE, size,
			    0644 | IPC_CREAT | IPC_EXCL)) == -1) {
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

	la->empty = 1;
	la->end = (char *)la->start + size;
	la->head = la->start;
	la->tail = la->start;

	if ((shmid = shmget(IPC_PRIVATE, MAX_MSG_SIZE + sizeof(struct logmsg),
			    0644 | IPC_CREAT | IPC_EXCL)) == -1) {
		syslog(LOG_ERR, "shmget logmsg failed: %m");
		shmdt(la->start);
		shmdt(la);
		return 1;
	}
	la->buff = shmat(shmid, NULL, 0);
	if (!la->buff) {
		syslog(LOG_ERR, "shmat logmsg failed: %m");
		shmdt(la->start);
		shmdt(la);
		return 1;
	}

	shmctl(shmid, IPC_RMID, NULL);

	if ((la->semid = semget(semkey, 1, 0666 | IPC_CREAT)) < 0) {
		syslog(LOG_ERR, "semget failed: %m");
		shmdt(la->buff);
		shmdt(la->start);
		shmdt(la);
		return 1;
	}

	la->semarg.val=1;
	if (semctl(la->semid, 0, SETVAL, la->semarg) < 0) {
		syslog(LOG_ERR, "semctl failed: %m");
		shmdt(la->buff);
		shmdt(la->start);
		shmdt(la);
		return 1;
	}

	return 0;
}

static void notrace free_logarea(void)
{
	if (la->fd >= 0)
		close(la->fd);
	semctl(la->semid, 0, IPC_RMID, la->semarg);
	shmdt(la->buff);
	shmdt(la->start);
	shmdt(la);
}

#if LOGDBG
static void dump_logarea(void)
{
	struct logmsg * msg;

	logdbg(stderr, "\n==== area: start addr = %p, end addr = %p ====\n",
		la->start, la->end);
	logdbg(stderr, "|addr     |next     |prio|msg\n");

	for (msg = (struct logmsg *)la->head; (void *)msg != la->tail;
	     msg = msg->next)
		logdbg(stderr, "|%p |%p |%i   |%s\n", (void *)msg, msg->next,
				msg->prio, (char *)&msg->str);

	logdbg(stderr, "|%p |%p |%i   |%s\n", (void *)msg, msg->next,
			msg->prio, (char *)&msg->str);

	logdbg(stderr, "\n\n");
}
#endif

static notrace int log_enqueue(int prio, const char *func, int line, const char *fmt,
		       va_list ap)
{
	int len, fwd;
	char *p, buff[MAX_MSG_SIZE];
	struct logmsg *msg;
	struct logmsg *lastmsg;

	lastmsg = (struct logmsg *)la->tail;

	if (!la->empty) {
		fwd = sizeof(struct logmsg) +
		      strlen((char *)&lastmsg->str) * sizeof(char) + 1;
		la->tail = (char *)la->tail + fwd;
	}

	p = buff;

	if (la->fd != -1) {
		time_t t;
		struct tm *tmp;

		t = time(NULL);
		tmp = localtime(&t);

		strftime(p, MAX_MSG_SIZE, "%b %2d %H:%M:%S ", tmp);
		p += strlen(p);
	}

	snprintf(p, MAX_MSG_SIZE, "%s(%d) ", func, line);

	p += strlen(p);

	vsnprintf(p, MAX_MSG_SIZE - strlen(p), fmt, ap);

	len = strlen(buff) * sizeof(char) + 1;

	/* not enough space on tail : rewind */
	if (la->head <= la->tail &&
	    (len + sizeof(struct logmsg)) > ((char *)la->end - (char *)la->tail)) {
		logdbg(stderr, "enqueue: rewind tail to %p\n", la->tail);
			la->tail = la->start;
	}

	/* not enough space on head : drop msg */
	if (la->head > la->tail &&
	    (len + sizeof(struct logmsg)) > ((char *)la->head - (char *)la->tail)) {
		logdbg(stderr, "enqueue: log area overrun, dropping message\n");

		if (!la->empty)
			la->tail = lastmsg;

		return 1;
	}

	/* ok, we can stage the msg in the area */
	la->empty = 0;
	msg = (struct logmsg *)la->tail;
	msg->prio = prio;
	memcpy((void *)&msg->str, buff, len);
	lastmsg->next = la->tail;
	msg->next = la->head;

	logdbg(stderr, "enqueue: %p, %p, %i, %s\n", (void *)msg, msg->next,
		msg->prio, (char *)&msg->str);

#if LOGDBG
	dump_logarea();
#endif
	return 0;
}

static notrace int log_dequeue(void *buff)
{
	struct logmsg * src = (struct logmsg *)la->head;
	struct logmsg * dst = (struct logmsg *)buff;
	struct logmsg * lst = (struct logmsg *)la->tail;
	int len;

	if (la->empty)
		return 1;

	len = strlen((char *)&src->str) * sizeof(char) +
		sizeof(struct logmsg) + 1;

	dst->prio = src->prio;
	memcpy(dst, src,  len);

	if (la->tail == la->head)
		la->empty = 1; /* we purge the last logmsg */
	else {
		la->head = src->next;
		lst->next = la->head;
	}
	logdbg(stderr, "dequeue: %p, %p, %i, %s\n",
		(void *)src, src->next, src->prio, (char *)&src->str);

	memset((void *)src, 0,  len);

	return la->empty;
}

/*
 * this one can block under memory pressure
 */
static notrace void log_syslog(void *buff)
{
	struct logmsg * msg = (struct logmsg *)buff;

	if (la->fd >= 0)
		xwrite(la->fd, (char *)&msg->str, strlen((char *)&msg->str));
	else
		syslog(msg->prio, "%s", (char *)&msg->str);
}

static notrace void dolog(int prio, const char *func, int line,
		const char *fmt, va_list ap)
{
	if (la) {
		struct sembuf ops;

		ops.sem_num = 0;
		ops.sem_flg = SEM_UNDO;
		ops.sem_op = -1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop up failed: %m");
			return;
		}

		log_enqueue(prio, func, line, fmt, ap);

		ops.sem_op = 1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop down failed: %m");
			return;
		}
	} else {
		char p[MAX_MSG_SIZE];

		vsnprintf(p, MAX_MSG_SIZE, fmt, ap);

		if (log_name)
			fprintf(stderr, "%s: %s(%d) %s", log_name, func, line, p);
		else
			fprintf(stderr, "%s(%d) %s", func, line, p);

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
	if (new_fd < 0)
		syslog(LOG_ERR, "fail to create new log file\n");

	dup2(new_fd, la->fd);
	la->fd = new_fd;
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

	while (!la->empty) {
		ops.sem_num = 0;
		ops.sem_flg = SEM_UNDO;
		ops.sem_op = -1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop up failed: %m");
			exit(1);
		}

		log_dequeue(la->buff);

		ops.sem_op = 1;
		if (semop(la->semid, &ops, 1) < 0) {
			syslog(LOG_ERR, "semop down failed: %m");
			exit(1);
		}
		log_syslog(la->buff);
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

notrace int log_init(char *program_name, int size, int to_stdout, int level,
		char *outfile)
{
	off_t offset;
	size_t log_size;
	char log_dir[PATH_MAX];

	log_level = level;

	logdbg(stderr, "entering log_init\n");
	log_name = program_name;
	log_nowname = outfile;
	strcpy(log_dir, outfile);
	strcpy(log_dir, dirname(log_dir));

	semkey = random();

	if (!to_stdout) {
		struct sigaction sa_old;
		struct sigaction sa_new;
		int fd;

		if (outfile) {
			fd = open(outfile, O_CREAT | O_RDWR | O_APPEND, 0644);
			if (fd < 0) {
				syslog(LOG_ERR, "failed to open %s\n", outfile);
				return 1;
			}
		} else {
			fd = -1;
			openlog(log_name, LOG_CONS | LOG_PID, LOG_DAEMON);
			setlogmask (LOG_UPTO (LOG_DEBUG));
		}

		if (logarea_init(size)) {
			syslog(LOG_ERR, "failed to initialize the logger\n");
			return 1;
		}

		la->active = 1;
		la->fd = fd;

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
		} else if (logger_pid) {
			syslog(LOG_WARNING, "logger pid %d starting\n", logger_pid);
			return 0;
		}

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

		while (la->active) {
			log_flush();

			if (max_logsize) {
				pthread_mutex_lock(&logsize_lock);
				offset = lseek(la->fd, 0, SEEK_END);
				if (offset < 0) {
					syslog(LOG_ERR, "sheep log error\n");
				} else {
					log_size = (size_t)offset;
					if (log_size >= max_logsize)
						rotate_log();
				}
				pthread_mutex_unlock(&logsize_lock);
			}

			sleep(1);
		}

		exit(0);
	}

	return 0;
}

notrace void log_close(void)
{
	if (la) {
		la->active = 0;
		waitpid(logger_pid, NULL, 0);

		vprintf(SDOG_WARNING, "logger pid %d stopped\n", logger_pid);
		log_flush();
		closelog();
		free_logarea();
	}
}
