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
 * This code is based on log.h from Linux target framework (tgt).
 *   Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 */
#ifndef LOGGER_H
#define LOGGER_H

#include <sys/sem.h>
#include <sys/syslog.h>

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};

#define LOG_SPACE_SIZE 1048576
#define MAX_MSG_SIZE 256

struct logmsg {
	short int prio;
	void *next;
	char *str;
};

struct logarea {
	int empty;
	int active;
	void *head;
	void *tail;
	void *start;
	void *end;
	char *buff;
	int semid;
	union semun semarg;
	int fd;
};

extern int log_init(char * progname, int size, int daemon, int level, char *outfile);
extern void log_close (void);
extern void dump_logmsg (void *);
extern void log_write(int prio, const char *func, int line, const char *fmt, ...)
	__attribute__ ((format (printf, 4, 5)));

#define	SDOG_EMERG	"<0>"
#define	SDOG_ALERT	"<1>"
#define	SDOG_CRIT	"<2>"
#define	SDOG_ERR	"<3>"
#define	SDOG_WARNING	"<4>"
#define	SDOG_NOTICE	"<5>"
#define	SDOG_INFO	"<6>"
#define	SDOG_DEBUG	"<7>"

#define vprintf(fmt, args...)						\
do {									\
	log_write(LOG_INFO, __func__, __LINE__, fmt, ##args);		\
} while (0)

#define panic(fmt, args...)			\
({						\
	vprintf(SDOG_EMERG fmt, ##args);	\
	abort();				\
})

/* don't use the following obsolete functions. use vprintf instead. */

#define eprintf(fmt, args...)						\
do {									\
	log_write(LOG_ERR, __func__, __LINE__, fmt, ##args);		\
} while (0)

#define dprintf(fmt, args...)						\
do {									\
	log_write(LOG_DEBUG, __func__, __LINE__, fmt, ##args);		\
} while (0)

#endif	/* LOG_H */
