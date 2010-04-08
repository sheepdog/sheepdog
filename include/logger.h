/*
 * iSCSI Safe Logging and Tracing Library
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * circular buffer code based on log.c from dm-multipath project
 *
 * heavily based on code from log.c:
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
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

#define LOG_SPACE_SIZE 16384
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
