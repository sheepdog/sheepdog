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

#include <stdbool.h>
#include <sys/syslog.h>

#define LOG_SPACE_SIZE (32 * 1024 * 1024)
#define MAX_MSG_SIZE 256
#define MAX_THREAD_NAME_LEN	20

void select_log_formatter(const char *format_name);
int log_init(const char *progname, int size, bool to_stdout, int level,
	char *outfile);
void log_close(void);
void dump_logmsg(void *);
void log_write(int prio, const char *func, int line, const char *fmt, ...)
	__attribute__ ((format (printf, 4, 5)));
void set_thread_name(const char *name, int idx);
void get_thread_name(char *name);

/*
+ * sheep log priorities, comliant with syslog spec
+ */
#define	SDOG_EMERG		LOG_EMERG
#define	SDOG_ALERT		LOG_ALERT
#define	SDOG_CRIT		LOG_CRIT
#define	SDOG_ERR		LOG_ERR
#define	SDOG_WARNING	LOG_WARNING
#define	SDOG_NOTICE		LOG_NOTICE
#define	SDOG_INFO		LOG_INFO
#define	SDOG_DEBUG		LOG_DEBUG

#define sd_printf(level, fmt, args...)					\
	do {								\
		log_write(level, __func__, __LINE__, fmt, ##args);	\
	} while (0)

#define panic(fmt, args...)					\
	({							\
		sd_printf(SDOG_EMERG, "PANIC: " fmt, ##args);	\
		abort();					\
	})

#define sd_iprintf(fmt, args...)					\
	do {								\
		log_write(SDOG_INFO, __func__, __LINE__, fmt, ##args);	\
	} while (0)

#define sd_eprintf(fmt, args...)					\
	do {								\
		log_write(SDOG_ERR, __func__, __LINE__, fmt, ##args);	\
	} while (0)

#define sd_dprintf(fmt, args...)					\
	do {								\
		log_write(SDOG_DEBUG, __func__, __LINE__, fmt, ##args);	\
	} while (0)

#endif	/* LOG_H */
