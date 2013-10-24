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

#include "compiler.h"

#define LOG_SPACE_SIZE (1 * 1024 * 1024)
#define LOG_SPACE_DEBUG_SIZE (32 * 1024 * 1024)
#define MAX_MSG_SIZE 1024
#define MAX_THREAD_NAME_LEN	20

struct logger_user_info {
	int port;
};

extern int sd_log_level;

void early_log_init(const char *format_name,
		struct logger_user_info *user_info);
int log_init(const char *progname, bool to_stdout, int level, char *outfile);
void log_close(void);
void dump_logmsg(void *);
void log_write(int prio, const char *func, int line, const char *fmt, ...)
	__printf(4, 5);
void set_thread_name(const char *name, bool show_idx);
void get_thread_name(char *name);

#define sd_dump_variable(var) ({		\
	__sd_dump_variable(#var);		\
})
int __sd_dump_variable(const char *var);
void sd_backtrace(void);

/* sheep log priorities, comliant with syslog spec */
#define	SDOG_EMERG	LOG_EMERG
#define	SDOG_ALERT	LOG_ALERT
#define	SDOG_CRIT	LOG_CRIT
#define	SDOG_ERR	LOG_ERR
#define	SDOG_WARNING	LOG_WARNING
#define	SDOG_NOTICE	LOG_NOTICE
#define	SDOG_INFO	LOG_INFO
#define	SDOG_DEBUG	LOG_DEBUG

#define sd_emerg(fmt, args...) \
	log_write(SDOG_EMERG, __func__, __LINE__, fmt, ##args)
#define sd_alert(fmt, args...) \
	log_write(SDOG_ALERT, __func__, __LINE__, fmt, ##args)
#define sd_crit(fmt, args...) \
	log_write(SDOG_CRIT, __func__, __LINE__, fmt, ##args)
#define sd_err(fmt, args...) \
	log_write(SDOG_ERR, __func__, __LINE__, fmt, ##args)
#define sd_warn(fmt, args...) \
	log_write(SDOG_WARNING, __func__, __LINE__, fmt, ##args)
#define sd_notice(fmt, args...) \
	log_write(SDOG_NOTICE, __func__, __LINE__, fmt, ##args)
#define sd_info(fmt, args...) \
	log_write(SDOG_INFO, __func__, __LINE__, fmt, ##args)

/*
 * 'args' must not contain an operation/function with a side-effect.  It won't
 * be evaluated when the log level is not SDOG_DEBUG.
 */
#define sd_debug(fmt, args...)						\
({									\
	if (unlikely(sd_log_level == SDOG_DEBUG))			\
		log_write(SDOG_DEBUG, __func__, __LINE__, fmt, ##args);	\
})

#define panic(fmt, args...)			\
({						\
	sd_emerg("PANIC: " fmt, ##args);	\
	abort();				\
})

void set_loglevel(int new_loglevel);
int get_loglevel(void);

extern pid_t logger_pid;

#endif	/* LOG_H */
