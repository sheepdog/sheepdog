/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/* This file contains shared functionalities for libsd.a */

#ifndef __COMMON_H__
#define __COMMON_H__

struct work_queue;
void register_util_wq(struct work_queue *wq);

int rmdir_r(const char *dir_path);
int purge_directory(const char *dir_path);
int purge_directory_async(const char *dir_path);
int atomic_create_and_write(const char *path, const char *buf, size_t len,
                            bool force_create);
int install_sighandler(int signum, void (*handler)(int, siginfo_t *, void *),
                       bool once);
int install_crash_handler(void (*handler)(int, siginfo_t *, void *));
void reraise_crash_signal(int signo, int status);

#endif

