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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "util.h"
#include "work.h"
#include "common.h"

static struct work_queue *util_wqueue;

void register_util_wq(struct work_queue *wq)
{
	util_wqueue = wq;
}

/*
 * If force_create is true, this function create the file even when the
 * temporary file exists.
 */
int atomic_create_and_write(const char *path, const char *buf, size_t len,
			    bool force_create)
{
	int fd, ret;
	char tmp_path[PATH_MAX];

	snprintf(tmp_path, PATH_MAX, "%s.tmp", path);
again:
	fd = open(tmp_path, O_WRONLY | O_CREAT | O_SYNC | O_EXCL, sd_def_fmode);
	if (fd < 0) {
		if (errno == EEXIST) {
			if (force_create) {
				sd_debug("clean up a temporary file %s",
					 tmp_path);
				unlink(tmp_path);
				goto again;
			} else
				sd_debug("someone else is dealing with %s",
					 tmp_path);
		} else
			sd_err("failed to open temporal file %s, %m", tmp_path);
		ret = -1;
		goto end;
	}

	ret = xwrite(fd, buf, len);
	if (unlikely(ret != len)) {
		sd_err("failed to write %s, %m", path);
		ret = -1;
		goto close_fd;
	}

	ret = rename(tmp_path, path);
	if (unlikely(ret < 0)) {
		sd_err("failed to rename %s, %m", path);
		ret = -1;
	}

close_fd:
	close(fd);
end:
	return ret;
}

struct purge_work_unit {
	bool is_dir;
	char path[PATH_MAX];
};

struct purge_work {
	struct work work;

	int nr_units, units_size;
	struct purge_work_unit *units;
};

static void purge_work_fn(struct work *work)
{
	struct purge_work *pw = container_of(work, struct purge_work, work);
	int ret;

	for (int i = 0 ; i < pw->nr_units; i++) {
		struct purge_work_unit *unit;

		unit = &pw->units[i];

		if (unit->is_dir)
			ret = rmdir_r(unit->path);
		else
			ret = unlink(unit->path);

		if (ret)
			sd_err("failed to remove %s %s: %m",
			       unit->is_dir ? "directory" : "file", unit->path);

		/*
		 * We cannot check and do something even above rmdir_r() and
		 * unlink() cause error. Actually, sd_store->cleanup() (typical
		 * user of purge_directory()) call of
		 * cluster_recovery_completion() ignores its error code.
		 */
	}
}

static void purge_work_done(struct work *work)
{
	struct purge_work *pw = container_of(work, struct purge_work, work);

	sd_debug("purging work done, number of units: %d", pw->nr_units);

	free(pw->units);
	free(pw);
}

/* Purge directory recursively */
static int raw_purge_directory(const char *dir_path, bool async)
{
	int ret = 0;
	struct stat s;
	DIR *dir;
	struct dirent *d;
	char path[PATH_MAX];
	struct purge_work *w = NULL;

	dir = opendir(dir_path);
	if (!dir) {
		if (errno != ENOENT)
			sd_err("failed to open %s: %m", dir_path);
		return -errno;
	}

	if (async && util_wqueue) {
		/* we have workqueue for it, don't unlink in this thread */
		w = xzalloc(sizeof(*w));
		w->nr_units = 0;
		w->units_size = 512; /* should this value be configurable? */
		w->units = xcalloc(w->units_size, sizeof(w->units[0]));
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir_path, d->d_name);
		ret = stat(path, &s);
		if (ret) {
			sd_err("failed to stat %s: %m", path);
			goto out;
		}

		if (async && util_wqueue) {
			struct purge_work_unit *unit;

			unit = &w->units[w->nr_units++];

			unit->is_dir = S_ISDIR(s.st_mode);
			pstrcpy(unit->path, PATH_MAX, path);

			if (w->nr_units == w->units_size) {
				w->units_size *= 2;
				w->units = xrealloc(w->units,
					    sizeof(struct purge_work_unit) *
						    w->units_size);
			}
		} else {
			if (S_ISDIR(s.st_mode))
				ret = rmdir_r(path);
			else
				ret = unlink(path);

			if (ret != 0) {
				sd_err("failed to remove %s %s: %m",
				       S_ISDIR(s.st_mode) ?
				       "directory" : "file",
				       path);
				goto out;
			}
		}
	}

	if (async && util_wqueue) {
		w->work.fn = purge_work_fn;
		w->work.done = purge_work_done;
		queue_work(util_wqueue, &w->work);
	}

out:
	closedir(dir);
	return ret;
}

int purge_directory(const char *dir_path)
{
	return raw_purge_directory(dir_path, false);
}

int purge_directory_async(const char *dir_path)
{
	return raw_purge_directory(dir_path, true);
}

/* remove directory recursively */
int rmdir_r(const char *dir_path)
{
	int ret;

	ret = purge_directory(dir_path);
	if (ret == 0)
		ret = rmdir(dir_path);

	return ret;
}

/*
 * If 'once' is true, the signal will be restored to the default state
 * after 'handler' is called.
 */
int install_sighandler(int signum, void (*handler)(int, siginfo_t *, void *),
	bool once)
{
	struct sigaction sa = {};

	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;

	if (once)
		sa.sa_flags = sa.sa_flags | SA_RESETHAND | SA_NODEFER;
	sigemptyset(&sa.sa_mask);

	return sigaction(signum, &sa, NULL);
}

int install_crash_handler(void (*handler)(int, siginfo_t *, void *))
{
	return install_sighandler(SIGSEGV, handler, true) ||
		install_sighandler(SIGABRT, handler, true) ||
		install_sighandler(SIGBUS, handler, true) ||
		install_sighandler(SIGILL, handler, true) ||
		install_sighandler(SIGFPE, handler, true) ||
		install_sighandler(SIGQUIT, handler, true);
}

/*
 * Re-raise the signal 'signo' for the default signal handler to dump
 * a core file, and exit with 'status' if the default handler cannot
 * terminate the process.  This function is expected to be called in
 * the installed signal handlers with install_crash_handler().
 */
void reraise_crash_signal(int signo, int status)
{
	int ret = raise(signo);

	/* We won't get here normally. */
	if (ret != 0)
		sd_emerg("failed to re-raise signal %d (%s).",
			  signo, strsignal(signo));
	else
		sd_emerg("default handler for the re-raised "
			  "signal %d (%s) didn't work as expected", signo,
			  strsignal(signo));

	exit(status);
}

