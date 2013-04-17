/*
 * Taken and modfied from git by Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <sys/xattr.h>
#include <fcntl.h>

#include "util.h"
#include "logger.h"

mode_t sd_def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
mode_t sd_def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

static void do_nothing(size_t size)
{
}

static void (*try_to_free_routine)(size_t size) = do_nothing;

try_to_free_t set_try_to_free_routine(try_to_free_t routine)
{
	try_to_free_t old = try_to_free_routine;
	if (!routine)
		routine = do_nothing;
	try_to_free_routine = routine;
	return old;
}

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret && !size)
		ret = malloc(1);
	if (!ret) {
		try_to_free_routine(size);
		ret = malloc(size);
		if (!ret && !size)
			ret = malloc(1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

void *xzalloc(size_t size)
{
	return xcalloc(1, size);
}

notrace void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret && !size)
		ret = realloc(ptr, 1);
	if (!ret) {
		try_to_free_routine(size);
		ret = realloc(ptr, size);
		if (!ret && !size)
			ret = realloc(ptr, 1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (!ret && (!nmemb || !size))
		ret = calloc(1, 1);
	if (!ret) {
		try_to_free_routine(nmemb * size);
		ret = calloc(nmemb, size);
		if (!ret && (!nmemb || !size))
			ret = calloc(1, 1);
		if (!ret)
			panic("Out of memory");
	}
	return ret;
}

void *xvalloc(size_t size)
{
	void *ret = valloc(size);
	if (!ret)
		panic("Out of memory");
	return ret;
}

static ssize_t _read(int fd, void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = read(fd, buf, len);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _write(int fd, const void *buf, size_t len)
{
	ssize_t nr;
	while (true) {
		nr = write(fd, buf, len);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xread(int fd, void *buf, size_t count)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _read(fd, p, count);
		if (loaded < 0)
			return -1;
		if (loaded == 0)
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
	}

	return total;
}

ssize_t xwrite(int fd, const void *buf, size_t count)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _write(fd, p, count);
		if (written < 0)
			return -1;
		if (!written) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
	}

	return total;
}

static ssize_t _pread(int fd, void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pread(fd, buf, len, offset);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

static ssize_t _pwrite(int fd, const void *buf, size_t len, off_t offset)
{
	ssize_t nr;
	while (true) {
		nr = pwrite(fd, buf, len, offset);
		if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
			continue;
		return nr;
	}
}

ssize_t xpread(int fd, void *buf, size_t count, off_t offset)
{
	char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t loaded = _pread(fd, p, count, offset);
		if (loaded < 0)
			return -1;
		if (loaded == 0)
			return total;
		count -= loaded;
		p += loaded;
		total += loaded;
		offset += loaded;
	}

	return total;
}

ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset)
{
	const char *p = buf;
	ssize_t total = 0;

	while (count > 0) {
		ssize_t written = _pwrite(fd, p, count, offset);
		if (written < 0)
			return -1;
		if (!written) {
			errno = ENOSPC;
			return -1;
		}
		count -= written;
		p += written;
		total += written;
		offset += written;
	}

	return total;
}

int xmkdir(const char *pathname, mode_t mode)
{
	if (mkdir(pathname, mode) < 0 && errno != EEXIST)
		return -1;
	return 0;
}

/*
 * Copy the string str to buf. If str length is bigger than buf_size -
 * 1 then it is clamped to buf_size - 1.
 * NOTE: this function does what strncpy should have done to be
 * useful. NEVER use strncpy.
 *
 * @param buf destination buffer
 * @param buf_size size of destination buffer
 * @param str source string
 */
void notrace pstrcpy(char *buf, int buf_size, const char *str)
{
	int c;
	char *q = buf;

	if (buf_size <= 0)
		return;

	while (true) {
		c = *str++;
		if (c == 0 || q >= buf + buf_size - 1)
			break;
		*q++ = c;
	}
	*q = '\0';
}

/* Purge directory recursively */
int purge_directory(char *dir_path)
{
	int ret = 0;
	struct stat s;
	DIR *dir;
	struct dirent *d;
	char path[PATH_MAX];

	dir = opendir(dir_path);
	if (!dir) {
		if (errno != ENOENT)
			sd_eprintf("failed to open %s: %m", dir_path);
		return -errno;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir_path, d->d_name);
		ret = stat(path, &s);
		if (ret) {
			sd_eprintf("failed to stat %s: %m", path);
			goto out;
		}
		if (S_ISDIR(s.st_mode))
			ret = rmdir_r(path);
		else
			ret = unlink(path);

		if (ret != 0) {
			sd_eprintf("failed to remove %s %s: %m",
				   S_ISDIR(s.st_mode) ? "directory" : "file",
				   path);
			goto out;
		}
	}
out:
	closedir(dir);
	return ret;
}

/* remove directory recursively */
int rmdir_r(char *dir_path)
{
	int ret;

	ret = purge_directory(dir_path);
	if (ret == 0)
		ret = rmdir(dir_path);

	return ret;
}

/* Trim zero sectors from the beginning and end of buffer */
void trim_zero_sectors(void *buf, uint64_t *offset, uint32_t *len)
{
	const uint8_t zero[SECTOR_SIZE] = {0};
	uint8_t *p = buf;

	assert(*offset == 0);

	/* trim zero sectors from the beginning of buffer */
	while (*len >= SECTOR_SIZE) {
		if (memcmp(p + *offset, zero, SECTOR_SIZE) != 0)
			break;

		*offset += SECTOR_SIZE;
		*len -= SECTOR_SIZE;
	}
	memmove(buf, p + *offset, *len);

	/* trim zero sectors from the end of buffer */
	while (*len >= SECTOR_SIZE) {
		if (memcmp(p + *len - SECTOR_SIZE, zero, SECTOR_SIZE) != 0)
			break;

		*len -= SECTOR_SIZE;
	}
}

/* Untrim zero sectors to the beginning and end of buffer */
void untrim_zero_sectors(void *buf, uint64_t offset, uint32_t len,
			 uint32_t requested_len)
{
	uint8_t *p = buf;

	if (offset > 0) {
		memmove(p + offset, buf, len);
		memset(p, 0, offset);
	}

	if (offset + len < requested_len)
		memset(p + offset + len, 0, requested_len - offset - len);
}

bool is_numeric(const char *s)
{
	const char *p = s;

	if (*p) {
		char c;

		while ((c = *p++))
			if (!isdigit(c))
				return false;
		return true;
	}
	return false;
}

/*
 * If 'once' is true, the signal will be restored to the default state
 * after 'handler' is called.
 */
int install_sighandler(int signum, void (*handler)(int), bool once)
{
	struct sigaction sa = {};

	sa.sa_handler = handler;
	if (once)
		sa.sa_flags = SA_RESETHAND | SA_NODEFER;
	sigemptyset(&sa.sa_mask);

	return sigaction(signum, &sa, NULL);
}

int install_crash_handler(void (*handler)(int))
{
	return install_sighandler(SIGSEGV, handler, true) ||
		install_sighandler(SIGABRT, handler, true) ||
		install_sighandler(SIGBUS, handler, true) ||
		install_sighandler(SIGILL, handler, true) ||
		install_sighandler(SIGFPE, handler, true);
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
		sd_printf(SDOG_EMERG, "failed to re-raise signal %d (%s).",
			  signo, strsignal(signo));
	else
		sd_printf(SDOG_EMERG, "default handler for the re-raised "
			  "signal %d (%s) didn't work expectedly", signo,
			  strsignal(signo));

	exit(status);
}

pid_t gettid(void)
{
	return syscall(SYS_gettid);
}

bool is_xattr_enabled(const char *path)
{
	int ret, dummy;

	ret = getxattr(path, "user.dummy", &dummy, sizeof(dummy));

	return !(ret == -1 && errno == ENOTSUP);
}

int atomic_create_and_write(const char *path, char *buf, size_t len)
{
	int fd, ret;
	char tmp_path[PATH_MAX];

	snprintf(tmp_path, PATH_MAX, "%s.tmp", path);

	fd = open(tmp_path, O_WRONLY | O_CREAT | O_SYNC, sd_def_fmode);
	if (fd < 0) {
		sd_eprintf("failed to open temporal file, %m");
		ret = -1;
		goto end;
	}

	ret = xwrite(fd, buf, len);
	if (ret != len) {
		sd_eprintf("failed to write, %m");
		ret = -1;
		goto close_fd;
	}

	ret = rename(tmp_path, path);
	if (ret < 0) {
		sd_eprintf("failed to rename, %m");
		ret = -1;
	}

close_fd:
	close(fd);
end:
	return ret;
}
