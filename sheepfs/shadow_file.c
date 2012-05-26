/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Liu Yuan <namei.unix@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 *  Sheepfs use this shadow file mechanism to mostly manage dentries. We
 *  might also make use of those shadow file to cache non-volatile states.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sys/xattr.h>
#include <stdlib.h>

#include "util.h"
#include "sheepfs.h"

int shadow_file_read(const char *path, char *buf, size_t size, off_t offset)
{
	char p[PATH_MAX];
	int fd, len;

	sprintf(p, "%s%s", sheepfs_shadow, path);
	fd = open(p, O_RDONLY);
	if (fd < 0) {
		sheepfs_pr("%m\n");
		return -errno;
	}
	len = xpread(fd, buf, size, offset);
	close(fd);
	return len;
}

size_t shadow_file_write(const char *path, char *buf, size_t size)
{
	char p[PATH_MAX];
	int fd;
	size_t len = 0;

	sprintf(p, "%s%s", sheepfs_shadow, path);
	fd = open(p, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		sheepfs_pr("%m\n");
		return 0;
	}
	len = xwrite(fd, buf, size);
	if (len != size) {
		sheepfs_pr("failed to write\n");
		len = 0;
	}
	close(fd);
	return len;
}

int shadow_file_create(const char *path)
{
	char p[PATH_MAX];
	int fd;
	sprintf(p, "%s%s", sheepfs_shadow, path);
	fd = creat(p, 0644);
	if (fd < 0) {
		if (errno != EEXIST) {
			sheepfs_pr("%m\n");
			return -1;
		}
	}
	close(fd);
	return 0;
}

int shadow_dir_create(const char *path)
{
	char p[PATH_MAX];

	sprintf(p, "%s%s", sheepfs_shadow, path);
	if (mkdir(p, 0755) < 0) {
		if (errno != EEXIST) {
			sheepfs_pr("%m\n");
			return -1;
		}
	}
	return 0;
}

int shadow_file_setxattr(const char *path, const char *name,
		const void *value, size_t size)
{
	char p[PATH_MAX];

	sprintf(p, "%s%s", sheepfs_shadow, path);
	if (setxattr(p, name, value, size, 0) < 0) {
		sheepfs_pr("%m\n");
		return -1;
	}
	return 0;
}

int shadow_file_getxattr(const char *path, const char *name,
		void *value, size_t size)
{
	char p[PATH_MAX];

	sprintf(p, "%s%s", sheepfs_shadow, path);
	if (getxattr(p, name, value, size) < 0) {
		sheepfs_pr("%m\n");
		return -1;
	}
	return 0;
}

int shadow_file_delete(const char *path)
{
	char p[PATH_MAX];

	sprintf(p, "%s%s", sheepfs_shadow, path);
	if (unlink(p) < 0) {
		if (errno != ENOENT) {
			sheepfs_pr("%m\n");
			return -1;
		}
	}
	return 0;
}

int shadow_file_exsit(const char *path)
{
	char p[PATH_MAX];

	sprintf(p, "%s%s", sheepfs_shadow, path);
	if (access(p, R_OK | W_OK) < 0) {
		if (errno != ENOENT)
			sheepfs_pr("%m\n");
		return 0;
	}

	return 1;
}
