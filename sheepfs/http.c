/*
 * Copyright (C) 2014 Taobao Inc.
 *
 * Robin Dong <sanbai@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "strbuf.h"
#include "sheepfs.h"
#include "net.h"

#define PATH_HTTP		"/http"
#define PATH_HTTP_ADDRESS	"/http/address"
#define PATH_HTTP_OBJECT	"/http/object"

int create_http_layout(void)
{
	if (shadow_dir_create(PATH_HTTP) < 0)
		return -1;

	if (shadow_file_create(PATH_HTTP_ADDRESS) < 0)
		return -1;
	if (sheepfs_set_op(PATH_HTTP_ADDRESS, OP_HTTP_ADDRESS) < 0)
		return -1;

	if (shadow_file_create(PATH_HTTP_OBJECT) < 0)
		return -1;
	if (sheepfs_set_op(PATH_HTTP_OBJECT, OP_HTTP_OBJECT) < 0)
		return -1;

	return 0;
}

int http_address_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

int http_address_write(const char *path, const char *buf, size_t size,
		       off_t ignore)
{
	return shadow_file_write(path, buf, size);
}

size_t http_address_get_size(const char *path)
{
	struct stat st;
	if (shadow_file_stat(path, &st))
		return st.st_size;
	return 0;
}

int http_object_write(const char *path, const char *buf, size_t size,
		      off_t ignore)
{
	return size;
}
