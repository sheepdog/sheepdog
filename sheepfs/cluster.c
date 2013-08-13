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

#define PATH_CLUSTER		"/cluster"
#define PATH_CLUSTER_INFO	"/cluster/info"

int create_cluster_layout(void)
{
	if (shadow_dir_create(PATH_CLUSTER) < 0)
		return -1;

	if (shadow_file_create(PATH_CLUSTER_INFO) < 0)
		return -1;
	if (sheepfs_set_op(PATH_CLUSTER_INFO, OP_CLUSTER_INFO) < 0)
		return -1;

	return 0;
}

int cluster_info_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

size_t cluster_info_get_size(const char *path)
{
	struct strbuf *buf;
	size_t len;
	char cmd[COMMAND_LEN];

	snprintf(cmd, sizeof(cmd), "dog cluster info -a %s -p %d",
		 sdhost, sdport);
	buf = sheepfs_run_cmd(cmd);
	if (!buf)
		return 0;

	len = shadow_file_write(path, buf->buf, buf->len);
	strbuf_release(buf);
	free(buf);
	return len;
}
