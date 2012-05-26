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

#define PATH_NODE	"/node"
#define PATH_NODE_INFO	"/node/info"
#define PATH_NODE_LIST	"/node/list"


int create_node_layout(void)
{
	if (shadow_dir_create(PATH_NODE) < 0)
		return -1;

	if (shadow_file_create(PATH_NODE_INFO) < 0)
		return -1;
	if (sheepfs_set_op(PATH_NODE_INFO, OP_NODE_INFO) < 0)
		return -1;

	if (shadow_file_create(PATH_NODE_LIST) < 0)
		return -1;
	if (sheepfs_set_op(PATH_NODE_LIST, OP_NODE_LIST) < 0)
		return -1;

	return 0;
}

int node_info_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

size_t node_info_get_size(const char *path)
{
	struct strbuf *buf;
	size_t len;
	char cmd[COMMAND_LEN];

	sprintf(cmd, "collie node info -a %s -p %d", sdhost, sdport);
	buf = sheepfs_run_cmd(cmd);
	if (!buf)
		return 0;

	len = shadow_file_write(path, buf->buf, buf->len);
	strbuf_release(buf);
	free(buf);
	return len;
}

int node_list_read(const char *path, char *buf, size_t size, off_t ignore)
{
	return shadow_file_read(path, buf, size, 0);
}

size_t node_list_get_size(const char *path)
{
	struct strbuf *buf;
	size_t len;
	char cmd[COMMAND_LEN];

	sprintf(cmd, "collie node list -a %s -p %d", sdhost, sdport);
	buf = sheepfs_run_cmd(cmd);
	if (!buf)
		return 0;

	len = shadow_file_write(path, buf->buf, buf->len);
	strbuf_release(buf);
	return len;
}
