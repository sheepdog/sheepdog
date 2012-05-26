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

#define PATH_CONFIG        "/config"
#define PATH_CONFIG_PCACHE "/config/page_cache"
#define PATH_CONFIG_OCACHE "/config/object_cache"
#define PATH_CONFIG_SHEEP  "/config/sheep_info"

int create_config_layout(void)
{
	if (shadow_dir_create(PATH_CONFIG) < 0)
		return -1;

	if (shadow_file_create(PATH_CONFIG_PCACHE) < 0)
		return -1;
	if (sheepfs_set_op(PATH_CONFIG_PCACHE, OP_CONFIG_PCACHE) < 0)
		return -1;

	if (shadow_file_create(PATH_CONFIG_OCACHE) < 0)
		return -1;
	if (sheepfs_set_op(PATH_CONFIG_OCACHE, OP_CONFIG_OCACHE) < 0)
		return -1;

	if (shadow_file_create(PATH_CONFIG_SHEEP) < 0)
		return -1;
	if (sheepfs_set_op(PATH_CONFIG_SHEEP, OP_CONFIG_SHEEP) < 0)
		return -1;

	return 0;
}

int config_pcache_read(const char *path, char *buf, size_t size, off_t ignore)
{
	sprintf(buf, "%d\n", sheepfs_page_cache);
	return strlen(buf);
}

int config_pcache_write(const char *path, const char *buf, size_t size,
			off_t ignore)
{
	int value;

	if (sscanf(buf, "%d", &value) != 1)
		return -EINVAL;

	sheepfs_page_cache = !!value;
	return size;
}

size_t config_pcache_get_size(const char *path)
{
	return sizeof(int) + 1/* \n */;
}

int config_ocache_read(const char *path, char *buf, size_t size, off_t ignore)
{
	sprintf(buf, "%d\n", sheepfs_object_cache);
	return strlen(buf);
}

int config_ocache_write(const char *path, const char *buf, size_t size,
			off_t ignore)
{
	int value;

	if (sscanf(buf, "%d\n", &value) != 1)
		return -EINVAL;

	sheepfs_object_cache = !!value;
	return size;
}

size_t config_ocache_get_size(const char *path)
{
	return sizeof(int) + 1;
}

int config_sheep_info_read(const char *path, char *buf, size_t size,
			   off_t ignore)
{
	sprintf(buf, "%s:%d\n", sdhost, sdport);
	return strlen(buf);
}

int config_sheep_info_write(const char *path, const char *buf, size_t size,
			    off_t ignore)
{
	char *ip, *pt;
	unsigned port;

	ip = strtok((char *)buf, ":");
	if (!ip)
		return -EINVAL;

	pt = strtok(NULL, ":");
	if (!pt)
		return -EINVAL;

	if (sscanf(pt, "%u", &port) != 1)
		return -EINVAL;

	memcpy(sdhost, ip, strlen(ip));
	sdhost[strlen(ip)] = '\0';
	sdport = port;
	if (reset_socket_pool() < 0)
		return -EINVAL;

	return size;
}

size_t config_sheep_info_get_size(const char *path)
{
	return strlen(sdhost) + 1/* : */ + sizeof(sdport) + 1/* \n */;
}
