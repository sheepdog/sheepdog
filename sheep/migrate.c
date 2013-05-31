/*
 * Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>

#include "sheep_priv.h"

/* sheepdog 0.4.0 */
struct node_id_v0 {
	uint8_t addr[16];
	uint16_t port;
};

struct sd_node_v0 {
	struct node_id_v0  nid;
	uint16_t	nr_vnodes;
	uint32_t	zone;
};

struct sheepdog_config_v0 {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t store[STORE_LEN];
};

/* sheepdog 0.5.1 */
struct node_id_v1 {
	uint8_t addr[16];
	uint16_t port;
};

struct sd_node_v1 {
	struct node_id_v1  nid;
	uint16_t	nr_vnodes;
	uint32_t	zone;
	uint64_t        space;
};

struct sheepdog_config_v1 {
	uint64_t ctime;
	uint16_t flags;
	uint8_t copies;
	uint8_t store[STORE_LEN];
	uint8_t __pad[3];
	uint16_t version;
	uint64_t space;
};

static size_t get_file_size(const char *path)
{
	struct stat stbuf;
	int ret;

	ret = stat(path, &stbuf);
	if (ret < 0) {
		sd_eprintf("failed to stat %s, %m", path);
		return -1;
	}
	return stbuf.st_size;
}

static void for_each_epoch(int (*func)(uint32_t epoch))
{
	DIR *dir;
	struct dirent *d;

	dir = opendir(epoch_path);
	if (!dir)
		panic("failed to open %s: %m", epoch_path);

	while ((d = readdir(dir))) {
		uint32_t e;
		char *p;
		e = strtol(d->d_name, &p, 10);
		if (d->d_name == p)
			continue;

		if (strlen(d->d_name) != 8)
			continue;

		if (func(e) != 0)
			return;
	}
	closedir(dir);
}

/* copy file from 'fname' to 'fname.suffix' */
static int backup_file(char *fname, char *suffix)
{
	char dst_file[PATH_MAX];
	int fd = -1, ret, len;
	void *buf = NULL;

	snprintf(dst_file, sizeof(dst_file), "%s.%s", fname, suffix);

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT) {
			sd_eprintf("failed to open %s, %m", fname);
			ret = -1;
		} else
			ret = 0;
		goto out;
	}

	len = get_file_size(fname);
	if (len < 0)
		goto out;

	buf = xmalloc(len);
	ret = xread(fd, buf, len);
	if (ret != len) {
		sd_eprintf("failed to read %s, %d %m", fname, ret);
		ret = -1;
		goto out;
	}

	close(fd);

	fd = open(dst_file, O_CREAT | O_WRONLY | O_DSYNC, 0644);
	if (fd < 0) {
		sd_eprintf("failed to create %s, %m", dst_file);
		ret = -1;
		goto out;
	}

	ret = xwrite(fd, buf, len);
	if (ret != len) {
		sd_eprintf("failed to write to %s, %d %m", dst_file, ret);
		ret = -1;
	}
out:
	if (fd >= 0)
		close(fd);
	free(buf);

	return ret;
}

static int backup_epoch(uint32_t epoch)
{
	char path[PATH_MAX];
	char suffix[256];
	struct timeval tv;
	struct tm tm;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(suffix, sizeof(suffix), "%Y-%m-%d_%H%M%S", &tm);

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);

	return backup_file(path, suffix);
}

/* backup config and epoch info */
static int backup_store(void)
{
	char suffix[256];
	struct timeval tv;
	struct tm tm;
	int ret;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(suffix, sizeof(suffix), "%Y-%m-%d_%H%M%S", &tm);

	ret = backup_file(config_path, suffix);
	if (ret < 0)
		return ret;

	for_each_epoch(backup_epoch);

	return 0;
}

static int update_epoch_from_v0_to_v1(uint32_t epoch)
{
	char path[PATH_MAX];
	struct sd_node_v0 nodes_v0[SD_MAX_NODES];
	struct sd_node_v1 nodes_v1[SD_MAX_NODES];
	size_t nr_nodes;
	time_t *t;
	int len, fd, ret;

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDWR | O_DSYNC);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;

		sd_eprintf("failed to open epoch %"PRIu32" log", epoch);
		return -1;
	}

	ret = xread(fd, nodes_v0, sizeof(nodes_v0));
	if (ret < 0) {
		sd_eprintf("failed to read epoch %"PRIu32" log", epoch);
		close(fd);
		return ret;
	}

	nr_nodes = ret / sizeof(nodes_v0[0]);
	for (int i = 0; i < nr_nodes; i++) {
		memcpy(&nodes_v1[i].nid, &nodes_v0[i].nid,
		       sizeof(struct node_id_v1));
		nodes_v1[i].nr_vnodes = nodes_v0[i].nr_vnodes;
		nodes_v1[i].zone = nodes_v0[i].zone;
		nodes_v1[i].space = 0;
	}

	len = sizeof(nodes_v1[0]) * nr_nodes;
	ret = xpwrite(fd, nodes_v1, len, 0);
	if (ret != len) {
		sd_eprintf("failed to write epoch %"PRIu32" log",
			   epoch);
		close(fd);
		return -1;
	}

	t = (time_t *)&nodes_v0[nr_nodes];

	ret = xpwrite(fd, t, sizeof(*t), len);
	if (ret != sizeof(*t)) {
		sd_eprintf("failed to write time to epoch %"
			   PRIu32" log", epoch);
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}

static int migrate_from_v0_to_v1(void)
{
	int ret, fd;
	struct sheepdog_config_v1 config;

	fd = open(config_path, O_RDWR);
	if (fd < 0) {
		sd_eprintf("failed to open config file, %m");
		return -1;
	}

	memset(&config, 0, sizeof(config));
	ret = xread(fd, &config, sizeof(config));
	if (ret < 0) {
		sd_eprintf("failed to read config file, %m");
		close(fd);
		return ret;
	}

	config.version = 1;
	ret = xpwrite(fd, &config, sizeof(config), 0);
	if (ret != sizeof(config)) {
		sd_eprintf("failed to write config data, %m");
		close(fd);
		return -1;
	}

	/* 0.5.1 could wrongly extend the config file, so truncate it here */
	ret = ftruncate(fd, sizeof(config));
	if (ret != 0) {
		sd_eprintf("failed to truncate config data, %m");
		close(fd);
		return -1;
	}

	close(fd);

	/*
	 * If the config file contains a space field, the store layout
	 * is compatible with v1.  In this case, what we need to do is
	 * only adding version number to the config file.
	 */
	if (config.space > 0)
		return 0;

	/* upgrade epoch log */
	for_each_epoch(update_epoch_from_v0_to_v1);

	return ret;
}

static int (*migrate[])(void) = {
	migrate_from_v0_to_v1, /* from 0.4.0 or 0.5.0 to 0.5.1 */
};

int sd_migrate_store(int from, int to)
{
	int ver, ret;

	assert(to <= sizeof(migrate));

	ret = backup_store();
	if (ret != 0) {
		sd_eprintf("failed to backup the old store");
		return ret;
	}

	for (ver = from; ver < to; ver++) {
		ret = migrate[ver]();
		if (ret < 0)
			return ret;
	}

	/* success */
	return 0;
}
