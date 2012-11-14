/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>

#include "sheep_priv.h"
#include "strbuf.h"
#include "util.h"
#include "farm/farm.h"

char *obj_path;
char *mnt_path;
char *jrnl_path;
char *epoch_path;

mode_t def_dmode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
mode_t def_fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

struct store_driver *sd_store;
LIST_HEAD(store_drivers);

int update_epoch_log(uint32_t epoch, struct sd_node *nodes, size_t nr_nodes)
{
	int fd, ret, len;
	time_t t;
	char path[PATH_MAX];

	dprintf("update epoch: %d, %zd\n", epoch, nr_nodes);

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDWR | O_CREAT | O_DSYNC, def_fmode);
	if (fd < 0) {
		ret = fd;
		goto err_open;
	}

	len = nr_nodes * sizeof(struct sd_node);
	ret = xwrite(fd, (char *)nodes, len);
	if (ret != len)
		goto err;

	/* Piggyback the epoch creation time for 'collie cluster info' */
	time(&t);
	len = sizeof(t);
	ret = xwrite(fd, (char *)&t, len);
	if (ret != len)
		goto err;

	close(fd);
	return 0;
err:
	close(fd);
err_open:
	dprintf("%s\n", strerror(errno));
	return -1;
}

int epoch_log_read_remote(uint32_t epoch, struct sd_node *nodes, int len)
{
	int i, ret;
	unsigned int nr, le;
	struct sd_node local_nodes[SD_MAX_NODES];

	le = get_latest_epoch();
	if (!le)
		return 0;

	nr = epoch_log_read(le, local_nodes, sizeof(local_nodes));
	if (nr < 0)
		return -1;

	for (i = 0; i < nr; i++) {
		struct sd_req hdr;
		struct sd_rsp *rsp = (struct sd_rsp *)&hdr;

		if (node_is_local(&local_nodes[i]))
			continue;

		sd_init_req(&hdr, SD_OP_GET_EPOCH);
		hdr.data_length = len;
		hdr.obj.tgt_epoch = epoch;
		ret = sheep_exec_req(&local_nodes[i].nid, &hdr, nodes);
		if (ret != SD_RES_SUCCESS)
			continue;

		return rsp->data_length / sizeof(*nodes);
	}

	/*
	 * If no node has targeted epoch log, return 0 here to at least
	 * allow reading older epoch logs.
	 */
	return 0;
}

int epoch_log_read(uint32_t epoch, struct sd_node *nodes, int len)
{
	int fd;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%08u", epoch_path, epoch);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		eprintf("failed to open epoch %"PRIu32" log\n", epoch);
		return -1;
	}

	len = read(fd, nodes, len);

	close(fd);

	if (len < 0) {
		eprintf("failed to read epoch %"PRIu32" log\n", epoch);
		return -1;
	}
	return len / sizeof(*nodes);
}

uint32_t get_latest_epoch(void)
{
	DIR *dir;
	struct dirent *d;
	uint32_t e, epoch = 0;
	char *p;

	dir = opendir(epoch_path);
	if (!dir) {
		vprintf(SDOG_EMERG, "failed to get the latest epoch: %m\n");
		abort();
	}

	while ((d = readdir(dir))) {
		e = strtol(d->d_name, &p, 10);
		if (d->d_name == p)
			continue;

		if (strlen(d->d_name) != 8)
			continue;

		if (e > epoch)
			epoch = e;
	}
	closedir(dir);

	return epoch;
}

static int init_path(const char *d, bool *new)
{
	int ret, retry = 0;
	struct stat s;

	if (new)
		*new = false;
again:
	ret = stat(d, &s);
	if (ret) {
		if (retry || errno != ENOENT) {
			eprintf("cannot handle the directory %s: %m\n", d);
			return 1;
		}

		ret = mkdir(d, def_dmode);
		if (ret) {
			eprintf("cannot create the directory %s: %m\n", d);
			return 1;
		} else {
			if (new)
				*new = true;
			retry++;
			goto again;
		}
	}

	if (!S_ISDIR(s.st_mode)) {
		eprintf("%s is not a directory\n", d);
		return 1;
	}

	return 0;
}

#define LOCK_PATH "/lock"

static int lock_base_dir(const char *d)
{
	char *lock_path;
	int ret = 0;
	int fd;

	lock_path = zalloc(strlen(d) + strlen(LOCK_PATH) + 1);
	sprintf(lock_path, "%s" LOCK_PATH, d);

	fd = open(lock_path, O_WRONLY|O_CREAT, def_fmode);
	if (fd < 0) {
		eprintf("failed to open lock file %s (%s)\n",
			lock_path, strerror(errno));
		ret = -1;
		goto out;
	}

	if (lockf(fd, F_TLOCK, 1) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			eprintf("another sheep daemon is using %s\n", d);
		} else {
			eprintf("unable to get base dir lock (%s)\n",
				strerror(errno));
		}
		ret = -1;
		goto out;
	}

out:
	free(lock_path);
	return ret;
}

int init_base_path(const char *d)
{
	int ret;

	ret = init_path(d, NULL);
	if (ret)
		return ret;
	return lock_base_dir(d);
}

#define OBJ_PATH "/obj/"

int init_obj_path(const char *base_path)
{
	int len;

	len = strlen(base_path);
	/* farm needs extra HEX_LEN + 3 chars to store snapshot objects.
	 * HEX_LEN + 3 = '/' + hex(2) + '/' + hex(38) + '\0'
	 */
	if (len + HEX_LEN + 3 > PATH_MAX) {
		eprintf("insanely long object directory %s", base_path);
		return -1;
	}

	obj_path = zalloc(strlen(base_path) + strlen(OBJ_PATH) + 1);
	sprintf(obj_path, "%s" OBJ_PATH, base_path);

	return init_path(obj_path, NULL);
}

#define EPOCH_PATH "/epoch/"

static int init_epoch_path(const char *base_path)
{
	epoch_path = zalloc(strlen(base_path) + strlen(EPOCH_PATH) + 1);
	sprintf(epoch_path, "%s" EPOCH_PATH, base_path);

	return init_path(epoch_path, NULL);
}

static int init_mnt_path(const char *base_path)
{
	int ret;
	FILE *fp;
	struct mntent *mnt;
	struct stat s, ms;

	ret = stat(base_path, &s);
	if (ret)
		return 1;

	fp = setmntent(MOUNTED, "r");
	if (!fp)
		return 1;

	while ((mnt = getmntent(fp))) {
		ret = stat(mnt->mnt_dir, &ms);
		if (ret)
			continue;

		if (ms.st_dev == s.st_dev) {
			mnt_path = strdup(mnt->mnt_dir);
			break;
		}
	}

	endmntent(fp);

	return 0;
}

#define JRNL_PATH "/journal/"

static int init_jrnl_path(const char *base_path)
{
	int ret;
	bool new;

	/* Create journal directory */
	jrnl_path = zalloc(strlen(base_path) + strlen(JRNL_PATH) + 1);
	sprintf(jrnl_path, "%s" JRNL_PATH, base_path);

	ret = init_path(jrnl_path, &new);
	/* Error during directory creation */
	if (ret)
		return ret;

	/* If journal is newly created */
	if (new)
		return 0;

	jrnl_recover(jrnl_path);

	return 0;
}

static int init_store_driver(void)
{
	char driver_name[STORE_LEN], *p;
	int ret;

	memset(driver_name, '\0', sizeof(driver_name));
	ret = get_cluster_store(driver_name);
	if (ret != SD_RES_SUCCESS)
		return ret;

	p = memchr(driver_name, '\0', STORE_LEN);
	if (!p) {
		/*
		 * If the driver name is not NUL terminated we are in deep
		 * trouble, let's get out here.
		 */
		dprintf("store name not NUL terminated\n");
		return SD_RES_NO_STORE;
	}

	/*
	 * The store file might not exist in case this is a new sheep that
	 * never joined a cluster before.
	 */
	if (p == driver_name)
		return 0;

	sd_store = find_store_driver(driver_name);
	if (!sd_store) {
		dprintf("store %s not found\n", driver_name);
		return SD_RES_NO_STORE;
	}

	return sd_store->init(obj_path);
}

static int init_disk_space(const char *base_path)
{
	int ret = SD_RES_SUCCESS;
	uint64_t space_size = 0;
	struct statvfs fs;

	if (sys->gateway_only)
		goto out;

	ret = get_cluster_space(&space_size);
	if (space_size != 0) {
		sys->disk_space = space_size;
		goto out;
	}

	if (sys->disk_space) {
		ret = set_cluster_space(sys->disk_space);
		goto out;
	}

	ret = statvfs(base_path, &fs);
	if (ret < 0) {
		dprintf("get disk space failed %m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	sys->disk_space = (uint64_t)fs.f_frsize * fs.f_bfree;
	ret = set_cluster_space(sys->disk_space);
out:
	dprintf("disk free space is %" PRIu64 "\n", sys->disk_space);
	return ret;
}

int init_store(const char *d)
{
	int ret;

	ret = init_epoch_path(d);
	if (ret)
		return ret;

	ret = init_mnt_path(d);
	if (ret)
		return ret;

	ret = init_jrnl_path(d);
	if (ret)
		return ret;

	ret = init_config_path(d);
	if (ret)
		return ret;

	ret = init_disk_space(d);
	if (ret)
		return ret;

	if (!sys->gateway_only) {
		ret = init_store_driver();
		if (ret)
			return ret;
	}

	if (is_object_cache_enabled()) {
		ret = object_cache_init(d);
		if (ret)
			return 1;
	}

	return ret;
}

/*
 * Write data to both local object cache (if enabled) and backends
 */
int write_object(uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, uint16_t flags, bool create, int nr_copies)
{
	struct sd_req hdr;
	int ret;

	if (is_object_cache_enabled() && object_is_cached(oid)) {
		ret = object_cache_write(oid, data, datalen, offset,
					 flags, create);
		if (ret == SD_RES_NO_CACHE)
			goto forward_write;

		if (ret != 0) {
			eprintf("write cache failed %"PRIx64" %"PRIx32"\n",
				oid, ret);
			return ret;
		}
	}

forward_write:
	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);
	hdr.flags = flags | SD_FLAG_CMD_WRITE;
	hdr.data_length = datalen;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;
	hdr.obj.copies = nr_copies;

	ret = exec_local_req(&hdr, data);
	if (ret != SD_RES_SUCCESS)
		eprintf("failed to write object %" PRIx64 ", %x\n", oid, ret);

	return ret;
}

int read_backend_object(uint64_t oid, char *data, unsigned int datalen,
		       uint64_t offset, int nr_copies)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.data_length = datalen;
	hdr.obj.oid = oid;
	hdr.obj.offset = offset;
	hdr.obj.copies = nr_copies;

	ret = exec_local_req(&hdr, data);
	if (ret != SD_RES_SUCCESS)
		eprintf("failed to read object %" PRIx64 ", %x\n", oid, ret);

	set_trimmed_sectors(data, rsp->obj.offset, rsp->data_length, datalen);

	return ret;
}

/*
 * Read data firstly from local object cache(if enabled), if fail,
 * try read backends
 */
int read_object(uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, int nr_copies)
{
	int ret;

	if (is_object_cache_enabled() && object_is_cached(oid)) {
		ret = object_cache_read(oid, data, datalen, offset);
		if (ret != SD_RES_SUCCESS) {
			eprintf("try forward read %"PRIx64" %"PRIx32"\n",
				oid, ret);
			goto forward_read;
		}
		return ret;
	}

forward_read:
	ret = read_backend_object(oid, data, datalen, offset, nr_copies);

	return ret;
}

int remove_object(uint64_t oid, int copies)
{
	struct sd_req hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_REMOVE_OBJ);
	hdr.obj.oid = oid;
	hdr.obj.copies = copies;

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		eprintf("failed to remove object %" PRIx64 ", %x\n", oid, ret);

	return ret;
}
