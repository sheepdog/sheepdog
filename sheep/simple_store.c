/*
 * Copyright (C) 2011 Taobao Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "sheep_priv.h"
#include "strbuf.h"
#include "util.h"


static int def_store_flags = O_DIRECT | O_DSYNC | O_RDWR;

static int simple_store_write(uint64_t oid, struct siocb *iocb);

static int simple_store_init(char *path)
{
	uint32_t epoch, latest_epoch;
	DIR *dir;
	struct dirent *dent;
	char p[PATH_MAX];

	eprintf("use simple store driver\n");
	strcpy(p, path);
	latest_epoch = get_latest_epoch();
	for (epoch = 1; epoch <= latest_epoch; epoch++) {
		snprintf(p, PATH_MAX, "%s/%08u", path, epoch);
		dir = opendir(p);
		if (!dir) {
			if (errno == ENOENT)
				continue;

			vprintf(SDOG_ERR, "failed to open the epoch directory: %m\n");
			return SD_RES_EIO;
		}

		vprintf(SDOG_INFO, "found the object directory %s\n", path);
		while ((dent = readdir(dir))) {
			uint64_t oid;

			if (!strcmp(dent->d_name, ".") ||
					!strcmp(dent->d_name, ".."))
				continue;

			oid = strtoull(dent->d_name, NULL, 16);
			if (oid == 0 || oid == ULLONG_MAX)
				continue;

			if (!is_vdi_obj(oid))
				continue;

			vprintf(SDOG_DEBUG, "found the VDI object %" PRIx64 "\n", oid);

			set_bit(oid_to_vid(oid), sys->vdi_inuse);
		}
		closedir(dir);
	}
	return SD_RES_SUCCESS;
}

static int store_write_last_sector(uint64_t oid, struct siocb *iocb)
{
	const int size = SECTOR_SIZE;
	char *buf = NULL;
	int ret;
	uint32_t length = iocb->length;

	buf = valloc(size);
	if (!buf) {
		eprintf("failed to allocate memory\n");
		return SD_RES_NO_MEM;
	}
	memset(buf, 0, size);

	iocb->buf = buf;
	iocb->length = size;
	iocb->offset = length - size;
	ret = simple_store_write(oid, iocb);
	free(buf);

	return ret;
}

static int simple_store_open(uint64_t oid, struct siocb *iocb, int create)
{
	struct strbuf path = STRBUF_INIT;
	int ret;
	int flags = def_store_flags;

	if (is_vdi_obj(oid))
		flags &= ~O_DIRECT;

	if (create)
		flags |= O_CREAT | O_TRUNC;

	strbuf_addf(&path, "%s%08u/%016" PRIx64, obj_path, iocb->epoch, oid);

	ret = open(path.buf, flags, def_fmode);
	if (ret < 0) {
		if (errno == ENOENT) {
			struct stat s;

			if (stat(obj_path, &s) < 0) {
				eprintf("store directory corrupted: %m\n");
				ret = SD_RES_EIO;
			} else {
				dprintf("object %08u/%016" PRIx64 " not found locally\n", iocb->epoch, oid);
				ret = SD_RES_NO_OBJ;
			}
		} else {
			eprintf("failed to open %s: %m\n", path.buf);
			ret = SD_RES_UNKNOWN;
		}
		goto out;
	}

	iocb->fd = ret;
	if (!(iocb->flags & SD_FLAG_CMD_COW) && create) {
		/*
		 * Preallocate the whole object to get a better filesystem layout.
		 */
		ret = fallocate(iocb->fd, 0, 0, iocb->length);
		if (ret < 0) {
			if (errno != ENOSYS && errno != EOPNOTSUPP) {
				ret = SD_RES_EIO;
				close(iocb->fd);
				goto out;
			}

			ret = store_write_last_sector(oid, iocb);
			if (ret) {
				close(iocb->fd);
				goto out;
			}
		}
	}

	ret = SD_RES_SUCCESS;
out:
	strbuf_release(&path);
	return ret;
}

static int simple_store_write(uint64_t oid, struct siocb *iocb)
{
	int size = xpwrite(iocb->fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length)
		return SD_RES_EIO;
	return SD_RES_SUCCESS;
}

static int simple_store_read(uint64_t oid, struct siocb *iocb)
{
	int size = xpread(iocb->fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length)
		return SD_RES_EIO;
	return SD_RES_SUCCESS;
}

static int simple_store_close(uint64_t oid, struct siocb *iocb)
{
	if (close(iocb->fd) < 0)
		return SD_RES_EIO;
	return SD_RES_SUCCESS;
}

static int get_epoch_obj_list(uint32_t epoch, uint64_t *objlist, int *nr)
{
	struct strbuf buf = STRBUF_INIT;
	DIR *dir;
	struct dirent *d;
	int length = 0;
	int ret = SD_RES_SUCCESS;

	strbuf_addf(&buf, "%s%08u/", obj_path, epoch);

	dprintf("%s\n", buf.buf);

	dir = opendir(buf.buf);
	if (!dir) {
		ret = SD_RES_EIO;
		goto out;
	}
	while ((d = readdir(dir))) {
		uint64_t oid;
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0)
			continue;

		objlist[length++] = oid;
	}
	closedir(dir);
	*nr = length;
out:
	strbuf_release(&buf);
	return ret;
}

static int simple_store_get_objlist(struct siocb *siocb)
{
	uint64_t *objlist = (uint64_t*)siocb->buf;
	uint64_t *buf;
	uint32_t epoch;
	int nr = 0, obj_nr = 0;
	DIR *dir;
	struct dirent *d;
	int ret = SD_RES_SUCCESS, r;

	dir = opendir(obj_path);
	if (!dir) {
		ret = SD_RES_EIO;
		goto out;
	}

	buf = zalloc(1 << 22);
	if (!buf) {
		dprintf("no memory to allocate.\n");
		ret = SD_RES_NO_MEM;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;
		epoch = strtoul(d->d_name, NULL, 16);
		if (epoch == 0)
			continue;

		r = get_epoch_obj_list(epoch, buf, &obj_nr);
		if (SD_RES_SUCCESS == r)
			nr = merge_objlist(objlist, nr, buf, obj_nr);
	}
	closedir(dir);

	siocb->length = nr;
	free(buf);
out:
	return ret;
}

static int simple_store_link(uint64_t oid, struct siocb *iocb, uint32_t tgt_epoch)
{
       char old[PATH_MAX], new[PATH_MAX];

       snprintf(old, sizeof(old), "%s%08u/%016" PRIx64, obj_path,
                tgt_epoch, oid);
       snprintf(new, sizeof(new), "%s%08u/%016" PRIx64, obj_path,
                iocb->epoch, oid);
       dprintf("link from %s to %s\n", old, new);
       if (link(old, new) == 0)
               return SD_RES_SUCCESS;

       if (errno == ENOENT)
               return SD_RES_NO_OBJ;

       return SD_RES_EIO;
}

static int simple_store_atomic_put(uint64_t oid, struct siocb *iocb)
{
	char path[PATH_MAX], tmp_path[PATH_MAX];
	int flags = O_DSYNC | O_RDWR | O_CREAT;
	int ret = SD_RES_EIO, epoch = iocb->epoch, fd;
	uint32_t len = iocb->length;

	snprintf(path, sizeof(path), "%s%08u/%016" PRIx64, obj_path,
		 epoch, oid);
	snprintf(tmp_path, sizeof(tmp_path), "%s%08u/%016" PRIx64 ".tmp",
		 obj_path, epoch, oid);

	fd = open(tmp_path, flags, def_fmode);
	if (fd < 0) {
		eprintf("failed to open %s: %m\n", tmp_path);
		goto out;
	}

	ret = write(fd, iocb->buf, len);
	if (ret != len) {
		eprintf("failed to write object. %m\n");
		ret = SD_RES_EIO;
		goto out_close;
	}


	ret = rename(tmp_path, path);
	if (ret < 0) {
		eprintf("failed to rename %s to %s: %m\n", tmp_path, path);
		ret = SD_RES_EIO;
		goto out_close;
	}
	dprintf("%"PRIx64"\n", oid);
	ret = SD_RES_SUCCESS;
out_close:
	close(fd);
out:
	return ret;
}

static int simple_store_format(struct siocb *iocb)
{
	char path[PATH_MAX];
	unsigned epoch = iocb->epoch, ret, i;
	const char name[] = "simple";

	dprintf("epoch %u\n", epoch);
	for (i = 1; i <= epoch; i++) {
		snprintf(path, sizeof(path), "%s%08u", obj_path, i);
		ret = rmdir_r(path);
		if (ret && ret != -ENOENT) {
			eprintf("failed to remove %s: %s\n", path, strerror(-ret));
			return SD_RES_EIO;
		}
	}

	if (set_cluster_store(name) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

struct store_driver simple_store = {
	.name = "simple",
	.init = simple_store_init,
	.open = simple_store_open,
	.write = simple_store_write,
	.read = simple_store_read,
	.close = simple_store_close,
	.get_objlist = simple_store_get_objlist,
	.link = simple_store_link,
	.atomic_put = simple_store_atomic_put,
	.format = simple_store_format,
};

add_store_driver(simple_store);
