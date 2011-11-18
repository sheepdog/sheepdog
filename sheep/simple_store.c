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

#include "sheep_priv.h"
#include "strbuf.h"
#include "util.h"


extern char *obj_path;

extern mode_t def_fmode;

static int def_store_flags = O_DSYNC | O_RDWR;

struct store_driver store;

static int simple_store_init(char *path)
{
	eprintf("Use simple store driver\n");
	return 0;
}

static int store_write_last_sector(uint64_t oid, struct siocb *iocb)
{
	const int size = SECTOR_SIZE;
	char *buf = NULL;
	int ret;

	buf = xzalloc(size);
	iocb->buf = buf;
	iocb->length = size;
	iocb->offset = SD_DATA_OBJ_SIZE - size;
	ret = store.write(oid, iocb);
	free(buf);

	return ret;
}

static int simple_store_open(uint64_t oid, struct siocb *iocb, int create)
{
	struct strbuf path = STRBUF_INIT;
	int ret;
	int flags = def_store_flags;

	if (sys->use_directio && is_data_obj(oid))
		flags |= O_DIRECT;

	if (create)
		flags |= O_CREAT | O_TRUNC;

	strbuf_addf(&path, "%s%08u/%016" PRIx64, obj_path, iocb->epoch, oid);

	ret = open(path.buf, flags, def_fmode);
	if (ret < 0) {
		eprintf("failed to open %s: %m\n", path.buf);
		if (errno == ENOENT) {
			struct stat s;

			ret = SD_RES_NO_OBJ;
			if (stat(obj_path, &s) < 0) {
				/* store directory is corrupted */
				eprintf("corrupted\n");
				ret = SD_RES_EIO;
			}
		} else
			ret = SD_RES_UNKNOWN;
		goto out;
	}

	iocb->fd = ret;
	if (!(iocb->flags & SD_FLAG_CMD_COW) && create) {
		/*
		 * Preallocate the whole object to get a better filesystem layout.
		 */
		ret = fallocate(iocb->fd, 0, 0, SD_DATA_OBJ_SIZE);
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
	iocb->rw_size = xpwrite(iocb->fd, iocb->buf, iocb->length, iocb->offset);
	if (iocb->rw_size < 0)
		return SD_RES_EIO;
	return SD_RES_SUCCESS;
}

static int simple_store_read(uint64_t oid, struct siocb *iocb)
{
	iocb->rw_size = xpread(iocb->fd, iocb->buf, iocb->length, iocb->offset);
	if (iocb->rw_size < 0)
		return SD_RES_EIO;
	return SD_RES_SUCCESS;
}

static int simple_store_close(uint64_t oid, struct siocb *iocb)
{
	if (close(iocb->fd) < 0)
		return SD_RES_EIO;
	return SD_RES_SUCCESS;
}

struct store_driver store = {
	.driver_name = "simple",
	.init = simple_store_init,
	.open = simple_store_open,
	.write = simple_store_write,
	.read = simple_store_read,
	.close = simple_store_close
};

void register_store_driver(struct store_driver *driver)
{
	store = *driver;
	eprintf("Register %s store driver\n", store.driver_name);
}
