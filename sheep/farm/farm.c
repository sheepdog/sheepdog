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

#include <dirent.h>

#include "farm.h"
#include "sheep_priv.h"

char farm_obj_dir[PATH_MAX];
char farm_dir[PATH_MAX];

static int def_open_flags = O_DSYNC | O_RDWR;
extern char *obj_path;
extern mode_t def_fmode;

static int create_directory(char *p)
{
	int i, ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, p);
	strbuf_addstr(&buf, ".farm");
	if (mkdir(buf.buf, 0755) < 0) {
		if (errno != EEXIST) {
			eprintf("%m\n");
			ret = -1;
			goto err;
		}
	}

	if (!strlen(farm_dir))
		memcpy(farm_dir, buf.buf, buf.len);

	strbuf_addstr(&buf, "/objects");
	if (mkdir(buf.buf, 0755) < 0) {
		if (errno != EEXIST) {
			eprintf("%m\n");
			ret = -1;
			goto err;
		}
	}
	for (i = 0; i < 256; i++) {
		strbuf_addf(&buf, "/%02x", i);
		if (mkdir(buf.buf, 0755) < 0) {
			if (errno != EEXIST) {
				eprintf("%m\n");
				ret = -1;
				goto err;
			}
		}
		strbuf_remove(&buf, buf.len - 3, 3);
	}

	if (!strlen(farm_obj_dir))
		memcpy(farm_obj_dir, buf.buf, buf.len);
err:
	strbuf_release(&buf);
	return ret;
}

static int farm_write(uint64_t oid, struct siocb *iocb)
{
	ssize_t size = xpwrite(iocb->fd, iocb->buf, iocb->length, iocb->offset);

	if (size != iocb->length)
		return SD_RES_EIO;

	trunk_update_entry(oid);
	return SD_RES_SUCCESS;
}

static int write_last_sector(int fd)
{
	const int size = SECTOR_SIZE;
	char *buf;
	int ret;
	off_t off = SD_DATA_OBJ_SIZE - size;

	buf = valloc(size);
	if (!buf) {
		eprintf("failed to allocate memory\n");
		return SD_RES_NO_MEM;
	}
	memset(buf, 0, size);

	ret = xpwrite(fd, buf, size, off);
	if (ret != size)
		ret = SD_RES_EIO;
	else
		ret = SD_RES_SUCCESS;
	free(buf);

	return ret;
}

static int err_to_sderr(uint64_t oid, int err)
{
	int ret;
	if (err == ENOENT) {
		struct stat s;

		if (stat(obj_path, &s) < 0) {
			eprintf("corrupted\n");
			ret = SD_RES_EIO;
		} else {
			dprintf("object %016" PRIx64 " not found locally\n", oid);
			ret = SD_RES_NO_OBJ;
		}
	} else {
		eprintf("%m\n");
		ret = SD_RES_UNKNOWN;
	}
	return ret;
}

/*
 * Preallocate the whole object to get a better filesystem layout.
 */
static int prealloc(int fd)
{
	int ret = fallocate(fd, 0, 0, SD_DATA_OBJ_SIZE);
	if (ret < 0) {
		if (errno != ENOSYS && errno != EOPNOTSUPP)
			ret = SD_RES_SYSTEM_ERROR;
		else
			ret = write_last_sector(fd);
	} else
		ret = SD_RES_SUCCESS;
	return ret;
}

static int farm_open(uint64_t oid, struct siocb *iocb, int create)
{
	struct strbuf buf = STRBUF_INIT;
	int ret = SD_RES_SUCCESS, fd;
	int flags = def_open_flags;

	if (iocb->epoch < sys->epoch)
		goto out;

	if (sys->use_directio && is_data_obj(oid))
		flags |= O_DIRECT;

	if (create)
		flags |= O_CREAT | O_TRUNC;

	strbuf_addstr(&buf, obj_path);
	strbuf_addf(&buf, "%016" PRIx64, oid);
	fd = open(buf.buf, flags, def_fmode);
	if (fd < 0) {
		ret = err_to_sderr(oid, errno);
		goto out;
	}
	iocb->fd = fd;
	ret = SD_RES_SUCCESS;
	if (!(iocb->flags & SD_FLAG_CMD_COW) && create) {
		ret = prealloc(fd);
		if (ret != SD_RES_SUCCESS)
			close(fd);
	}
out:
	strbuf_release(&buf);
	return ret;
}

static int farm_close(uint64_t oid, struct siocb *iocb)
{
	if (iocb->epoch < sys->epoch)
		return SD_RES_SUCCESS;

	if (close(iocb->fd) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

static int farm_init(char *p)
{
	dprintf("use farm store driver\n");
	if (create_directory(p) < 0)
		goto err;

	if (trunk_init() < 0)
		goto err;

	if (snap_init() < 0)
		goto err;

	return SD_RES_SUCCESS;
err:
	return SD_RES_EIO;
}

static int get_trunk_sha1(int epoch, unsigned char *outsha1, int user)
{
	int i, nr_logs = -1, ret = -1;
	struct snap_log *log_buf, *log_free = NULL;
	void *snap_buf = NULL;
	struct sha1_file_hdr hdr;

	log_free = log_buf = snap_log_read(&nr_logs, user);
	dprintf("%d\n", nr_logs);
	if (nr_logs < 0)
		goto out;

	for (i = 0; i < nr_logs; i++, log_buf++) {
		if (log_buf->epoch != epoch)
			continue;
		snap_buf = snap_file_read(log_buf->sha1, &hdr);
		if (!snap_buf)
			goto out;
		memcpy(outsha1, snap_buf, SHA1_LEN);
		ret = 0;
		break;
	}
out:
	free(log_free);
	free(snap_buf);
	return ret;
}

static int farm_get_objlist(struct siocb *iocb)
{
	struct sha1_file_hdr hdr;
	struct trunk_entry *trunk_buf, *trunk_free = NULL;
	unsigned char trunk_sha1[SHA1_LEN];
	uint64_t nr_trunks, i;
	uint64_t *objlist = (uint64_t *)iocb->buf;
	int ret = SD_RES_NO_TAG;

	if (get_trunk_sha1(iocb->epoch, trunk_sha1, 0) < 0)
		goto out;

	trunk_free = trunk_buf = trunk_file_read(trunk_sha1, &hdr);
	if (!trunk_buf)
		goto out;

	nr_trunks = hdr.priv;
	for (i = 0; i < nr_trunks; i++, trunk_buf++)
		objlist[iocb->length++] = trunk_buf->oid;

	dprintf("%"PRIu32"\n", iocb->length);
	ret = SD_RES_SUCCESS;
out:
	free(trunk_free);
	return ret;
}

static void *retrieve_object_from_snap(uint64_t oid, int epoch)
{
	struct sha1_file_hdr hdr;
	struct trunk_entry *trunk_buf, *trunk_free = NULL;
	unsigned char trunk_sha1[SHA1_LEN];
	uint64_t nr_trunks, i;
	void *buffer = NULL;

	if (get_trunk_sha1(epoch, trunk_sha1, 0) < 0)
		goto out;

	trunk_free = trunk_buf = trunk_file_read(trunk_sha1, &hdr);
	if (!trunk_buf)
		goto out;

	nr_trunks = hdr.priv;
	for (i = 0; i < nr_trunks; i++, trunk_buf++) {
		struct sha1_file_hdr h;
		if (trunk_buf->oid != oid)
			continue;
		buffer = sha1_file_read(trunk_buf->sha1, &h);
		if (!buffer)
			goto out;
		break;
	}
out:
	dprintf("oid %"PRIx64", epoch %d, %s\n", oid, epoch, buffer ? "succeed" : "fail");
	free(trunk_free);
	return buffer;
}

static int farm_read(uint64_t oid, struct siocb *iocb)
{
	if (iocb->epoch < sys->epoch) {
		void *buffer = retrieve_object_from_snap(oid, iocb->epoch);
		if (!buffer)
			return SD_RES_NO_OBJ;
		memcpy(iocb->buf, buffer, iocb->length);
		free(buffer);
	} else {
		ssize_t size = xpread(iocb->fd, iocb->buf, iocb->length, iocb->offset);

		if (size != iocb->length)
			return SD_RES_EIO;
	}
	return SD_RES_SUCCESS;
}

static int farm_atomic_put(uint64_t oid, struct siocb *iocb)
{
	char path[PATH_MAX], tmp_path[PATH_MAX];
	int flags = def_open_flags | O_CREAT;
	int ret = SD_RES_EIO, fd;
	uint32_t len = iocb->length;

	snprintf(path, sizeof(path), "%s%016" PRIx64, obj_path, oid);
	snprintf(tmp_path, sizeof(tmp_path), "%s%016" PRIx64 ".tmp",
		 obj_path, oid);
	fd = open(tmp_path, flags, def_fmode);
	if (fd < 0) {
		eprintf("failed to open %s: %m\n", tmp_path);
		goto out;
	}

	ret = xwrite(fd, iocb->buf, len);
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
	trunk_get_entry(oid);
	ret = SD_RES_SUCCESS;
out_close:
	close(fd);
out:
	return ret;
}

static int farm_link(uint64_t oid, struct siocb *iocb, int tgt_epoch)
{
	int ret = SD_RES_EIO;
	void *buf;
	struct siocb io = { 0 };

	dprintf("try link %"PRIx64" from snapshot with epoch %d\n", oid, tgt_epoch);
	buf = retrieve_object_from_snap(oid, tgt_epoch);
	if (!buf)
		goto fail;

	io.length = SD_DATA_OBJ_SIZE;
	io.buf = buf;
	ret = farm_atomic_put(oid, &io);
fail:
	free(buf);
	return ret;
}

static int farm_begin_recover(struct siocb *iocb)
{
	unsigned char snap_sha1[SHA1_LEN];
	int epoch = iocb->epoch - 1;

	if (epoch == 0)
		return SD_RES_SUCCESS;
	dprintf("epoch %d\n", epoch);
	if (snap_file_write(epoch, snap_sha1, 0) < 0)
		return SD_RES_EIO;

	if (snap_log_write(iocb->epoch - 1, snap_sha1, 0) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

static int oid_stale(uint64_t oid)
{
	int i, vidx;
	struct sd_vnode *vnodes = sys->vnodes;

	for (i = 0; i < sys->nr_sobjs; i++) {
		vidx = obj_to_sheep(vnodes, sys->nr_vnodes, oid, i);
		if (is_myself(vnodes[vidx].addr, vnodes[vidx].port))
			return 0;
	}
	return 1;
}

static int farm_end_recover(struct siocb *iocb)
{
	DIR *dir;
	struct dirent *d;
	uint64_t oid;
	int ret = SD_RES_EIO;

	dprintf("%d\n", iocb->epoch);
	dir = opendir(obj_path);
	if (!dir)
		goto out;

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;
		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0 || oid == ULLONG_MAX)
			continue;
		if (oid_stale(oid)) {
			char p[PATH_MAX];
			snprintf(p, sizeof(p), "%s%s", obj_path, d->d_name);
			if (unlink(p) < 0) {
				eprintf("%s:%m\n", p);
				goto out_close;
			}
			trunk_put_entry(oid);
			dprintf("remove oid %s\n", d->d_name);
		}
	}
	ret = SD_RES_SUCCESS;
out_close:
	closedir(dir);
out:
	return ret;
}

struct store_driver farm = {
	.name = "farm",
	.init = farm_init,
	.open = farm_open,
	.write = farm_write,
	.read = farm_read,
	.close = farm_close,
	.get_objlist = farm_get_objlist,
	.link = farm_link,
	.atomic_put = farm_atomic_put,
	.begin_recover = farm_begin_recover,
	.end_recover = farm_end_recover,
};

add_store_driver(farm);
