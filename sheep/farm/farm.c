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
#include <pthread.h>
#include <linux/limits.h>

#include "farm.h"
#include "sheep_priv.h"
#include "sheepdog_proto.h"
#include "sheep.h"

char farm_obj_dir[PATH_MAX];
char farm_dir[PATH_MAX];

static int def_open_flags = O_DIRECT | O_DSYNC | O_RDWR;

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
		strbuf_copyout(&buf, farm_dir, sizeof(farm_dir));

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
		strbuf_copyout(&buf, farm_obj_dir, sizeof(farm_obj_dir));
err:
	strbuf_release(&buf);
	return ret;
}

static int farm_exist(uint64_t oid)
{
	char path[PATH_MAX];

	sprintf(path, "%s%016"PRIx64, obj_path, oid);
	if (access(path, R_OK | W_OK) < 0) {
		if (errno != ENOENT)
			eprintf("%m\n");
		return 0;
	}

	return 1;
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

static int farm_write(uint64_t oid, struct siocb *iocb, int create)
{
	int flags = def_open_flags, fd, ret = SD_RES_SUCCESS;
	char path[PATH_MAX];
	ssize_t size;

	if (iocb->epoch < sys_epoch()) {
		dprintf("%"PRIu32" sys %"PRIu32"\n", iocb->epoch, sys_epoch());
		return SD_RES_OLD_NODE_VER;
	}
	if (is_vdi_obj(oid))
		flags &= ~O_DIRECT;

	if (create)
		flags |= O_CREAT | O_TRUNC;

	sprintf(path, "%s%016"PRIx64, obj_path, oid);
	fd = open(path, flags, def_fmode);
	if (fd < 0)
		return err_to_sderr(oid, errno);

	if (create && !(iocb->flags & SD_FLAG_CMD_COW)) {
		ret = prealloc(fd, is_vdi_obj(oid) ?
			       SD_INODE_SIZE : SD_DATA_OBJ_SIZE);
		if (ret != SD_RES_SUCCESS)
			goto out;
	}
	size = xpwrite(fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length) {
		eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	trunk_update_entry(oid);
out:
	close(fd);
	return ret;
}

static int write_last_sector(int fd, uint32_t length)
{
	const int size = SECTOR_SIZE;
	char *buf;
	int ret;
	off_t off = length - size;

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

/*
 * Preallocate the whole object to get a better filesystem layout.
 */
int prealloc(int fd, uint32_t size)
{
	int ret = fallocate(fd, 0, 0, size);
	if (ret < 0) {
		if (errno != ENOSYS && errno != EOPNOTSUPP) {
			dprintf("%m\n");
			ret = SD_RES_SYSTEM_ERROR;
		} else
			ret = write_last_sector(fd, size);
	} else
		ret = SD_RES_SUCCESS;
	return ret;
}

static int get_trunk_sha1(uint32_t epoch, unsigned char *outsha1, int user)
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

static int cleanup_trunk(uint32_t epoch)
{
	struct sha1_file_hdr hdr;
	struct trunk_entry *trunk_buf, *trunk_free = NULL;
	unsigned char trunk_sha1[SHA1_LEN];
	uint64_t nr_trunks, i;
	int ret = SD_RES_EIO;

	if (get_trunk_sha1(epoch, trunk_sha1, 0) < 0)
		goto out;

	trunk_free = trunk_buf = trunk_file_read(trunk_sha1, &hdr);
	if (!trunk_buf)
		goto out;

	nr_trunks = hdr.priv;
	for (i = 0; i < nr_trunks; i++, trunk_buf++)
		sha1_file_try_delete(trunk_buf->sha1);

	if (sha1_file_try_delete(trunk_sha1) < 0)
		goto out;

	ret = SD_RES_SUCCESS;

out:
	free(trunk_free);
	return ret;
}

static int farm_cleanup_sys_obj(struct siocb *iocb)
{
	int i, ret = SD_RES_SUCCESS;
	uint32_t epoch = iocb->epoch;
	struct snap_log *log_pos, *log_free = NULL;
	int nr_logs;

	if (iocb->epoch == 0)
		return ret;

	for (i = 1; i <= epoch; i++)
		cleanup_trunk(i);

	log_free = log_pos = snap_log_read(&nr_logs, 0);
	if (snap_log_truncate() < 0) {
		dprintf("snap reset fail\n");
		ret = SD_RES_EIO;
		goto out;
	}

	for (i = epoch + 1; i < nr_logs; i++, log_pos++) {
		if (snap_log_write(log_pos->epoch, log_pos->sha1, 0) < 0) {
			dprintf("snap write fail %d, %s\n",
					log_pos->epoch, sha1_to_hex(log_pos->sha1));
			ret = SD_RES_EIO;
			goto out;
		}
	}

out:
	free(log_free);
	return ret;
}

static int init_sys_vdi_bitmap(char *path)
{
	DIR *dir;
	struct dirent *dent;

	dir = opendir(path);
	if (!dir) {
		vprintf(SDOG_ERR, "failed to open the working directory: %m\n");
		return -1;
	}

	vprintf(SDOG_INFO, "found the working directory %s\n", path);
	while ((dent = readdir(dir))) {
		uint64_t oid;

		if (!strcmp(dent->d_name, "."))
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

	return 0;
}

static int farm_init(char *p)
{
	struct siocb iocb;

	dprintf("use farm store driver\n");
	if (create_directory(p) < 0)
		goto err;

	if (trunk_init() < 0)
		goto err;

	if (snap_init() < 0)
		goto err;

	if (init_sys_vdi_bitmap(p) < 0)
		goto err;

	iocb.epoch = sys->epoch ? sys->epoch - 1 : 0;
	farm_cleanup_sys_obj(&iocb);

	return SD_RES_SUCCESS;
err:
	return SD_RES_EIO;
}

static void *read_working_object(uint64_t oid, uint64_t offset,
				 uint32_t length)
{
	void *buf = NULL;
	char path[PATH_MAX];
	int fd, flags = def_open_flags;
	size_t size;

	snprintf(path, sizeof(path), "%s%016" PRIx64, obj_path, oid);

	if (is_vdi_obj(oid))
		flags &= ~O_DIRECT;

	fd = open(path, flags);
	if (fd < 0) {
		dprintf("object %"PRIx64" not found\n", oid);
		goto out;
	}

	buf = valloc(length);
	if (!buf) {
		eprintf("no memory to allocate buffer.\n");
		goto out;
	}

	size = xpread(fd, buf, length, offset);
	if (length != size) {
		eprintf("size %zu len %"PRIu32" off %"PRIu64" %m\n", size,
			length, offset);
		free(buf);
		buf = NULL;
		goto out;
	}

out:
	if (fd > 0)
		close(fd);
	return buf;
}

static void *retrieve_object_from_snap(uint64_t oid, uint32_t epoch)
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
		break;
	}

out:
	dprintf("oid %"PRIx64", epoch %d, %s\n", oid, epoch, buffer ? "succeed" : "fail");
	free(trunk_free);
	return buffer;
}

static int farm_read(uint64_t oid, struct siocb *iocb)
{
	int flags = def_open_flags, fd, ret = SD_RES_SUCCESS;
	uint32_t epoch = sys_epoch();
	char path[PATH_MAX];
	ssize_t size;
	int i;
	void *buffer;

	if (iocb->epoch < epoch) {

		buffer = read_working_object(oid, iocb->offset, iocb->length);
		if (!buffer) {
			/* Here if read the object from the targeted epoch failed,
			 * we need to read from the later epoch, because at some epoch
			 * we doesn't write the object to the snapshot, we assume
			 * it in the current local object directory, but maybe
			 * in the next epoch we removed it from the local directory.
			 * in this case, we should try to retrieve object upwards, since.
			 * when the object is to be removed, it will get written to the
			 * snapshot at later epoch.
			 */
			for (i = iocb->epoch; i < epoch; i++) {
				buffer = retrieve_object_from_snap(oid, i);
				if (buffer)
					break;
			}
		}
		if (!buffer)
			return SD_RES_NO_OBJ;
		memcpy(iocb->buf, buffer, iocb->length);
		free(buffer);

		return SD_RES_SUCCESS;
	}

	if (is_vdi_obj(oid))
		flags &= ~O_DIRECT;

	sprintf(path, "%s%016"PRIx64, obj_path, oid);
	fd = open(path, flags);

	if (fd < 0)
		return err_to_sderr(oid, errno);

	size = xpread(fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length) {
		ret = SD_RES_EIO;
		goto out;
	}
out:
	close(fd);
	return ret;
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

	if (is_vdi_obj(oid))
		flags &= ~O_DIRECT;
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

static int farm_link(uint64_t oid, struct siocb *iocb, uint32_t tgt_epoch)
{
	int ret = SD_RES_EIO;
	void *buf = NULL;
	struct siocb io = { 0 };
	int i;
	uint32_t epoch = sys_epoch();

	dprintf("try link %"PRIx64" from snapshot with epoch %d\n", oid, tgt_epoch);

	for (i = tgt_epoch; i < epoch; i++) {
		buf = retrieve_object_from_snap(oid, i);
		if (buf)
			break;
	}
	if (!buf)
		goto out;

	io.length = iocb->length;
	io.buf = buf;
	ret = farm_atomic_put(oid, &io);
out:
	free(buf);
	return ret;
}

static int farm_end_recover(struct siocb *iocb)
{
	unsigned char snap_sha1[SHA1_LEN];
	unsigned char trunk_sha1[SHA1_LEN];
	uint32_t epoch = iocb->epoch - 1;

	if (epoch == 0)
		return SD_RES_SUCCESS;
	dprintf("epoch %d\n", iocb->epoch);
	if (trunk_file_write_recovery(trunk_sha1) < 0)
		return SD_RES_EIO;

	if (snap_file_write(epoch, trunk_sha1, snap_sha1, 0) < 0)
		return SD_RES_EIO;

	if (snap_log_write(epoch, snap_sha1, 0) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

static int farm_snapshot(struct siocb *iocb)
{
	unsigned char snap_sha1[SHA1_LEN];
	unsigned char trunk_sha1[SHA1_LEN];
	void *buffer;
	int log_nr, ret = SD_RES_EIO, epoch;

	buffer = snap_log_read(&log_nr, 1);
	if (!buffer)
		goto out;

	epoch = log_nr + 1;
	dprintf("user epoch %d\n", epoch);
	if (trunk_file_write_user(trunk_sha1) < 0)
		goto out;

	if (snap_file_write(epoch, trunk_sha1, snap_sha1, 1) < 0)
		goto out;

	if (snap_log_write(epoch, snap_sha1, 1) < 0)
		goto out;

	ret = SD_RES_SUCCESS;
out:
	free(buffer);
	return ret;
}

static int cleanup_working_dir(void)
{
	DIR *dir;
	struct dirent *d;

	dprintf("try clean up working dir\n");
	dir = opendir(obj_path);
	if (!dir)
		return -1;

	while ((d = readdir(dir))) {
		char p[PATH_MAX];
		if (!strncmp(d->d_name, ".", 1))
			continue;
		snprintf(p, sizeof(p), "%s%s", obj_path, d->d_name);
		if (unlink(p) < 0) {
			eprintf("%s:%m\n", p);
			continue;
		}
		dprintf("remove file %s\n", d->d_name);
	}
	closedir(dir);
	return 0;
}

static int restore_objects_from_snap(uint32_t epoch)
{
	struct sha1_file_hdr hdr;
	struct trunk_entry *trunk_buf, *trunk_free = NULL;
	unsigned char trunk_sha1[SHA1_LEN];
	uint64_t nr_trunks, i;
	int ret = SD_RES_EIO;

	if (get_trunk_sha1(epoch, trunk_sha1, 1) < 0)
		goto out;

	trunk_free = trunk_buf = trunk_file_read(trunk_sha1, &hdr);
	if (!trunk_buf)
		goto out;

	nr_trunks = hdr.priv;
	ret = SD_RES_SUCCESS;
	for (i = 0; i < nr_trunks; i++, trunk_buf++) {
		struct sha1_file_hdr h;
		struct siocb io = { 0 };
		uint64_t oid;
		void *buffer = NULL;

		oid = trunk_buf->oid;
		buffer = sha1_file_read(trunk_buf->sha1, &h);
		if (!buffer) {
			eprintf("oid %"PRIx64" not restored\n", oid);
			goto out;
		}
		io.length = h.size;
		io.buf = buffer;
		ret = farm_atomic_put(oid, &io);
		if (ret != SD_RES_SUCCESS) {
			eprintf("oid %"PRIx64" not restored\n", oid);
			goto out;
		} else
			dprintf("oid %"PRIx64" restored\n", oid);

		free(buffer);
	}
out:
	free(trunk_free);
	return ret;
}

static int farm_restore(struct siocb *iocb)
{
	int ret = SD_RES_EIO, epoch = iocb->epoch;

	dprintf("try recover user epoch %d\n", epoch);

	if (cleanup_working_dir() < 0) {
		eprintf("failed to clean up the working dir %m\n");
		goto out;
	}

	ret = restore_objects_from_snap(epoch);
	if (ret != SD_RES_SUCCESS)
		goto out;
out:
	return ret;
}

static int farm_get_snap_file(struct siocb *iocb)
{
	int ret = SD_RES_EIO;
	void *buffer = NULL;
	size_t size;
	int nr;

	dprintf("try get snap file\n");
	buffer = snap_log_read(&nr, 1);
	if (!buffer)
		goto out;
	size = nr * sizeof(struct snap_log);
	memcpy(iocb->buf, buffer, size);
	iocb->length = size;
	ret = SD_RES_SUCCESS;
out:
	free(buffer);
	return ret;
}

static int farm_format(struct siocb *iocb)
{
	char path[PATH_MAX];
	unsigned ret;
	const char name[] = "farm";

	dprintf("try get a clean store\n");
	snprintf(path, sizeof(path), "%s", obj_path);
	ret = rmdir_r(path);
	if (ret && ret != -ENOENT) {
		eprintf("failed to remove %s: %s\n", path, strerror(-ret));
		return SD_RES_EIO;
	}
	if (mkdir(path, def_dmode) < 0) {
		eprintf("%m\n");
		return SD_RES_EIO;
	}

	if (set_cluster_store(name) < 0)
		return SD_RES_EIO;

	trunk_reset();

	return SD_RES_SUCCESS;
}

static int farm_purge_obj(void)
{
	if (cleanup_working_dir() < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

struct store_driver farm = {
	.name = "farm",
	.init = farm_init,
	.exist = farm_exist,
	.write = farm_write,
	.read = farm_read,
	.link = farm_link,
	.atomic_put = farm_atomic_put,
	.end_recover = farm_end_recover,
	.snapshot = farm_snapshot,
	.cleanup = farm_cleanup_sys_obj,
	.restore = farm_restore,
	.get_snap_file = farm_get_snap_file,
	.format = farm_format,
	.purge_obj = farm_purge_obj,
};

add_store_driver(farm);
