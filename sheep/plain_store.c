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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>

#include "sheep_priv.h"
#include "config.h"

static int get_open_flags(uint64_t oid, bool create, int fl)
{
	int flags = O_DSYNC | O_RDWR;

	if (uatomic_is_true(&sys->use_journal) || sys->nosync == true)
		flags &= ~O_DSYNC;

	/* We can not use DIO for inode object because it is not 512B aligned */
	if (sys->backend_dio && is_data_obj(oid))
		flags |= O_DIRECT;

	if (create)
		flags |= O_CREAT | O_EXCL;

	return flags;
}

static int get_obj_path(uint64_t oid, char *path)
{
	return snprintf(path, PATH_MAX, "%s/%016" PRIx64,
			get_object_path(oid), oid);
}

static int get_tmp_obj_path(uint64_t oid, char *path)
{
	return snprintf(path, PATH_MAX, "%s/%016"PRIx64".tmp",
			get_object_path(oid), oid);
}

static int get_stale_obj_path(uint64_t oid, uint32_t epoch, char *path)
{
	return md_get_stale_path(oid, epoch, path);
}

bool default_exist(uint64_t oid)
{
	return md_exist(oid);
}

static int err_to_sderr(char *path, uint64_t oid, int err)
{
	struct stat s;
	char *dir = dirname(path);

	sd_dprintf("%s", dir);
	switch (err) {
	case ENOENT:
		if (stat(dir, &s) < 0) {
			sd_eprintf("%s corrupted", dir);
			return md_handle_eio(dir);
		}
		sd_dprintf("object %016" PRIx64 " not found locally", oid);
		return SD_RES_NO_OBJ;
	case ENOSPC:
		/* TODO: stop automatic recovery */
		sd_eprintf("diskfull, oid=%"PRIx64, oid);
		return SD_RES_NO_SPACE;
	default:
		sd_eprintf("oid=%"PRIx64", %m", oid);
		return md_handle_eio(dir);
	}
}

int default_write(uint64_t oid, const struct siocb *iocb)
{
	int flags = get_open_flags(oid, false, iocb->flags), fd,
	    ret = SD_RES_SUCCESS;
	char path[PATH_MAX];
	ssize_t size;

	if (iocb->epoch < sys_epoch()) {
		sd_dprintf("%"PRIu32" sys %"PRIu32, iocb->epoch, sys_epoch());
		return SD_RES_OLD_NODE_VER;
	}

	get_obj_path(oid, path);

	if (uatomic_is_true(&sys->use_journal) &&
	    journal_write_store(oid, iocb->buf, iocb->length, iocb->offset,
				false)
	    != SD_RES_SUCCESS) {
		sd_eprintf("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_DSYNC;
		sync();
	}

	fd = open(path, flags, def_fmode);
	if (fd < 0)
		return err_to_sderr(path, oid, errno);

	size = xpwrite(fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length) {
		sd_eprintf("failed to write object %"PRIx64", path=%s, offset=%"
			PRId64", size=%"PRId32", result=%zd, %m", oid, path,
			iocb->offset, iocb->length, size);
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}
out:
	close(fd);
	return ret;
}

static int make_stale_dir(char *path)
{
	char p[PATH_MAX];

	snprintf(p, PATH_MAX, "%s/.stale", path);
	if (xmkdir(p, def_dmode) < 0) {
		sd_eprintf("%s failed, %m", p);
		return SD_RES_EIO;
	}
	return SD_RES_SUCCESS;
}

static int purge_dir(char *path)
{
	if (purge_directory(path) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

static int purge_stale_dir(char *path)
{
	char p[PATH_MAX];

	snprintf(p, PATH_MAX, "%s/.stale", path);
	return purge_dir(p);
}

int default_cleanup(void)
{
	int ret;

	ret = for_each_obj_path(purge_stale_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return SD_RES_SUCCESS;
}

static int init_vdi_copy_number(uint64_t oid, char *wd)
{
	char path[PATH_MAX];
	int fd, flags = get_open_flags(oid, false, 0), ret;
	struct sheepdog_inode *inode = xzalloc(sizeof(*inode));

	snprintf(path, sizeof(path), "%s/%016"PRIx64, wd, oid);

	fd = open(path, flags);
	if (fd < 0) {
		sd_eprintf("failed to open %s, %m", path);
		ret = SD_RES_EIO;
		goto out;
	}

	ret = xpread(fd, inode, SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_INODE_HEADER_SIZE) {
		sd_eprintf("failed to read inode header, path=%s, %m", path);
		ret = SD_RES_EIO;
		goto out;
	}

	add_vdi_copy_number(oid_to_vid(oid), inode->nr_copies);

	ret = SD_RES_SUCCESS;
out:
	free(inode);
	return SD_RES_SUCCESS;
}

static int init_objlist_and_vdi_bitmap(uint64_t oid, char *wd, void *arg)
{
	int ret;
	objlist_cache_insert(oid);

	if (is_vdi_obj(oid)) {
		sd_dprintf("found the VDI object %" PRIx64, oid);
		set_bit(oid_to_vid(oid), sys->vdi_inuse);
		ret = init_vdi_copy_number(oid, wd);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return SD_RES_SUCCESS;
}

int default_init(void)
{
	int ret;

	sd_dprintf("use plain store driver");
	ret = for_each_obj_path(make_stale_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return for_each_object_in_wd(init_objlist_and_vdi_bitmap, true, NULL);
}

static int default_read_from_path(uint64_t oid, char *path,
				  const struct siocb *iocb)
{
	int flags = get_open_flags(oid, false, iocb->flags), fd,
	    ret = SD_RES_SUCCESS;
	ssize_t size;

	fd = open(path, flags);

	if (fd < 0)
		return err_to_sderr(path, oid, errno);

	size = xpread(fd, iocb->buf, iocb->length, iocb->offset);
	if (size != iocb->length) {
		sd_eprintf("failed to read object %"PRIx64", path=%s, offset=%"
			PRId64", size=%"PRId32", result=%zd, %m", oid, path,
			iocb->offset, iocb->length, size);
		ret = err_to_sderr(path, oid, errno);
	}

	close(fd);

	return ret;
}

int default_read(uint64_t oid, const struct siocb *iocb)
{
	int ret;
	char path[PATH_MAX];
	uint32_t epoch = sys_epoch();

	get_obj_path(oid, path);
	ret = default_read_from_path(oid, path, iocb);

	/*
	 * If the request is againt the older epoch, try to read from
	 * the stale directory
	 */
	while (ret == SD_RES_NO_OBJ && iocb->epoch < epoch) {
		epoch--;
		get_stale_obj_path(oid, epoch, path);
		ret = default_read_from_path(oid, path, iocb);
	}

	return ret;
}

/* Preallocate the whole object to get a better filesystem layout. */
int prealloc(int fd, uint32_t size)
{
	int ret = fallocate(fd, 0, 0, size);
	if (ret < 0) {
		if (errno != ENOSYS && errno != EOPNOTSUPP) {
			sd_eprintf("failed to preallocate space, %m");
			return ret;
		}

		return ftruncate(fd, size);
	}

	return 0;
}

int default_create_and_write(uint64_t oid, const struct siocb *iocb)
{
	char path[PATH_MAX], tmp_path[PATH_MAX];
	int flags = get_open_flags(oid, true, iocb->flags);
	int ret, fd;
	uint32_t len = iocb->length;

	get_obj_path(oid, path);
	get_tmp_obj_path(oid, tmp_path);

	if (uatomic_is_true(&sys->use_journal) &&
	    journal_write_store(oid, iocb->buf, iocb->length,
				iocb->offset, true)
	    != SD_RES_SUCCESS) {
		sd_eprintf("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_DSYNC;
		sync();
	}

	fd = open(tmp_path, flags, def_fmode);
	if (fd < 0) {
		if (errno == EEXIST) {
			/*
			 * This happens if node membership changes during object
			 * creation; while gateway retries a CREATE request,
			 * recovery process could also recover the object at the
			 * same time.  They should try to write the same date,
			 * so it is okay to simply return success here.
			 */
			sd_dprintf("%s exists", tmp_path);
			return SD_RES_SUCCESS;
		}

		sd_eprintf("failed to open %s: %m", tmp_path);
		return err_to_sderr(path, oid, errno);
	}

	if (iocb->offset != 0 || iocb->length != get_objsize(oid)) {
		ret = prealloc(fd, get_objsize(oid));
		if (ret < 0) {
			ret = err_to_sderr(path, oid, errno);
			goto out;
		}
	}

	ret = xpwrite(fd, iocb->buf, len, iocb->offset);
	if (ret != len) {
		sd_eprintf("failed to write object. %m");
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}

	ret = rename(tmp_path, path);
	if (ret < 0) {
		sd_eprintf("failed to rename %s to %s: %m", tmp_path, path);
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}
	sd_dprintf("%"PRIx64, oid);
	ret = SD_RES_SUCCESS;
out:
	if (ret != SD_RES_SUCCESS)
		unlink(tmp_path);
	close(fd);
	return ret;
}

int default_link(uint64_t oid, uint32_t tgt_epoch)
{
	char path[PATH_MAX], stale_path[PATH_MAX];

	sd_dprintf("try link %"PRIx64" from snapshot with epoch %d", oid,
		   tgt_epoch);

	get_obj_path(oid, path);
	get_stale_obj_path(oid, tgt_epoch, stale_path);

	if (link(stale_path, path) < 0) {
		sd_eprintf("failed to link from %s to %s, %m", stale_path,
			   path);
		return err_to_sderr(path, oid, errno);
	}

	return SD_RES_SUCCESS;
}

static bool oid_stale(uint64_t oid)
{
	int i, nr_copies;
	struct vnode_info *vinfo;
	const struct sd_vnode *v;
	bool ret = true;
	const struct sd_vnode *obj_vnodes[SD_MAX_COPIES];

	vinfo = get_vnode_info();
	nr_copies = get_obj_copy_number(oid, vinfo->nr_zones);
	if (!nr_copies) {
		ret = false;
		goto out;
	}

	oid_to_vnodes(vinfo->vnodes, vinfo->nr_vnodes, oid,
		      nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			ret = false;
			break;
		}
	}
out:
	put_vnode_info(vinfo);
	return ret;
}

static int move_object_to_stale_dir(uint64_t oid, char *wd, void *arg)
{
	char path[PATH_MAX], stale_path[PATH_MAX];
	uint32_t tgt_epoch = *(int *)arg;

	snprintf(path, PATH_MAX, "%s/%016" PRIx64, wd, oid);
	snprintf(stale_path, PATH_MAX, "%s/.stale/%016"PRIx64".%"PRIu32, wd,
		 oid, tgt_epoch);

	if (rename(path, stale_path) < 0) {
		sd_eprintf("failed to move stale object %"PRIX64" to %s, %m",
			   oid, path);
		return SD_RES_EIO;
	}

	sd_dprintf("moved object %"PRIx64, oid);
	return SD_RES_SUCCESS;
}

static int check_stale_objects(uint64_t oid, char *wd, void *arg)
{
	if (oid_stale(oid))
		return move_object_to_stale_dir(oid, wd, arg);

	return SD_RES_SUCCESS;
}

int default_end_recover(uint32_t old_epoch,
			const struct vnode_info *old_vnode_info)
{
	if (old_epoch == 0)
		return SD_RES_SUCCESS;

	return for_each_object_in_wd(check_stale_objects, false, &old_epoch);
}

int default_format(void)
{
	unsigned ret;

	sd_dprintf("try get a clean store");
	ret = for_each_obj_path(purge_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (sys->enable_object_cache)
		object_cache_format();

	return SD_RES_SUCCESS;
}

int default_remove_object(uint64_t oid)
{
	char path[PATH_MAX];

	get_obj_path(oid, path);

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return SD_RES_NO_OBJ;

		sd_eprintf("failed to remove object %"PRIx64", %m", oid);
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

int default_purge_obj(void)
{
	uint32_t tgt_epoch = get_latest_epoch();

	return for_each_object_in_wd(move_object_to_stale_dir, true, &tgt_epoch);
}

static struct store_driver plain_store = {
	.name = "plain",
	.init = default_init,
	.exist = default_exist,
	.create_and_write = default_create_and_write,
	.write = default_write,
	.read = default_read,
	.link = default_link,
	.end_recover = default_end_recover,
	.cleanup = default_cleanup,
	.format = default_format,
	.remove_object = default_remove_object,
	.purge_obj = default_purge_obj,
};

add_store_driver(plain_store);
