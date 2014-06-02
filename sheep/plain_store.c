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

#include <libgen.h>
#include <linux/falloc.h>

#include "sheep_priv.h"

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif

#define sector_algined(x) ({ ((x) & (SECTOR_SIZE - 1)) == 0; })

static inline bool iocb_is_aligned(const struct siocb *iocb)
{
	return  sector_algined(iocb->offset) && sector_algined(iocb->length);
}

static int prepare_iocb(uint64_t oid, const struct siocb *iocb, bool create)
{
	int flags = O_DSYNC | O_RDWR;

	if (uatomic_is_true(&sys->use_journal) || sys->nosync == true)
		flags &= ~O_DSYNC;

	if (sys->backend_dio && iocb_is_aligned(iocb)) {
		if (!is_aligned_to_pagesize(iocb->buf))
			panic("Memory isn't aligned to pagesize %p", iocb->buf);
		flags |= O_DIRECT;
	}

	if (create)
		flags |= O_CREAT | O_EXCL;

	return flags;
}

int get_store_path(uint64_t oid, uint8_t ec_index, char *path)
{
	if (is_erasure_oid(oid)) {
		if (unlikely(ec_index >= SD_MAX_COPIES))
			panic("invalid ec_index %d", ec_index);
		return snprintf(path, PATH_MAX, "%s/%016"PRIx64"_%d",
				md_get_object_dir(oid), oid, ec_index);
	}

	return snprintf(path, PATH_MAX, "%s/%016" PRIx64,
			md_get_object_dir(oid), oid);
}

static int get_store_tmp_path(uint64_t oid, uint8_t ec_index, char *path)
{
	if (is_erasure_oid(oid)) {
		if (unlikely(ec_index >= SD_MAX_COPIES))
			panic("invalid ec_index %d", ec_index);
		return snprintf(path, PATH_MAX, "%s/%016"PRIx64"_%d.tmp",
				md_get_object_dir(oid), oid, ec_index);
	}

	return snprintf(path, PATH_MAX, "%s/%016" PRIx64".tmp",
			md_get_object_dir(oid), oid);
}

static int get_store_stale_path(uint64_t oid, uint32_t epoch, uint8_t ec_index,
				char *path)
{
	return md_get_stale_path(oid, epoch, ec_index, path);
}

/*
 * Check if oid is in this nodes (if oid is in the wrong place, it will be moved
 * to the correct one after this call in a MD setup.
 */
bool default_exist(uint64_t oid, uint8_t ec_index)
{
	return md_exist(oid, ec_index);
}

static int err_to_sderr(const char *path, uint64_t oid, int err)
{
	struct stat s;
	char p[PATH_MAX], *dir;

	/* Use a temporary buffer since dirname() may modify its argument. */
	pstrcpy(p, sizeof(p), path);
	dir = dirname(p);

	sd_debug("%s", path);
	switch (err) {
	case ENOENT:
		if (stat(dir, &s) < 0) {
			sd_err("%s corrupted", dir);
			return md_handle_eio(dir);
		}
		sd_debug("object %016" PRIx64 " not found locally", oid);
		return SD_RES_NO_OBJ;
	case ENOSPC:
		/* TODO: stop automatic recovery */
		sd_err("diskfull, oid=%"PRIx64, oid);
		return SD_RES_NO_SPACE;
	case EMFILE:
	case ENFILE:
	case EINTR:
	case EAGAIN:
	case EEXIST:
		sd_err("%m, oid=%"PRIx64, oid);
		/* make gateway try again */
		return SD_RES_NETWORK_ERROR;
	default:
		sd_err("oid=%"PRIx64", %m", oid);
		return md_handle_eio(dir);
	}
}

static int discard(int fd, uint64_t start, uint32_t end)
{
	int ret = xfallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
			     start, end - start);
	if (ret < 0) {
		if (errno == ENOSYS || errno == EOPNOTSUPP)
			sd_info("FALLOC_FL_PUNCH_HOLE is not supported "
				"on this filesystem");
		else
			sd_err("failed to discard object, %m");
	}

	return ret;
}

/* Trim zero blocks of the beginning and end of the object. */
static int default_trim(int fd, uint64_t oid, const struct siocb *iocb,
			uint64_t *poffset, uint32_t *plen)
{
	trim_zero_blocks(iocb->buf, poffset, plen);

	if (iocb->offset < *poffset) {
		sd_debug("discard between %d, %ld, %" PRIx64, iocb->offset,
			 *poffset, oid);

		if (discard(fd, iocb->offset, *poffset) < 0)
			return -1;
	}

	if (*poffset + *plen < iocb->offset + iocb->length) {
		uint64_t end = iocb->offset + iocb->length;
		if (end == get_objsize(oid))
			/* This is necessary to punch the last block */
			end = round_up(end, BLOCK_SIZE);
		sd_debug("discard between %ld, %ld, %" PRIx64, *poffset + *plen,
			 end, oid);

		if (discard(fd, *poffset + *plen, end) < 0)
			return -1;
	}

	return 0;
}

int default_write(uint64_t oid, const struct siocb *iocb)
{
	int flags = prepare_iocb(oid, iocb, false), fd,
	    ret = SD_RES_SUCCESS;
	char path[PATH_MAX];
	ssize_t size;
	uint32_t len = iocb->length;
	uint64_t offset = iocb->offset;
	static bool trim_is_supported = true;

	if (iocb->epoch < sys_epoch()) {
		sd_debug("%"PRIu32" sys %"PRIu32, iocb->epoch, sys_epoch());
		return SD_RES_OLD_NODE_VER;
	}

	if (uatomic_is_true(&sys->use_journal) &&
	    unlikely(journal_write_store(oid, iocb->buf, iocb->length,
					 iocb->offset, false))
	    != SD_RES_SUCCESS) {
		sd_err("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_DSYNC;
		sync();
	}

	get_store_path(oid, iocb->ec_index, path);

	/*
	 * Make sure oid is in the right place because oid might be misplaced
	 * in a wrong place, due to 'shutdown/restart with less/more disks' or
	 * any bugs. We need call err_to_sderr() to return EIO if disk is broken
	 */
	if (!default_exist(oid, iocb->ec_index))
		return err_to_sderr(path, oid, ENOENT);

	fd = open(path, flags, sd_def_fmode);
	if (unlikely(fd < 0))
		return err_to_sderr(path, oid, errno);

	if (trim_is_supported && is_sparse_object(oid)) {
		if (default_trim(fd, oid, iocb, &offset, &len) < 0) {
			trim_is_supported = false;
			offset = iocb->offset;
			len = iocb->length;
		}
	}

	size = xpwrite(fd, iocb->buf, len, offset);
	if (unlikely(size != len)) {
		sd_err("failed to write object %"PRIx64", path=%s, offset=%"
		       PRId32", size=%"PRId32", result=%zd, %m", oid, path,
		       iocb->offset, iocb->length, size);
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}
out:
	close(fd);
	return ret;
}

static int make_stale_dir(const char *path)
{
	char p[PATH_MAX];

	snprintf(p, PATH_MAX, "%s/.stale", path);
	if (xmkdir(p, sd_def_dmode) < 0) {
		sd_err("%s failed, %m", p);
		return SD_RES_EIO;
	}
	return SD_RES_SUCCESS;
}

static int purge_dir(const char *path)
{
	if (purge_directory(path) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

static int purge_stale_dir(const char *path)
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

static int init_vdi_state(uint64_t oid, const char *wd, uint32_t epoch)
{
	int ret;
	struct sd_inode *inode = xzalloc(SD_INODE_HEADER_SIZE);
	struct siocb iocb = {
		.epoch = epoch,
		.buf = inode,
		.length = SD_INODE_HEADER_SIZE,
	};

	ret = default_read(oid, &iocb);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode header %" PRIx64 " %" PRId32
		       "wat %s", oid, epoch, wd);
		goto out;
	}

	add_vdi_state(oid_to_vid(oid), inode->nr_copies,
		      vdi_is_snapshot(inode), inode->copy_policy);
	atomic_set_bit(oid_to_vid(oid), sys->vdi_inuse);

	ret = SD_RES_SUCCESS;
out:
	free(inode);
	return ret;
}

static int init_objlist_and_vdi_bitmap(uint64_t oid, const char *wd,
				       uint32_t epoch, uint8_t ec_index,
				       struct vnode_info *vinfo,
				       void *arg)
{
	int ret;
	objlist_cache_insert(oid);

	if (is_vdi_obj(oid)) {
		sd_debug("found the VDI object %" PRIx64" epoch %"PRIu32
			 " at %s", oid, epoch, wd);
		ret = init_vdi_state(oid, wd, epoch);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return SD_RES_SUCCESS;
}

int default_init(void)
{
	int ret;

	sd_debug("use plain store driver");
	ret = for_each_obj_path(make_stale_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	for_each_object_in_stale(init_objlist_and_vdi_bitmap, NULL);

	return for_each_object_in_wd(init_objlist_and_vdi_bitmap, true, NULL);
}

static int default_read_from_path(uint64_t oid, const char *path,
				  const struct siocb *iocb)
{
	int flags = prepare_iocb(oid, iocb, false), fd,
	    ret = SD_RES_SUCCESS;
	ssize_t size;

	/*
	 * Make sure oid is in the right place because oid might be misplaced
	 * in a wrong place, due to 'shutdown/restart with less disks' or any
	 * bugs. We need call err_to_sderr() to return EIO if disk is broken.
	 *
	 * For stale path, get_store_stale_path already does default_exist job.
	 */
	if (!is_stale_path(path) && !default_exist(oid, iocb->ec_index))
		return err_to_sderr(path, oid, ENOENT);

	fd = open(path, flags);
	if (fd < 0)
		return err_to_sderr(path, oid, errno);

	size = xpread(fd, iocb->buf, iocb->length, iocb->offset);
	if (unlikely(size != iocb->length)) {
		sd_err("failed to read object %"PRIx64", path=%s, offset=%"
		       PRId32", size=%"PRId32", result=%zd, %m", oid, path,
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

	get_store_path(oid, iocb->ec_index, path);
	ret = default_read_from_path(oid, path, iocb);

	/*
	 * If the request is againt the older epoch, try to read from
	 * the stale directory
	 */
	if (ret == SD_RES_NO_OBJ && iocb->epoch > 0 &&
	    iocb->epoch < sys_epoch()) {
		get_store_stale_path(oid, iocb->epoch, iocb->ec_index, path);
		ret = default_read_from_path(oid, path, iocb);
	}

	return ret;
}

/* Preallocate the whole object to get a better filesystem layout. */
int prealloc(int fd, uint32_t size)
{
	int ret = xfallocate(fd, 0, 0, size);
	if (ret < 0) {
		if (errno != ENOSYS && errno != EOPNOTSUPP) {
			sd_err("failed to preallocate space, %m");
			return ret;
		}

		return xftruncate(fd, size);
	}

	return 0;
}

size_t get_store_objsize(uint64_t oid)
{
	if (is_erasure_oid(oid)) {
		uint8_t policy = get_vdi_copy_policy(oid_to_vid(oid));
		int d;
		ec_policy_to_dp(policy, &d, NULL);
		return SD_DATA_OBJ_SIZE / d;
	}
	return get_objsize(oid);
}

int default_create_and_write(uint64_t oid, const struct siocb *iocb)
{
	char path[PATH_MAX], tmp_path[PATH_MAX];
	int flags = prepare_iocb(oid, iocb, true);
	int ret, fd;
	uint32_t len = iocb->length;
	size_t obj_size;
	uint64_t offset = iocb->offset;

	sd_debug("%"PRIx64, oid);
	get_store_path(oid, iocb->ec_index, path);
	get_store_tmp_path(oid, iocb->ec_index, tmp_path);

	if (uatomic_is_true(&sys->use_journal) &&
	    journal_write_store(oid, iocb->buf, iocb->length,
				iocb->offset, true)
	    != SD_RES_SUCCESS) {
		sd_err("turn off journaling");
		uatomic_set_false(&sys->use_journal);
		flags |= O_DSYNC;
		sync();
	}

	fd = open(tmp_path, flags, sd_def_fmode);
	if (fd < 0) {
		if (errno == EEXIST) {
			/*
			 * This happens if node membership changes during object
			 * creation; while gateway retries a CREATE request,
			 * recovery process could also recover the object at the
			 * same time.  They should try to write the same date,
			 * so it is okay to simply return success here.
			 */
			sd_debug("%s exists", tmp_path);
			return SD_RES_SUCCESS;
		}

		sd_err("failed to open %s: %m", tmp_path);
		return err_to_sderr(path, oid, errno);
	}

	obj_size = get_store_objsize(oid);

	trim_zero_blocks(iocb->buf, &offset, &len);

	if (offset != 0 || len != get_objsize(oid)) {
		if (is_sparse_object(oid))
			ret = xftruncate(fd, obj_size);
		else
			ret = prealloc(fd, obj_size);
		if (ret < 0) {
			ret = err_to_sderr(path, oid, errno);
			goto out;
		}
	}

	ret = xpwrite(fd, iocb->buf, len, offset);
	if (ret != len) {
		sd_err("failed to write object. %m");
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}

	ret = rename(tmp_path, path);
	if (ret < 0) {
		sd_err("failed to rename %s to %s: %m", tmp_path, path);
		ret = err_to_sderr(path, oid, errno);
		goto out;
	}

	ret = SD_RES_SUCCESS;
	objlist_cache_insert(oid);
out:
	if (ret != SD_RES_SUCCESS)
		unlink(tmp_path);
	close(fd);
	return ret;
}

int default_link(uint64_t oid, uint32_t tgt_epoch)
{
	char path[PATH_MAX], stale_path[PATH_MAX];

	sd_debug("try link %"PRIx64" from snapshot with epoch %d", oid,
		 tgt_epoch);

	snprintf(path, PATH_MAX, "%s/%016"PRIx64, md_get_object_dir(oid), oid);
	get_store_stale_path(oid, tgt_epoch, 0, stale_path);

	if (link(stale_path, path) < 0) {
		/*
		 * Recovery thread and main thread might try to recover the
		 * same object and we might get EEXIST in such case.
		 */
		if (errno == EEXIST)
			goto out;

		sd_debug("failed to link from %s to %s, %m", stale_path, path);
		return err_to_sderr(path, oid, errno);
	}
out:
	return SD_RES_SUCCESS;
}

/*
 * For replicated object, if any of the replica belongs to this node, we
 * consider it not stale.
 *
 * For erasured object, since every copy is unique and if it migrates to other
 * node(index gets changed even it has some other copy belongs to it) because
 * of hash ring changes, we consider it stale.
 */
static bool oid_stale(uint64_t oid, int ec_index, struct vnode_info *vinfo)
{
	uint32_t i, nr_copies;
	const struct sd_vnode *v;
	bool ret = true;
	const struct sd_vnode *obj_vnodes[SD_MAX_COPIES];

	nr_copies = get_obj_copy_number(oid, vinfo->nr_zones);
	oid_to_vnodes(oid, &vinfo->vroot, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			if (ec_index < SD_MAX_COPIES) {
				if (i == ec_index)
					ret = false;
			} else {
				ret = false;
			}
			break;
		}
	}

	return ret;
}

static int move_object_to_stale_dir(uint64_t oid, const char *wd,
				    uint32_t epoch, uint8_t ec_index,
				    struct vnode_info *vinfo, void *arg)
{
	char path[PATH_MAX], stale_path[PATH_MAX];
	uint32_t tgt_epoch = *(uint32_t *)arg;

	/* ec_index from md.c is reliable so we can directly use it */
	if (ec_index < SD_MAX_COPIES) {
		snprintf(path, PATH_MAX, "%s/%016"PRIx64"_%d",
			 md_get_object_dir(oid), oid, ec_index);
		snprintf(stale_path, PATH_MAX,
			 "%s/.stale/%016"PRIx64"_%d.%"PRIu32,
			 md_get_object_dir(oid), oid, ec_index, tgt_epoch);
	} else {
		snprintf(path, PATH_MAX, "%s/%016" PRIx64,
			 md_get_object_dir(oid), oid);
		snprintf(stale_path, PATH_MAX, "%s/.stale/%016"PRIx64".%"PRIu32,
			 md_get_object_dir(oid), oid, tgt_epoch);
	}

	if (unlikely(rename(path, stale_path)) < 0) {
		sd_err("failed to move stale object %" PRIX64 " to %s, %m", oid,
		       path);
		return SD_RES_EIO;
	}

	sd_debug("moved object %"PRIx64, oid);
	return SD_RES_SUCCESS;
}

static int check_stale_objects(uint64_t oid, const char *wd, uint32_t epoch,
			       uint8_t ec_index, struct vnode_info *vinfo,
			       void *arg)
{
	if (oid_stale(oid, ec_index, vinfo))
		return move_object_to_stale_dir(oid, wd, 0, ec_index,
						NULL, arg);

	return SD_RES_SUCCESS;
}

int default_update_epoch(uint32_t epoch)
{
	assert(epoch);
	return for_each_object_in_wd(check_stale_objects, false, &epoch);
}

int default_format(void)
{
	unsigned ret;

	sd_debug("try get a clean store");
	ret = for_each_obj_path(purge_dir);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (sys->enable_object_cache)
		object_cache_format();

	return SD_RES_SUCCESS;
}

int default_remove_object(uint64_t oid, uint8_t ec_index)
{
	char path[PATH_MAX];

	if (uatomic_is_true(&sys->use_journal))
		journal_remove_object(oid);

	get_store_path(oid, ec_index, path);

	if (unlink(path) < 0) {
		if (errno == ENOENT)
			return SD_RES_NO_OBJ;

		sd_err("failed, %s, %m", path);
		return SD_RES_EIO;
	}

	return SD_RES_SUCCESS;
}

#define SHA1NAME "user.obj.sha1"

static int get_object_sha1(const char *path, uint8_t *sha1)
{
	if (getxattr(path, SHA1NAME, sha1, SHA1_DIGEST_SIZE)
	    != SHA1_DIGEST_SIZE) {
		if (errno == ENODATA)
			sd_debug("sha1 is not cached yet, %s", path);
		else
			sd_err("fail to get xattr, %s", path);
		return -1;
	}

	return 0;
}

static int set_object_sha1(const char *path, const uint8_t *sha1)
{
	int ret;

	ret = setxattr(path, SHA1NAME, sha1, SHA1_DIGEST_SIZE, 0);
	if (ret < 0)
		sd_err("fail to set sha1, %s", path);

	return ret;
}

static int get_object_path(uint64_t oid, uint32_t epoch, char *path,
			   size_t size)
{
	if (default_exist(oid, 0)) {
		snprintf(path, PATH_MAX, "%s/%016"PRIx64,
			 md_get_object_dir(oid), oid);
	} else {
		get_store_stale_path(oid, epoch, 0, path);
		if (access(path, F_OK) < 0) {
			if (errno == ENOENT)
				return SD_RES_NO_OBJ;
			return SD_RES_EIO;
		}

	}

	return SD_RES_SUCCESS;
}

int default_get_hash(uint64_t oid, uint32_t epoch, uint8_t *sha1)
{
	int ret;
	void *buf;
	struct siocb iocb = {};
	uint32_t length;
	bool is_readonly_obj = oid_is_readonly(oid);
	char path[PATH_MAX];

	ret = get_object_path(oid, epoch, path, sizeof(path));
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (is_readonly_obj) {
		if (get_object_sha1(path, sha1) == 0) {
			sd_debug("use cached sha1 digest %s",
				 sha1_to_hex(sha1));
			return SD_RES_SUCCESS;
		}
	}

	length = get_store_objsize(oid);
	buf = valloc(length);
	if (buf == NULL)
		return SD_RES_NO_MEM;

	iocb.epoch = epoch;
	iocb.buf = buf;
	iocb.length = length;

	ret = default_read_from_path(oid, path, &iocb);
	if (ret != SD_RES_SUCCESS) {
		free(buf);
		return ret;
	}

	get_buffer_sha1(buf, length, sha1);
	free(buf);

	sd_debug("the message digest of %"PRIx64" at epoch %d is %s", oid,
		 epoch, sha1_to_hex(sha1));

	if (is_readonly_obj)
		set_object_sha1(path, sha1);

	return ret;
}

int default_purge_obj(void)
{
	uint32_t tgt_epoch = get_latest_epoch();

	return for_each_object_in_wd(move_object_to_stale_dir, true,
				     &tgt_epoch);
}

static struct store_driver plain_store = {
	.name = "plain",
	.init = default_init,
	.exist = default_exist,
	.create_and_write = default_create_and_write,
	.write = default_write,
	.read = default_read,
	.link = default_link,
	.update_epoch = default_update_epoch,
	.cleanup = default_cleanup,
	.format = default_format,
	.remove_object = default_remove_object,
	.get_hash = default_get_hash,
	.purge_obj = default_purge_obj,
};

add_store_driver(plain_store);
