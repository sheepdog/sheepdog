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
#include <assert.h>
#include <syslog.h>

#include "sheep.h"
#include "strbuf.h"
#include "sheepfs.h"
#include "net.h"
#include "rbtree.h"

#define PATH_VOLUME	"/volume"

#define SH_VID_NAME   "user.volume.vid"
#define SH_VID_SIZE   sizeof(uint32_t)

#define SH_SIZE_NAME   "user.volume.size"
#define SH_SIZE_SIZE   sizeof(size_t)

#define VOLUME_READ   0
#define VOLUME_WRITE  1

struct vdi_inode {
	struct rb_node rb;
	uint32_t vid;
	struct sheepdog_inode *inode;
};

static struct rb_root vdi_inode_tree = RB_ROOT;

static struct vdi_inode *vdi_inode_tree_insert(struct vdi_inode *new)
{
	struct rb_node **p = &vdi_inode_tree.rb_node;
	struct rb_node *parent = NULL;
	struct vdi_inode *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct vdi_inode, rb);

		if (new->vid < entry->vid)
			p = &(*p)->rb_left;
		else if (new->vid > entry->vid)
			p = &(*p)->rb_right;
		else
			return entry; /* already has this entry */
	}
	rb_link_node(&new->rb, parent, p);
	rb_insert_color(&new->rb, &vdi_inode_tree);

	return NULL; /* insert successfully */
}

static struct vdi_inode *vdi_inode_tree_search(uint32_t vid)
{
	struct rb_node *n = vdi_inode_tree.rb_node;
	struct vdi_inode *t;

	while (n) {
		t = rb_entry(n, struct vdi_inode, rb);

		if (vid < t->vid)
			n = n->rb_left;
		else if (vid > t->vid)
			n = n->rb_right;
		else
			return t; /* found it */
	}

	return NULL;
}

int create_volume_layout(void)
{
	if (shadow_dir_create(PATH_VOLUME) < 0)
		return -1;
	return 0;
}

static int volume_rw_object(char *buf, uint64_t oid, size_t size,
			    off_t off, int rw)
{
	struct sd_req hdr = { 0 };
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;
	unsigned wlen = 0, rlen = 0;
	int create = 0;
	uint32_t vid = oid_to_vid(oid);
	struct vdi_inode *vdi = vdi_inode_tree_search(vid);
	unsigned long idx = 0;

	if (is_data_obj(oid)) {
		if (off % SECTOR_SIZE || size % SECTOR_SIZE) {
			syslog(LOG_ERR, "offset or size not aligned\n");
			return -1;
		}

		idx = data_oid_to_idx(oid);
		assert(vdi);
		if (!vdi->inode->data_vdi_id[idx]) {
			/* if object doesn't exist, we'er done */
			if (rw == VOLUME_READ) {
				memset(buf, 0, size);
				goto done;
			}
			create = 1;
		}
	}

	if (rw == VOLUME_READ) {
		rlen = size;
		hdr.opcode = SD_OP_READ_OBJ;
	} else {
		wlen = size;
		hdr.opcode = create ?
			SD_OP_CREATE_AND_WRITE_OBJ : SD_OP_WRITE_OBJ;
		hdr.flags |= SD_FLAG_CMD_WRITE;
	}

	hdr.obj.oid = oid;
	hdr.obj.offset = off;
	hdr.data_length = size;
	hdr.flags |= SD_FLAG_CMD_CACHE;

	ret = exec_req(0, &hdr, buf, &wlen, &rlen);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		syslog(LOG_ERR, "failed to %s object %" PRIx64 " ret %d, res %d\n",
			rw == VOLUME_READ ? "read" : "write", oid, ret,
			rsp->result);
		return -1;
	}

	if (create) {
		vdi->inode->data_vdi_id[idx] = vid;
		/* writeback inode update */
		if (volume_rw_object((char *)&vid, vid_to_vdi_oid(vid),
				     sizeof(vid),
				     SD_INODE_HEADER_SIZE + sizeof(vid) * idx,
				     VOLUME_WRITE) < 0)
			return -1;
	}
done:
	return size;
}

/* Do sync read/write */
static int volume_do_rw(const char *path, char *buf, size_t size,
			 off_t offset, int rw)
{
	uint32_t vid;
	uint64_t oid;
	unsigned long idx;
	off_t start;
	size_t len, ret;

	if (shadow_file_getxattr(path, SH_VID_NAME, &vid, SH_VID_SIZE) < 0)
		return -1;

	idx = offset / SD_DATA_OBJ_SIZE;
	oid = vid_to_data_oid(vid, idx);
	start = offset % SD_DATA_OBJ_SIZE;

	len = SD_DATA_OBJ_SIZE - start;
	if (size < len)
		len = size;

	do {
		syslog(LOG_ERR, "%s oid %"PRIx64", off %ju, len %zu,"
			" size %zu\n",
			rw == VOLUME_READ ? "read" : "write",
			oid, start, len, size);
		ret = volume_rw_object(buf, oid, len, start, rw);

		if (ret != len)
			return -1;

		oid++;
		size -= len;
		start = (start + len) % SD_DATA_OBJ_SIZE;
		buf += len;
		len = size > SD_DATA_OBJ_SIZE ? SD_DATA_OBJ_SIZE : size;
	} while (size > 0);

	return 0;
}

int volume_read(const char *path, char *buf, size_t size, off_t offset)
{

	if (volume_do_rw(path, buf, size, offset, VOLUME_READ) < 0)
		return -EIO;

	return size;
}

int volume_write(const char *path, const char *buf, size_t size, off_t offset)
{
	if (volume_do_rw(path, (char *)buf, size, offset, VOLUME_WRITE) < 0)
		return -EIO;

	return size;
}

size_t volume_get_size(const char *path)
{
	size_t size = 0;

	shadow_file_getxattr(path, SH_SIZE_NAME, &size, SH_SIZE_SIZE);
	return size;
}

static int volume_do_sync(uint32_t vid)
{
	struct sd_obj_req hdr = { 0 };
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	int ret;
	unsigned wlen = 0, rlen = 0;

	hdr.opcode = SD_OP_FLUSH_VDI;
	hdr.oid = vid_to_vdi_oid(vid);

	ret = exec_req(0, (struct sd_req *)&hdr, NULL, &wlen, &rlen);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		syslog(LOG_ERR, "[%s] failed to flush vdi %"PRIx32"\n",
			__func__, vid);
		return -1;
	}

	return 0;
}

int volume_sync(const char *path)
{
	uint32_t vid;

	if (shadow_file_getxattr(path, SH_VID_NAME, &vid, SH_VID_SIZE) < 0)
		return -EIO;

	if (volume_do_sync(vid) < 0)
		return -EIO;

	return 0;
}

int volume_open(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static int init_vdi_info(const char *entry, uint32_t *vid, size_t *size)
{
	struct strbuf *buf;
	void *inode_buf;
	struct vdi_inode *inode;
	char command[256] = { 0 };
	int ret = -1;

	sprintf(command, "%s %s\n", "collie vdi list -r", entry);
	buf = sheepfs_run_cmd(command);
	if (!buf)
		return -1;
	if (sscanf(buf->buf, "%*s %*s %*d %zu %*s %*s %*s %"PRIx32,
	    size, vid) < 2) {
		syslog(LOG_ERR, "[%s] failed to sscanf %s\n", __func__, entry);
		goto out;
	}

	inode_buf = malloc(SD_INODE_SIZE);
	if (!inode_buf) {
		syslog(LOG_ERR, "[%s] %m\n", __func__);
		goto out;
	}

	if (volume_rw_object(inode_buf, vid_to_vdi_oid(*vid), SD_INODE_SIZE,
			     0, VOLUME_READ) < 0) {
		free(inode_buf);
		goto out;
	}

	inode = xzalloc(sizeof(*inode));
	inode->vid = *vid;
	inode->inode = inode_buf;
	if (vdi_inode_tree_insert(inode)) {
		free(inode_buf);
		free(inode);
	}
	ret = 0;
out:
	strbuf_release(buf);
	return ret;
}

int volume_create_entry(const char *entry)
{
	char path[PATH_MAX], *ch;
	uint32_t vid;
	size_t size;

	ch = strchr(entry, '\n');
	if (ch != NULL)
		*ch = '\0';

	sprintf(path, "%s/%s", PATH_VOLUME, entry);
	if (shadow_file_exsit(path))
		return 0;

	if (init_vdi_info(entry, &vid, &size) < 0)
		return -1;

	if (shadow_file_create(path) < 0)
		return -1;

	if (shadow_file_setxattr(path, SH_VID_NAME, &vid, SH_VID_SIZE) < 0) {
		shadow_file_delete(path);
		return -1;
	}
	if (shadow_file_setxattr(path, SH_SIZE_NAME, &size, SH_SIZE_SIZE) < 0) {
		shadow_file_delete(path);
		return -1;
	}
	if (sheepfs_set_op(path, OP_VOLUME) < 0)
		return -1;

	return 0;
}

static int volume_sync_and_delete(uint32_t vid)
{
	struct sd_obj_req hdr = { 0 };
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	int ret;
	unsigned wlen = 0, rlen = 0;

	hdr.opcode = SD_OP_FLUSH_DEL_CACHE;
	hdr.oid = vid_to_vdi_oid(vid);

	ret = exec_req(0, (struct sd_req *)&hdr, NULL, &wlen, &rlen);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		syslog(LOG_ERR, "[%s] failed to flush vdi %" PRIx32 "\n",
			__func__, vid);
		return -1;
	}

	return 0;
}

int volume_remove_entry(const char *entry)
{
	char path[PATH_MAX], *ch;
	uint32_t vid;

	ch = strchr(entry, '\n');
	if (ch != NULL)
		*ch = '\0';

	sprintf(path, "%s/%s", PATH_VOLUME, entry);
	if (!shadow_file_exsit(path))
		return -1;

	if (shadow_file_getxattr(path, SH_VID_NAME, &vid, SH_VID_SIZE) < 0)
		return -1;

	if (volume_sync_and_delete(vid) < 0)
		return -1;

	shadow_file_delete(path);

	return 0;
}
