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
#include <urcu/uatomic.h>
#include <pthread.h>

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

/* #define DEBUG */

struct vdi_inode {
	struct rb_node rb;
	uint32_t vid;
	struct sheepdog_inode *inode;
/* FIXME
 * 1) Consider various VM request queue depth.
 * 2) Most drive presents 31 to Linux, I set it as 31 to expect that VM's
 *    real queue depth never exceed 31
 */
#define SOCKET_POOL_SIZE  31
/* Socket pool is used for FUSE read threads, which use threads
 * to simulate aysnc read. All sockets point to the same gateway
 */
	int socket_pool[SOCKET_POOL_SIZE];
	char socket_in_use[SOCKET_POOL_SIZE]; /* 1 means in use */
	unsigned socket_poll_adder;
};

static struct rb_root vdi_inode_tree = RB_ROOT;
static pthread_rwlock_t vdi_inode_tree_lock = PTHREAD_RWLOCK_INITIALIZER;

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

/* We must use get/put_socket_fd in pair */
static inline int get_socket_fd(struct vdi_inode *vdi, int *idx)
{
	int sock_idx, fd;

retry:
	sock_idx = uatomic_add_return(&vdi->socket_poll_adder, 1) %
		   SOCKET_POOL_SIZE;
	/* if socket_in_use[sock_idx] == 0, set it to 1, otherwise, retry */
	if (uatomic_cmpxchg(&vdi->socket_in_use[sock_idx], 0, 1))
		goto retry;
	fd = vdi->socket_pool[sock_idx];
	*idx = sock_idx;

	return fd;
}

static inline void put_socket_fd(struct vdi_inode *vdi, int idx)
{
	uatomic_dec(&vdi->socket_in_use[idx]);
}

static int volume_rw_object(char *buf, uint64_t oid, size_t size,
			    off_t off, int rw)
{
	struct sd_req hdr = { 0 };
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret, fd, sock_idx;
	unsigned wlen = 0, rlen = 0;
	int create = 0;
	uint32_t vid = oid_to_vid(oid);
	struct vdi_inode *vdi;
	unsigned long idx = 0;
	uint64_t cow_oid = 0;

	pthread_rwlock_rdlock(&vdi_inode_tree_lock);
	vdi = vdi_inode_tree_search(vid);
	pthread_rwlock_unlock(&vdi_inode_tree_lock);

	if (is_data_obj(oid)) {
		if (off % SECTOR_SIZE || size % SECTOR_SIZE) {
			sheepfs_pr("offset or size not aligned\n");
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
		} else {
			if (rw == VOLUME_READ) {
				oid = vid_to_data_oid(
					vdi->inode->data_vdi_id[idx],
					idx);
			/* in case we are writing a COW object */
			} else if (!is_data_obj_writeable(vdi->inode, idx)) {
				cow_oid = vid_to_data_oid(
						vdi->inode->data_vdi_id[idx],
						idx);
				hdr.flags |= SD_FLAG_CMD_COW;
				create = 1;
			}
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
	hdr.obj.cow_oid = cow_oid;
	hdr.data_length = size;
	if (sheepfs_object_cache)
		hdr.flags |= SD_FLAG_CMD_CACHE;

	fd = get_socket_fd(vdi, &sock_idx);
	ret = exec_req(fd, &hdr, buf, &wlen, &rlen);
	put_socket_fd(vdi, sock_idx);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		sheepfs_pr(
			"[%s] failed to %s object %" PRIx64 " ret %d, res %u\n",
			__func__, rw == VOLUME_READ ? "read" : "write",
			oid, ret, rsp->result);
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
#ifdef DEBUG
		sheepfs_pr("%s oid %"PRIx64", off %ju, len %zu,"
			   " size %zu\n",
			   rw == VOLUME_READ ? "read" : "write",
			   oid, start, len, size);
#endif
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
	struct sd_req hdr = { 0 };
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret, fd, idx;
	unsigned wlen = 0, rlen = 0;
	struct vdi_inode *vdi;

	pthread_rwlock_rdlock(&vdi_inode_tree_lock);
	vdi = vdi_inode_tree_search(vid);
	pthread_rwlock_unlock(&vdi_inode_tree_lock);

	hdr.opcode = SD_OP_FLUSH_VDI;
	hdr.obj.oid = vid_to_vdi_oid(vid);

	fd = get_socket_fd(vdi, &idx);
	ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
	put_socket_fd(vdi, idx);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		sheepfs_pr("failed to flush vdi %"PRIx32"\n", vid);
		return -1;
	}

	return 0;
}

int volume_sync(const char *path)
{
	uint32_t vid;

	if (shadow_file_getxattr(path, SH_VID_NAME, &vid, SH_VID_SIZE) < 0)
		return -EIO;

	if (sheepfs_object_cache && volume_do_sync(vid) < 0)
		return -EIO;

	return 0;
}

int volume_open(const char *path, struct fuse_file_info *fi)
{
	if (!sheepfs_page_cache)
		fi->direct_io = 1;
	return 0;
}

static void destroy_socket_pool(int array[], int len)
{
	int i;
	for (i = 0; i < len; i++)
		close(array[i]);
}

static int setup_socket_pool(int array[], int len)
{
	int fd, i, ret;

	for (i = 0; i < len; i++) {
		fd = connect_to(sdhost, sdport);
		if (fd < 0) {
			sheepfs_pr("connect_to %m\n");
			destroy_socket_pool(array, --i);
			return -1;
		}

		ret = set_nodelay(fd);
		if (ret) {
			sheepfs_pr("%m\n");
			destroy_socket_pool(array, i);
			return -1;
		}

		array[i] = fd;
	}

	return 0;
}

int reset_socket_pool(void)
{
	struct rb_node *node;
	struct vdi_inode *vdi;
	int ret = 0;

	pthread_rwlock_rdlock(&vdi_inode_tree_lock);
	for (node = rb_first(&vdi_inode_tree); node; node = rb_next(node)) {
		vdi = rb_entry(node, struct vdi_inode, rb);
		destroy_socket_pool(vdi->socket_pool, SOCKET_POOL_SIZE);
		if (setup_socket_pool(vdi->socket_pool,
			SOCKET_POOL_SIZE) < 0) {
			ret = -1;
			goto out;
		}
	}
out:
	pthread_rwlock_unlock(&vdi_inode_tree_lock);
	return ret;
}

static int init_vdi_info(const char *entry, uint32_t *vid, size_t *size)
{
	struct strbuf *buf;
	void *inode_buf = NULL;
	struct vdi_inode *inode = NULL, *dummy;
	char command[COMMAND_LEN];

	sprintf(command, "collie vdi list -r %s -a %s -p %d",
		entry, sdhost, sdport);
	buf = sheepfs_run_cmd(command);
	if (!buf)
		return -1;
	if (sscanf(buf->buf, "%*s %*s %*d %zu %*s %*s %*s %"PRIx32,
	    size, vid) < 2) {
		sheepfs_pr("failed to sscanf %s\n", entry);
		goto err;
	}

	inode_buf = malloc(SD_INODE_SIZE);
	if (!inode_buf) {
		sheepfs_pr("%m\n");
		goto err;
	}

	inode = xzalloc(sizeof(*inode));
	inode->vid = *vid;
	if (setup_socket_pool(inode->socket_pool, SOCKET_POOL_SIZE) < 0) {
		sheepfs_pr("failed to setup socket pool\n");
		goto err;
	}
	/* we need insert inode before calling volume_rw_object */
	pthread_rwlock_wrlock(&vdi_inode_tree_lock);
	dummy = vdi_inode_tree_insert(inode);
	pthread_rwlock_unlock(&vdi_inode_tree_lock);
	if (dummy)
		goto err;
	if (volume_rw_object(inode_buf, vid_to_vdi_oid(*vid), SD_INODE_SIZE,
			     0, VOLUME_READ) < 0) {
		rb_erase(&inode->rb, &vdi_inode_tree);
		sheepfs_pr("failed to read inode for %"PRIx32"\n", *vid);
		goto err;
	}
	inode->inode = inode_buf;
	strbuf_release(buf);
	free(buf);
	return 0;
err:
	free(inode_buf);
	free(inode);
	strbuf_release(buf);
	free(buf);
	return -1;
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
	struct sd_req hdr = { 0 };
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret, fd, idx;
	unsigned wlen = 0, rlen = 0;
	struct vdi_inode *vdi;

	pthread_rwlock_rdlock(&vdi_inode_tree_lock);
	vdi = vdi_inode_tree_search(vid);
	pthread_rwlock_unlock(&vdi_inode_tree_lock);

	hdr.opcode = SD_OP_FLUSH_DEL_CACHE;
	hdr.obj.oid = vid_to_vdi_oid(vid);

	fd = get_socket_fd(vdi, &idx);
	ret = exec_req(fd, &hdr, NULL, &wlen, &rlen);
	put_socket_fd(vdi, idx);

	if (ret || rsp->result != SD_RES_SUCCESS) {
		sheepfs_pr("failed to flush vdi %" PRIx32 "\n", vid);
		return -1;
	}

	return 0;
}

int volume_remove_entry(const char *entry)
{
	char path[PATH_MAX], *ch;
	uint32_t vid;
	struct vdi_inode *vdi;

	ch = strchr(entry, '\n');
	if (ch != NULL)
		*ch = '\0';

	sprintf(path, "%s/%s", PATH_VOLUME, entry);
	if (!shadow_file_exsit(path))
		return -1;

	if (shadow_file_getxattr(path, SH_VID_NAME, &vid, SH_VID_SIZE) < 0)
		return -1;

	if (sheepfs_object_cache && volume_sync_and_delete(vid) < 0)
		return -1;

	pthread_rwlock_rdlock(&vdi_inode_tree_lock);
	vdi = vdi_inode_tree_search(vid);
	pthread_rwlock_unlock(&vdi_inode_tree_lock);
	destroy_socket_pool(vdi->socket_pool, SOCKET_POOL_SIZE);

	pthread_rwlock_wrlock(&vdi_inode_tree_lock);
	rb_erase(&vdi->rb, &vdi_inode_tree);
	pthread_rwlock_unlock(&vdi_inode_tree_lock);

	free(vdi->inode);
	free(vdi);
	shadow_file_delete(path);

	return 0;
}
