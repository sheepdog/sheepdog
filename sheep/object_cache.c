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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/file.h>
#include <dirent.h>

#include "sheep_priv.h"
#include "util.h"
#include "strbuf.h"
#include "rbtree.h"

/*
 * Object Cache ID
 *
 *  0 - 19 (20 bits): data object space
 *  20 - 27 (8 bits): reserved
 *  28 - 31 (4 bits): object type indentifier space
 */
#define CACHE_VDI_SHIFT       31
#define CACHE_VDI_BIT         (UINT32_C(1) << CACHE_VDI_SHIFT)
#define CACHE_BLOCK_SIZE      ((UINT64_C(1) << 10) * 64) /* 64 KB */

struct object_cache {
	uint32_t vid;
	struct hlist_node hash;

	struct list_head dirty_lists[2];
	struct list_head *active_dirty_list;

	struct rb_root dirty_trees[2];
	struct rb_root *active_dirty_tree;

	pthread_mutex_t lock;
};

struct object_cache_entry {
	uint32_t idx;
	uint64_t bmap; /* each bit represents one dirty
			* block which should be flushed */
	struct rb_node rb;
	struct list_head list;
	int create;
};

struct flush_work {
	struct object_cache *cache;
	struct vnode_info *vnode_info;
	struct work work;
};

static char cache_dir[PATH_MAX];
static int def_open_flags = O_RDWR;

#define HASH_BITS	5
#define HASH_SIZE	(1 << HASH_BITS)

static pthread_mutex_t hashtable_lock[HASH_SIZE] = { [0 ... HASH_SIZE - 1] = PTHREAD_MUTEX_INITIALIZER };
static struct hlist_head cache_hashtable[HASH_SIZE];

static inline int hash(uint64_t vid)
{
	return hash_64(vid, HASH_BITS);
}

static uint64_t calc_object_bmap(size_t len, off_t offset)
{
	int start, end, nr;
	uint64_t bmap = 0;

	start = offset / CACHE_BLOCK_SIZE;
	end = (offset + len - 1) / CACHE_BLOCK_SIZE;

	nr = end - start + 1;
	while (nr--)
		set_bit(start + nr, &bmap);

	return bmap;
}

static struct object_cache_entry *dirty_tree_insert(struct rb_root *root,
		struct object_cache_entry *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct object_cache_entry *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct object_cache_entry, rb);

		if (new->idx < entry->idx)
			p = &(*p)->rb_left;
		else if (new->idx > entry->idx)
			p = &(*p)->rb_right;
		else {
			/* already has this entry, merge bmap */
			entry->bmap |= new->bmap;
			return entry;
		}
	}
	rb_link_node(&new->rb, parent, p);
	rb_insert_color(&new->rb, root);

	return NULL; /* insert successfully */
}

__attribute__ ((unused))
static struct object_cache_entry *dirty_tree_search(struct rb_root *root,
		struct object_cache_entry *entry)
{
	struct rb_node *n = root->rb_node;
	struct object_cache_entry *t;

	while (n) {
		t = rb_entry(n, struct object_cache_entry, rb);

		if (entry->idx < t->idx)
			n = n->rb_left;
		else if (entry->idx > t->idx)
			n = n->rb_right;
		else
			return t; /* found it */
	}

	return NULL;
}

static int create_dir_for(uint32_t vid)
{
	int ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, cache_dir);
	strbuf_addf(&buf, "/%06"PRIx32, vid);
	if (mkdir(buf.buf, def_dmode) < 0)
		if (errno != EEXIST) {
			eprintf("%m\n");
			ret = -1;
			goto err;
		}
err:
	strbuf_release(&buf);
	return ret;
}

static struct object_cache *find_object_cache(uint32_t vid, int create)
{
	int h = hash(vid);
	struct hlist_head *head = cache_hashtable + h;
	struct object_cache *cache = NULL;
	struct hlist_node *node;

	pthread_mutex_lock(&hashtable_lock[h]);
	if (hlist_empty(head))
		goto not_found;

	hlist_for_each_entry(cache, node, head, hash) {
		if (cache->vid == vid)
			goto out;
	}
not_found:
	if (create) {
		cache = xzalloc(sizeof(*cache));
		cache->vid = vid;
		create_dir_for(vid);

		cache->dirty_trees[0] = RB_ROOT;
		cache->dirty_trees[1] = RB_ROOT;
		cache->active_dirty_tree = &cache->dirty_trees[0];

		INIT_LIST_HEAD(&cache->dirty_lists[0]);
		INIT_LIST_HEAD(&cache->dirty_lists[1]);
		cache->active_dirty_list = &cache->dirty_lists[0];

		pthread_mutex_init(&cache->lock, NULL);
		hlist_add_head(&cache->hash, head);
	} else
		cache = NULL;
out:
	pthread_mutex_unlock(&hashtable_lock[h]);
	return cache;
}

static void add_to_dirty_tree_and_list(struct object_cache *oc, uint32_t idx,
		uint64_t bmap, struct object_cache_entry *entry, int create)
{
	if (!entry) {
		entry = xzalloc(sizeof(*entry));
		entry->idx = idx;
		entry->bmap = bmap;
		entry->create = create;
	}
	if (!dirty_tree_insert(oc->active_dirty_tree, entry))
		list_add(&entry->list, oc->active_dirty_list);
	else
		free(entry);
}

static inline void del_from_dirty_tree_and_list(
		struct object_cache_entry *entry,
		struct rb_root *dirty_tree)
{
	rb_erase(&entry->rb, dirty_tree);
	list_del(&entry->list);
}

static void switch_dirty_tree_and_list(struct object_cache *oc,
		struct rb_root ** inactive_dirty_tree,
		struct list_head **inactive_dirty_list)
{
	pthread_mutex_lock(&oc->lock);

	*inactive_dirty_list = oc->active_dirty_list;
	*inactive_dirty_tree = oc->active_dirty_tree;

	if (oc->active_dirty_tree == &oc->dirty_trees[0]) {
		oc->active_dirty_list = &oc->dirty_lists[1];
		oc->active_dirty_tree = &oc->dirty_trees[1];
	} else {
		oc->active_dirty_list = &oc->dirty_lists[0];
		oc->active_dirty_tree = &oc->dirty_trees[0];
	}

	pthread_mutex_unlock(&oc->lock);
}

static void merge_dirty_tree_and_list(struct object_cache *oc,
		struct rb_root *inactive_dirty_tree,
		struct list_head *inactive_dirty_list)
{
	struct object_cache_entry *entry, *t;

	pthread_mutex_lock(&oc->lock);

	list_for_each_entry_safe(entry, t, inactive_dirty_list, list) {
		del_from_dirty_tree_and_list(entry, inactive_dirty_tree);
		add_to_dirty_tree_and_list(oc, entry->idx, 0, entry, 0);
	}

	pthread_mutex_unlock(&oc->lock);
}

static int object_cache_lookup(struct object_cache *oc, uint32_t idx,
		int create)
{
	struct strbuf buf;
	int fd, ret = 0, flags = def_open_flags;

	strbuf_init(&buf, PATH_MAX);
	strbuf_addstr(&buf, cache_dir);
	strbuf_addf(&buf, "/%06"PRIx32"/%08"PRIx32, oc->vid, idx);

	if (create)
		flags |= O_CREAT | O_TRUNC;

	fd = open(buf.buf, flags, def_fmode);
	if (fd < 0) {
		ret = -1;
		goto out;
	}

	if (create) {
		unsigned data_length;
		if (idx & CACHE_VDI_BIT)
			data_length = SD_INODE_SIZE;
		else
			data_length = SD_DATA_OBJ_SIZE;

		ret = prealloc(fd, data_length);
		if (ret != SD_RES_SUCCESS)
			ret = -1;
		else {
			pthread_mutex_lock(&oc->lock);
			add_to_dirty_tree_and_list(oc, idx, 0, NULL, 1);
			pthread_mutex_unlock(&oc->lock);
		}
	}
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int write_cache_object(uint32_t vid, uint32_t idx, void *buf, size_t count, off_t offset)
{
	size_t size;
	int fd, flags = def_open_flags, ret = SD_RES_SUCCESS;
	struct strbuf p;

	strbuf_init(&p, PATH_MAX);
	strbuf_addstr(&p, cache_dir);
	strbuf_addf(&p, "/%06"PRIx32"/%08"PRIx32, vid, idx);

	if (sys->use_directio && !(idx & CACHE_VDI_BIT))
		flags |= O_DIRECT;

	fd = open(p.buf, flags, def_fmode);
	if (fd < 0) {
		eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	if (flock(fd, LOCK_EX) < 0) {
		ret = SD_RES_EIO;
		eprintf("%m\n");
		goto out_close;
	}
	size = xpwrite(fd, buf, count, offset);
	if (flock(fd, LOCK_UN) < 0) {
		ret = SD_RES_EIO;
		eprintf("%m\n");
		goto out_close;
	}

	if (size != count) {
		eprintf("size %zu, count:%zu, offset %zu %m\n",
			size, count, offset);
		ret = SD_RES_EIO;
	}
out_close:
	close(fd);
out:
	strbuf_release(&p);
	return ret;
}

static int read_cache_object(uint32_t vid, uint32_t idx, void *buf, size_t count, off_t offset)
{
	size_t size;
	int fd, flags = def_open_flags, ret = SD_RES_SUCCESS;
	struct strbuf p;

	strbuf_init(&p, PATH_MAX);
	strbuf_addstr(&p, cache_dir);
	strbuf_addf(&p, "/%06"PRIx32"/%08"PRIx32, vid, idx);

	if (sys->use_directio && !(idx & CACHE_VDI_BIT))
		flags |= O_DIRECT;

	fd = open(p.buf, flags, def_fmode);
	if (fd < 0) {
		eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	if (flock(fd, LOCK_SH) < 0) {
		ret = SD_RES_EIO;
		eprintf("%m\n");
		goto out_close;
	}
	size = xpread(fd, buf, count, offset);
	if (flock(fd, LOCK_UN) < 0) {
		ret = SD_RES_EIO;
		eprintf("%m\n");
		goto out_close;
	}

	if (size != count) {
		eprintf("size %zu, count:%zu, offset %zu %m\n",
			size, count, offset);
		ret = SD_RES_EIO;
	}

out_close:
	close(fd);
out:
	strbuf_release(&p);
	return ret;
}

static int object_cache_rw(struct object_cache *oc, uint32_t idx,
		struct request *req)
{
	struct sd_req *hdr = &req->rq;
	uint64_t bmap = 0;
	int ret;

	dprintf("%08"PRIx32", len %"PRIu32", off %"PRIu64"\n", idx,
		hdr->data_length, hdr->obj.offset);

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		ret = write_cache_object(oc->vid, idx, req->data,
					 hdr->data_length, hdr->obj.offset);
		if (ret != SD_RES_SUCCESS)
			goto out;
		bmap = calc_object_bmap(hdr->data_length, hdr->obj.offset);
		pthread_mutex_lock(&oc->lock);
		add_to_dirty_tree_and_list(oc, idx, bmap, NULL, 0);
		pthread_mutex_unlock(&oc->lock);
	} else {
		ret = read_cache_object(oc->vid, idx, req->data,
					hdr->data_length, hdr->obj.offset);
		if (ret != SD_RES_SUCCESS)
			goto out;
		req->rp.data_length = hdr->data_length;
	}
out:
	return ret;
}

static int create_cache_object(struct object_cache *oc, uint32_t idx, void *buffer,
		size_t buf_size)
{
	int flags = def_open_flags | O_CREAT | O_EXCL, fd, ret = SD_RES_SUCCESS;
	struct strbuf buf;

	strbuf_init(&buf, PATH_MAX);
	strbuf_addstr(&buf, cache_dir);
	strbuf_addf(&buf, "/%06"PRIx32"/%08"PRIx32, oc->vid, idx);

	fd = open(buf.buf, flags, def_fmode);
	if (fd < 0) {
		if (errno == EEXIST) {
			dprintf("%08"PRIx32" already created\n", idx);
			goto out;
		}
		dprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	if (flock(fd, LOCK_EX) < 0) {
		ret = SD_RES_EIO;
		eprintf("%m\n");
		goto out_close;
	}
	ret = xpwrite(fd, buffer, buf_size, 0);
	if (flock(fd, LOCK_UN) < 0) {
		ret = SD_RES_EIO;
		eprintf("%m\n");
		goto out_close;
	}

	if (ret != buf_size) {
		ret = SD_RES_EIO;
		eprintf("failed, vid %"PRIx32", idx %"PRIx32"\n", oc->vid, idx);
		goto out_close;
	}
	ret = SD_RES_SUCCESS;
	dprintf("%08"PRIx32" size %zu\n", idx, buf_size);
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

/* Fetch the object, cache it in success */
static int object_cache_pull(struct vnode_info *vnodes, struct object_cache *oc,
		      uint32_t idx)
{
	struct request read_req;
	struct sd_req *hdr = &read_req.rq;
	int ret = SD_RES_NO_MEM;
	uint64_t oid;
	uint32_t data_length;
	void *buf;

	if (idx & CACHE_VDI_BIT) {
		oid = vid_to_vdi_oid(oc->vid);
		data_length = SD_INODE_SIZE;
	} else {
		oid = vid_to_data_oid(oc->vid, idx);
		data_length = SD_DATA_OBJ_SIZE;
	}

	buf = valloc(data_length);
	if (buf == NULL) {
		eprintf("failed to allocate memory\n");
		goto out;
	}
	memset(&read_req, 0, sizeof(read_req));
	hdr->opcode = SD_OP_READ_OBJ;
	hdr->data_length = data_length;
	hdr->epoch = sys_epoch();

	hdr->obj.oid = oid;
	hdr->obj.offset = 0;
	hdr->obj.copies = get_nr_copies(vnodes);

	read_req.data = buf;
	read_req.op = get_sd_op(hdr->opcode);
	read_req.vnodes = vnodes;

	ret = forward_read_obj_req(&read_req);

	if (ret == SD_RES_SUCCESS) {
		dprintf("oid %"PRIx64" pulled successfully\n", oid);
		ret = create_cache_object(oc, idx, buf, data_length);
	}
	free(buf);
out:
	return ret;
}

static uint64_t idx_to_oid(uint32_t vid, uint32_t idx)
{
	if (idx & CACHE_VDI_BIT)
		return vid_to_vdi_oid(vid);
	else
		return vid_to_data_oid(vid, idx);
}

static int push_cache_object(struct vnode_info *vnode_info, uint32_t vid,
		uint32_t idx, uint64_t bmap, int create)
{
	struct request fake_req;
	struct sd_req *hdr = &fake_req.rq;
	void *buf;
	off_t offset;
	unsigned data_length;
	int ret = SD_RES_NO_MEM;
	uint64_t oid = idx_to_oid(vid, idx);
	int first_bit, last_bit;

	dprintf("%"PRIx64", create %d\n", oid, create);

	if (!bmap) {
		dprintf("WARN: nothing to flush\n");
		return SD_RES_SUCCESS;
	}

	memset(&fake_req, 0, sizeof(fake_req));

	first_bit = ffsll(bmap) - 1;
	last_bit = fls64(bmap) - 1;

	dprintf("bmap:0x%"PRIx64", first_bit:%d, last_bit:%d\n",
			bmap, first_bit, last_bit);
	offset = first_bit * CACHE_BLOCK_SIZE;
	data_length = (last_bit - first_bit + 1) * CACHE_BLOCK_SIZE;

	/*
	 * CACHE_BLOCK_SIZE may not be divisible by SD_INODE_SIZE,
	 * so (offset + data_length) could larger than SD_INODE_SIZE
	 */
	if (is_vdi_obj(oid) && (offset + data_length) > SD_INODE_SIZE)
		data_length = SD_INODE_SIZE - offset;

	buf = valloc(data_length);
	if (buf == NULL) {
		eprintf("failed to allocate memory\n");
		goto out;
	}

	ret = read_cache_object(vid, idx, buf, data_length, offset);
	if (ret != SD_RES_SUCCESS)
		goto out;

	hdr->opcode = create ? SD_OP_CREATE_AND_WRITE_OBJ : SD_OP_WRITE_OBJ;
	hdr->flags = SD_FLAG_CMD_WRITE;
	hdr->data_length = data_length;
	hdr->epoch = sys_epoch();

	hdr->obj.oid = oid;
	hdr->obj.offset = 0;
	hdr->obj.copies = sys->nr_copies;

	fake_req.data = buf;
	fake_req.op = get_sd_op(hdr->opcode);
	fake_req.vnodes = vnode_info;

	ret = forward_write_obj_req(&fake_req);
	if (ret != SD_RES_SUCCESS)
		eprintf("failed to push object %x\n", ret);

out:
	free(buf);
	return ret;
}

/* Push back all the dirty objects to sheep cluster storage */
static int object_cache_push(struct vnode_info *vnode_info,
		struct object_cache *oc)
{
	struct object_cache_entry *entry, *t;
	struct rb_root *inactive_dirty_tree;
	struct list_head *inactive_dirty_list;
	int ret = SD_RES_SUCCESS;

	if (node_in_recovery())
		/* We don't do flushing in recovery */
		return SD_RES_SUCCESS;

	switch_dirty_tree_and_list(oc,
			&inactive_dirty_tree,
			&inactive_dirty_list);

	/* 1. for async flush, there is only one worker
	 * 2. for sync flush, Guest assure us of that only one sync
	 * request is issued in one of gateway worker threads
	 * So we need not to protect inactive dirty tree and list */
	list_for_each_entry_safe(entry, t, inactive_dirty_list, list) {
		ret = push_cache_object(vnode_info, oc->vid, entry->idx,
				entry->bmap, entry->create);
		if (ret != SD_RES_SUCCESS)
			goto push_failed;
		del_from_dirty_tree_and_list(entry, inactive_dirty_tree);
		free(entry);
	}
	return ret;
push_failed:
	merge_dirty_tree_and_list(oc,
			inactive_dirty_tree,
			inactive_dirty_list);
	return ret;
}

int object_is_cached(uint64_t oid)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;

	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 0);
	if (!cache)
		return 0;

	if (object_cache_lookup(cache, idx, 0) < 0)
		return 0;
	else
		return 1; /* found it */
}

void object_cache_delete(uint32_t vid)
{
	struct object_cache *cache;

	cache = find_object_cache(vid, 0);
	if (cache) {
		int h = hash(vid);
		struct object_cache_entry *entry, *t;
		struct strbuf buf = STRBUF_INIT;

		/* Firstly we free memeory */
		pthread_mutex_lock(&hashtable_lock[h]);
		hlist_del(&cache->hash);
		pthread_mutex_unlock(&hashtable_lock[h]);

		list_for_each_entry_safe(entry, t, cache->active_dirty_list, list) {
			free(entry);
		}
		free(cache);

		/* Then we free disk */
		strbuf_addf(&buf, "%s/%06"PRIx32, cache_dir, vid);
		rmdir_r(buf.buf);

		strbuf_release(&buf);
	}

}

static int object_cache_flush_and_delete(struct vnode_info *vnode_info,
		struct object_cache *oc)
{
	DIR *dir;
	struct dirent *d;
	uint32_t vid = oc->vid;
	uint32_t idx;
	uint64_t all = UINT64_MAX;
	struct strbuf p;
	int ret = 0;

	strbuf_init(&p, PATH_MAX);
	strbuf_addstr(&p, cache_dir);
	strbuf_addf(&p, "/%06"PRIx32, vid);

	dprintf("%"PRIx32"\n", vid);
	dir = opendir(p.buf);
	if (!dir) {
		dprintf("%m\n");
		ret = -1;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;
		idx = strtoul(d->d_name, NULL, 16);
		if (idx == ULLONG_MAX)
			continue;
		if (push_cache_object(vnode_info, vid, idx, all, 1) !=
				SD_RES_SUCCESS) {
			dprintf("failed to push %"PRIx64"\n",
				idx_to_oid(vid, idx));
			ret = -1;
			goto out;
		}
	}

	object_cache_delete(vid);
out:
	strbuf_release(&p);
	return ret;
}

int bypass_object_cache(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;

	if (!(req->rq.flags & SD_FLAG_CMD_CACHE)) {
		uint32_t vid = oid_to_vid(oid);
		struct object_cache *cache;

		cache = find_object_cache(vid, 0);
		if (!cache)
			return 1;
		if (req->rq.flags & SD_FLAG_CMD_WRITE) {
			object_cache_flush_and_delete(req->vnodes, cache);
			return 1;
		} else  {
			/* For read requet, we can read cache if any */
			uint32_t idx = data_oid_to_idx(oid);
			if (is_vdi_obj(oid))
				idx |= 1 << CACHE_VDI_SHIFT;

			if (object_cache_lookup(cache, idx, 0) < 0)
				return 1;
			else
				return 0;
		}
	}

	/*
	 * For vmstate && vdi_attr object, we don't do caching
	 */
	if (is_vmstate_obj(oid) || is_vdi_attr_obj(oid) ||
	    req->rq.flags & SD_FLAG_CMD_COW)
		return 1;
	return 0;
}

int object_cache_handle_request(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;
	int ret, create = 0;

	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 1);

	if (req->rq.opcode == SD_OP_CREATE_AND_WRITE_OBJ)
		create = 1;

	if (object_cache_lookup(cache, idx, create) < 0) {
		ret = object_cache_pull(req->vnodes, cache, idx);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return object_cache_rw(cache, idx, req);
}

int object_cache_write(uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, uint16_t flags, int copies, uint32_t epoch,
		int create)
{
	int ret;
	struct request *req;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;

	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 0);

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;

	if (create)
		req->rq.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	else
		req->rq.opcode = SD_OP_WRITE_OBJ;
	req->rq.flags = flags | SD_FLAG_CMD_WRITE;
	req->rq.data_length = datalen;

	req->rq.obj.oid = oid;
	req->rq.obj.offset = offset;
	req->rq.obj.copies = copies;

	req->data = data;
	req->op = get_sd_op(req->rq.opcode);

	ret = object_cache_rw(cache, idx, req);

	free(req);
	return ret;
}

int object_cache_read(uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, int copies, uint32_t epoch)
{
	int ret;
	struct request *req;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;

	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 0);

	req = zalloc(sizeof(*req));
	if (!req)
		return SD_RES_NO_MEM;

	req->rq.opcode = SD_OP_READ_OBJ;
	req->rq.data_length = datalen;

	req->rq.obj.oid = oid;
	req->rq.obj.offset = offset;
	req->rq.obj.copies = copies;

	req->data = data;
	req->op = get_sd_op(req->rq.opcode);

	ret = object_cache_rw(cache, idx, req);

	free(req);

	return ret;
}

static void object_cache_flush_vdi_fn(struct work *work)
{
	struct flush_work *fw = container_of(work, struct flush_work, work);

	dprintf("flush vdi %"PRIx32"\n", fw->cache->vid);
	if (object_cache_push(fw->vnode_info, fw->cache) != SD_RES_SUCCESS)
		eprintf("failed to flush vdi %"PRIx32"\n", fw->cache->vid);
}

static void object_cache_flush_vdi_done(struct work *work)
{
	struct flush_work *fw = container_of(work, struct flush_work, work);

	dprintf("flush vdi %"PRIx32" done\n", fw->cache->vid);

	put_vnode_info(fw->vnode_info);
	free(fw);
}

int object_cache_flush_vdi(struct request *req)
{
	uint32_t vid = oid_to_vid(req->rq.obj.oid);
	struct object_cache *cache;

	cache = find_object_cache(vid, 0);
	if (!cache)
		return SD_RES_SUCCESS;

	if (sys->async_flush) {
		struct flush_work *fw = xmalloc(sizeof(*fw));

		fw->work.fn = object_cache_flush_vdi_fn;
		fw->work.done = object_cache_flush_vdi_done;
		fw->cache = cache;
		fw->vnode_info = grab_vnode_info(req->vnodes);

		queue_work(sys->flush_wqueue, &fw->work);
		return SD_RES_SUCCESS;
	}

	return object_cache_push(req->vnodes, cache);
}

int object_cache_flush_and_del(struct request *req)
{
	uint32_t vid = oid_to_vid(req->rq.obj.oid);
	struct object_cache *cache;

	cache = find_object_cache(vid, 0);
	if (cache && object_cache_flush_and_delete(req->vnodes, cache) < 0)
		return SD_RES_EIO;
	return SD_RES_SUCCESS;
}

int object_cache_init(const char *p)
{
	int ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, p);
	strbuf_addstr(&buf, "/cache");
	if (mkdir(buf.buf, def_dmode) < 0) {
		if (errno != EEXIST) {
			eprintf("%m\n");
			ret = -1;
			goto err;
		}
	}
	strbuf_copyout(&buf, cache_dir, sizeof(cache_dir));
err:
	strbuf_release(&buf);
	return ret;
}
