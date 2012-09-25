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
#include <urcu/uatomic.h>
#include <urcu/rculist.h>

#include "sheep_priv.h"
#include "util.h"
#include "strbuf.h"
#include "rbtree.h"

/*
 * Object Cache ID
 *
 *  0 - 19 (20 bits): data object space
 *  20 - 27 (8 bits): object flag space
 *  28 - 31 (4 bits): object type indentifier space
 */
#define CACHE_VDI_SHIFT       31 /* if the entry is identified as VDI object */
#define CACHE_CREATE_SHIFT    27 /* If the entry should be created at backend */

#define CACHE_VDI_BIT         (UINT32_C(1) << CACHE_VDI_SHIFT)
#define CACHE_CREATE_BIT      (UINT32_C(1) << CACHE_CREATE_SHIFT)

#define CACHE_INDEX_MASK      (CACHE_CREATE_BIT)

#define CACHE_BLOCK_SIZE      ((UINT64_C(1) << 10) * 64) /* 64 KB */


struct global_cache {
	uint32_t cache_size;
	int in_reclaim;
	struct cds_list_head cache_lru_list;
};

struct object_cache_entry {
	uint32_t idx;
	int refcnt;
	uint64_t bmap; /* each bit represents one dirty block in object */
	struct object_cache *oc;
	struct rb_node node;
	struct rb_node dirty_node;
	struct list_head dirty_list;
	struct list_head object_list;
	struct cds_list_head lru_list;
};

struct object_cache {
	uint32_t vid;
	struct hlist_node hash;

	struct list_head dirty_list;
	struct list_head object_list;
	struct rb_root dirty_tree;
	struct rb_root object_tree;

	pthread_rwlock_t lock;
};

static struct global_cache sys_cache;
static char cache_dir[PATH_MAX];
static int def_open_flags = O_RDWR;

#define HASH_BITS	5
#define HASH_SIZE	(1 << HASH_BITS)

static pthread_mutex_t hashtable_lock[HASH_SIZE] = {
	[0 ... HASH_SIZE - 1] = PTHREAD_MUTEX_INITIALIZER
};

static struct hlist_head cache_hashtable[HASH_SIZE];

/*
 * If the cache is already in reclaim, return 1, otherwise return 0
 * and set sys_cache.in_reclaim to 1
 */
static inline int mark_cache_in_reclaim(void)
{
	return uatomic_cmpxchg(&sys_cache.in_reclaim, 0, 1);
}

static inline int entry_is_dirty(struct object_cache_entry *entry)
{
	return !!entry->bmap;
}

static inline int hash(uint64_t vid)
{
	return hash_64(vid, HASH_BITS);
}

/* We should always use this helper to get entry idx */
static inline uint32_t entry_idx(struct object_cache_entry *entry)
{
	return entry->idx & ~CACHE_INDEX_MASK;
}

static inline uint32_t object_cache_oid_to_idx(uint64_t oid)
{
	uint32_t idx = data_oid_to_idx(oid);
	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;
	return idx;
}

static inline int idx_has_vdi_bit(uint32_t idx)
{
	return idx & CACHE_VDI_BIT;
}

static uint64_t calc_object_bmap(size_t len, off_t offset)
{
	int start, end, nr;
	unsigned long bmap = 0;

	start = offset / CACHE_BLOCK_SIZE;
	end = DIV_ROUND_UP(len + offset, CACHE_BLOCK_SIZE);
	nr = end - start;

	while (nr--)
		set_bit(start + nr, &bmap);

	return (uint64_t)bmap;
}

static struct object_cache_entry *
object_cache_insert(struct rb_root *root, struct object_cache_entry *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct object_cache_entry *entry;
	uint32_t idx = entry_idx(new);

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct object_cache_entry, node);

		if (idx < entry_idx(entry))
			p = &(*p)->rb_left;
		else if (idx > entry_idx(entry))
			p = &(*p)->rb_right;
		else {
			/* already has this entry */
			return entry;
		}
	}
	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return NULL; /* insert successfully */
}

static struct object_cache_entry *object_tree_search(struct rb_root *root,
						     uint32_t idx)
{
	struct rb_node *n = root->rb_node;
	struct object_cache_entry *t;

	while (n) {
		t = rb_entry(n, struct object_cache_entry, node);

		if (idx < entry_idx(t))
			n = n->rb_left;
		else if (idx > entry_idx(t))
			n = n->rb_right;
		else
			return t; /* found it */
	}

	return NULL;
}

static inline void
del_from_dirty_tree_and_list(struct object_cache_entry *entry,
			     struct rb_root *dirty_tree)
{
	rb_erase(&entry->dirty_node, dirty_tree);
	list_del_init(&entry->dirty_list);
}

static inline void
del_from_object_tree_and_list(struct object_cache_entry *entry,
			      struct rb_root *object_tree)
{
	rb_erase(&entry->node, object_tree);
	list_del_init(&entry->object_list);
	cds_list_del_rcu(&entry->lru_list);
}

static uint64_t idx_to_oid(uint32_t vid, uint32_t idx)
{
	if (idx_has_vdi_bit(idx))
		return vid_to_vdi_oid(vid);
	else
		return vid_to_data_oid(vid, idx);
}

static int remove_cache_object(struct object_cache *oc, uint32_t idx)
{
	struct strbuf buf;
	int ret = SD_RES_SUCCESS;

	strbuf_init(&buf, PATH_MAX);
	strbuf_addstr(&buf, cache_dir);
	strbuf_addf(&buf, "/%06"PRIx32"/%08"PRIx32, oc->vid, idx);

	dprintf("removing cache object %"PRIx64"\n", idx_to_oid(oc->vid, idx));
	if (unlink(buf.buf) < 0) {
		ret = SD_RES_EIO;
		eprintf("failed to remove cached object %m\n");
		goto out;
	}
out:
	strbuf_release(&buf);

	return ret;
}

static struct object_cache_entry *
dirty_tree_and_list_insert(struct object_cache *oc, uint32_t idx,
			   uint64_t bmap, int create)
{
	struct rb_node **p = &oc->dirty_tree.rb_node;
	struct rb_node *parent = NULL;
	struct object_cache_entry *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct object_cache_entry, dirty_node);

		if (idx < entry_idx(entry))
			p = &(*p)->rb_left;
		else if (idx > entry_idx(entry))
			p = &(*p)->rb_right;
		else {
			/* already has this entry, merge bmap */
			entry->bmap |= bmap;
			return entry;
		}
	}

	entry = object_tree_search(&oc->object_tree, idx);
	if (!entry)
		panic("Can not find object entry %" PRIx32 "\n", idx);

	entry->bmap |= bmap;
	if (create)
		entry->idx |= CACHE_CREATE_BIT;
	rb_link_node(&entry->dirty_node, parent, p);
	rb_insert_color(&entry->dirty_node, &oc->dirty_tree);
	list_add(&entry->dirty_list, &oc->dirty_list);

	return entry;
}

static inline void lru_move_entry(struct object_cache_entry *entry)
{
	cds_list_del_rcu(&entry->lru_list);
	cds_list_add_rcu(&entry->lru_list, &sys_cache.cache_lru_list);
}

static inline void update_cache_entry(struct object_cache_entry *entry,
				      uint32_t idx, size_t datalen,
				      off_t offset, int dirty)
{
	struct object_cache *oc = entry->oc;

	if (dirty) {
		uint64_t bmap = calc_object_bmap(datalen, offset);

		pthread_rwlock_wrlock(&oc->lock);
		dirty_tree_and_list_insert(oc, idx, bmap, 0);
		pthread_rwlock_unlock(&oc->lock);
	}

	lru_move_entry(entry);
}

static int read_cache_object_noupdate(uint32_t vid, uint32_t idx, void *buf,
				      size_t count, off_t offset)
{
	size_t size;
	int fd, flags = def_open_flags, ret = SD_RES_SUCCESS;
	struct strbuf p;

	strbuf_init(&p, PATH_MAX);
	strbuf_addstr(&p, cache_dir);
	strbuf_addf(&p, "/%06"PRIx32"/%08"PRIx32, vid, idx);

	if (sys->object_cache_directio && !idx_has_vdi_bit(idx))
		flags |= O_DIRECT;

	fd = open(p.buf, flags, def_fmode);
	if (fd < 0) {
		eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	size = xpread(fd, buf, count, offset);

	if (size != count) {
		eprintf("size %zu, count:%zu, offset %jd %m\n",
			size, count, (intmax_t)offset);
		ret = SD_RES_EIO;
		goto out_close;
	}

out_close:
	close(fd);
out:
	strbuf_release(&p);
	return ret;
}

static int write_cache_object_noupdate(uint32_t vid, uint32_t idx, void *buf,
				       size_t count, off_t offset)
{
	size_t size;
	int fd, flags = def_open_flags, ret = SD_RES_SUCCESS;
	struct strbuf p;

	strbuf_init(&p, PATH_MAX);
	strbuf_addstr(&p, cache_dir);
	strbuf_addf(&p, "/%06"PRIx32"/%08"PRIx32, vid, idx);

	if (sys->object_cache_directio && !idx_has_vdi_bit(idx))
		flags |= O_DIRECT;

	fd = open(p.buf, flags, def_fmode);
	if (fd < 0) {
		eprintf("%m\n");
		ret = SD_RES_EIO;
		goto out;
	}

	size = xpwrite(fd, buf, count, offset);

	if (size != count) {
		eprintf("size %zu, count:%zu, offset %jd %m\n",
			size, count, (intmax_t)offset);
		ret = SD_RES_EIO;
		goto out_close;
	}

out_close:
	close(fd);
out:
	strbuf_release(&p);
	return ret;
}

static int read_cache_object(struct object_cache_entry *entry, void *buf,
			     size_t count, off_t offset)
{
	uint32_t vid = entry->oc->vid, idx = entry_idx(entry);
	int ret;

	ret = read_cache_object_noupdate(vid, idx, buf, count, offset);

	if (ret == SD_RES_SUCCESS)
		update_cache_entry(entry, idx, count, offset, 0);
	return ret;
}

static int write_cache_object(struct object_cache_entry *entry, void *buf,
			      size_t count, off_t offset, int create,
			      bool writeback)
{
	uint32_t vid = entry->oc->vid, idx = entry_idx(entry);
	uint64_t oid = idx_to_oid(vid, idx);
	struct sd_req hdr;
	int ret;

	ret = write_cache_object_noupdate(vid, idx, buf, count, offset);

	if (ret != SD_RES_SUCCESS)
		return ret;

	if (writeback)
		goto out;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);
	hdr.flags =  SD_FLAG_CMD_WRITE;
	hdr.data_length = count;

	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = exec_local_req(&hdr, buf);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to write object %" PRIx64 ", %x\n", oid, ret);
		return ret;
	}
out:
	update_cache_entry(entry, idx, count, offset, writeback);
	return ret;
}

static int push_cache_object(uint32_t vid, uint32_t idx, uint64_t bmap,
			     int create)
{
	struct sd_req hdr;
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

	ret = read_cache_object_noupdate(vid, idx, buf, data_length, offset);
	if (ret != SD_RES_SUCCESS)
		goto out;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = data_length;
	hdr.obj.oid = oid;
	hdr.obj.offset = offset;

	ret = exec_local_req(&hdr, buf);
	if (ret != SD_RES_SUCCESS)
		eprintf("failed to push object %x\n", ret);

out:
	free(buf);
	return ret;
}

/*
 * The reclaim algorithm is similar to Linux kernel's page cache:
 *  - only tries to reclaim 'clean' object, which doesn't has any dirty updates,
 *    in a LRU list.
 *  - skip the object when it is in R/W operation.
 *  - skip the dirty object if it is not in push(writeback) phase.
 *  - wait on the dirty object if it is in push phase.
 */
static int do_reclaim_object(struct object_cache_entry *entry)
{
	struct object_cache *oc = entry->oc;
	uint64_t oid;
	int ret = 0;

	pthread_rwlock_wrlock(&oc->lock);

	oid = idx_to_oid(oc->vid, entry_idx(entry));
	if (uatomic_read(&entry->refcnt) > 0) {
		dprintf("%"PRIx64" is in operation, skip...\n", oid);
		ret = -1;
		goto out;
	}

	if (entry_is_dirty(entry)) {
		dprintf("%"PRIx64" is dirty, skip...\n", oid);
		ret = -1;
		goto out;
	}

	if (remove_cache_object(oc, entry_idx(entry)) != SD_RES_SUCCESS) {
		ret = -1;
		goto out;
	}

	dprintf("oid %"PRIx64" reclaimed successfully, cache_size: %"PRId32"\n",
		oid, uatomic_read(&sys_cache.cache_size));
	del_from_object_tree_and_list(entry, &oc->object_tree);
out:
	pthread_rwlock_unlock(&oc->lock);
	/*
	 * Reclaimer grabs a write lock, which will blocks all the IO thread of
	 * this VDI. We call pthread_yield() to expect that other threads can
	 * grab the lock more often.
	 */
	pthread_yield();
	return ret;
}

static void do_reclaim(struct work *work)
{
	struct object_cache_entry *entry, *n;

	list_for_each_entry_revert_safe_rcu(entry, n,
		       &sys_cache.cache_lru_list, lru_list) {
		unsigned data_length;
		/* Reclaim cache to 80% of max size */
		if (uatomic_read(&sys_cache.cache_size) <=
			sys->object_cache_size * 8 / 10)
			break;

		if (do_reclaim_object(entry) < 0)
			continue;
		if (idx_has_vdi_bit(entry_idx(entry)))
			data_length = SD_INODE_SIZE;
		else
			data_length = SD_DATA_OBJ_SIZE;

		data_length = data_length / 1024 / 1024;
		uatomic_sub(&sys_cache.cache_size, data_length);
		free(entry);
	}

	dprintf("cache reclaim complete\n");
}

static void reclaim_done(struct work *work)
{
	uatomic_set(&sys_cache.in_reclaim, 0);
	free(work);
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
		cache->object_tree = RB_ROOT;
		create_dir_for(vid);

		cache->dirty_tree = RB_ROOT;
		INIT_LIST_HEAD(&cache->dirty_list);
		INIT_LIST_HEAD(&cache->object_list);

		pthread_rwlock_init(&cache->lock, NULL);
		hlist_add_head(&cache->hash, head);
	} else {
		cache = NULL;
	}
out:
	pthread_mutex_unlock(&hashtable_lock[h]);
	return cache;
}

void object_cache_try_to_reclaim(void)
{
	struct work *work;

	if (!sys->object_cache_size)
		return;

	if (uatomic_read(&sys_cache.cache_size) < sys->object_cache_size)
		return;

	if (mark_cache_in_reclaim())
		return;

	work = xzalloc(sizeof(struct work));
	work->fn = do_reclaim;
	work->done = reclaim_done;
	queue_work(sys->reclaim_wqueue, work);
}

static void add_to_object_cache(struct object_cache *oc, uint32_t idx,
				int create)
{
	struct object_cache_entry *entry, *old;
	uint32_t data_length;

	if (idx_has_vdi_bit(idx))
		data_length = SD_INODE_SIZE;
	else
		data_length = SD_DATA_OBJ_SIZE;
	data_length = data_length / 1024 / 1024;

	entry = xzalloc(sizeof(*entry));
	entry->oc = oc;
	entry->idx = idx;
	INIT_LIST_HEAD(&entry->dirty_list);
	INIT_LIST_HEAD(&entry->object_list);
	CDS_INIT_LIST_HEAD(&entry->lru_list);

	pthread_rwlock_wrlock(&oc->lock);
	old = object_cache_insert(&oc->object_tree, entry);
	if (!old) {
		dprintf("oid %"PRIx64"\n", idx_to_oid(oc->vid, idx));
		uatomic_add(&sys_cache.cache_size, data_length);
		list_add(&entry->object_list, &oc->object_list);
		cds_list_add_rcu(&entry->lru_list, &sys_cache.cache_lru_list);
	} else {
		free(entry);
		entry = old;
	}
	if (create) {
		uint64_t all = UINT64_MAX;
		dirty_tree_and_list_insert(oc, idx, all, create);
	}
	pthread_rwlock_unlock(&oc->lock);
	lru_move_entry(entry);

	object_cache_try_to_reclaim();
}

static int object_cache_lookup(struct object_cache *oc, uint32_t idx,
			       int create, bool writeback)
{
	struct strbuf buf;
	int fd, ret = SD_RES_SUCCESS, flags = def_open_flags;
	unsigned data_length;

	strbuf_init(&buf, PATH_MAX);
	strbuf_addstr(&buf, cache_dir);
	strbuf_addf(&buf, "/%06"PRIx32"/%08"PRIx32, oc->vid, idx);

	if (!create) {
		if (access(buf.buf, R_OK | W_OK) < 0) {
			if (errno != ENOENT) {
				dprintf("%m\n");
				ret = SD_RES_EIO;
			} else {
				ret = SD_RES_NO_CACHE;
			}
		}
		goto out;
	}

	flags |= O_CREAT | O_TRUNC;

	fd = open(buf.buf, flags, def_fmode);
	if (fd < 0) {
		ret = SD_RES_EIO;
		goto out;
	}

	if (idx_has_vdi_bit(idx))
		data_length = SD_INODE_SIZE;
	else
		data_length = SD_DATA_OBJ_SIZE;

	ret = prealloc(fd, data_length);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_EIO;
	} else
		add_to_object_cache(oc, idx, writeback);

	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int create_cache_object(struct object_cache *oc, uint32_t idx,
			       void *buffer, size_t buf_size)
{
	int flags = def_open_flags | O_CREAT | O_EXCL, fd;
	int ret = SD_RES_OID_EXIST;
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

	ret = xpwrite(fd, buffer, buf_size, 0);
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
static int object_cache_pull(struct object_cache *oc, uint32_t idx)
{
	struct sd_req hdr;
	int ret = SD_RES_NO_MEM;
	uint64_t oid;
	uint32_t data_length;
	void *buf;

	if (idx_has_vdi_bit(idx)) {
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

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.data_length = data_length;
	hdr.obj.oid = oid;
	hdr.obj.offset = 0;
	ret = exec_local_req(&hdr, buf);

	if (ret == SD_RES_SUCCESS) {
		dprintf("oid %"PRIx64" pulled successfully\n", oid);
		ret = create_cache_object(oc, idx, buf, data_length);
		if (ret == SD_RES_SUCCESS)
			add_to_object_cache(oc, idx, 0);
		else if (ret == SD_RES_OID_EXIST)
			ret = SD_RES_SUCCESS;
	}
	free(buf);
out:
	return ret;
}

/* Push back all the dirty objects to sheep cluster storage */
static int object_cache_push(struct object_cache *oc)
{
	struct object_cache_entry *entry, *t;

	int ret = SD_RES_SUCCESS;

	pthread_rwlock_wrlock(&oc->lock);
	list_for_each_entry_safe(entry, t, &oc->dirty_list, dirty_list) {
		ret = push_cache_object(oc->vid, entry_idx(entry), entry->bmap,
					!!(entry->idx & CACHE_CREATE_BIT));
		if (ret != SD_RES_SUCCESS)
			goto push_failed;
		entry->idx &= ~CACHE_CREATE_BIT;
		entry->bmap = 0;
		del_from_dirty_tree_and_list(entry, &oc->dirty_tree);
	}
push_failed:
	pthread_rwlock_unlock(&oc->lock);
	return ret;
}

int object_is_cached(uint64_t oid)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;

	cache = find_object_cache(vid, 0);
	if (!cache)
		return 0;

	return (object_cache_lookup(cache, idx, 0, false) == SD_RES_SUCCESS);
}

void object_cache_delete(uint32_t vid)
{
	struct object_cache *cache;
	int h = hash(vid);
	struct object_cache_entry *entry, *t;
	struct strbuf buf = STRBUF_INIT;

	cache = find_object_cache(vid, 0);
	if (!cache)
		return;

	/* Firstly we free memeory */
	pthread_mutex_lock(&hashtable_lock[h]);
	hlist_del(&cache->hash);
	pthread_mutex_unlock(&hashtable_lock[h]);

	pthread_rwlock_wrlock(&cache->lock);
	list_for_each_entry_safe(entry, t, &cache->object_list, object_list) {
		del_from_object_tree_and_list(entry, &cache->object_tree);
		if (!list_empty(&entry->dirty_list))
			del_from_dirty_tree_and_list(entry, &cache->dirty_tree);
		free(entry);
	}
	pthread_rwlock_unlock(&cache->lock);
	free(cache);

	/* Then we free disk */
	strbuf_addf(&buf, "%s/%06"PRIx32, cache_dir, vid);
	rmdir_r(buf.buf);

	strbuf_release(&buf);
}

static struct object_cache_entry *
get_cache_entry(struct object_cache *cache, uint32_t idx)
{
	struct object_cache_entry *entry;

	pthread_rwlock_rdlock(&cache->lock);
	entry = object_tree_search(&cache->object_tree, idx);
	if (!entry) {
		/* The cache entry may be reclaimed, so try again. */
		pthread_rwlock_unlock(&cache->lock);
		return NULL;
	}

	uatomic_inc(&entry->refcnt);
	pthread_rwlock_unlock(&cache->lock);

	return entry;
}

static void put_cache_entry(struct object_cache_entry *entry)
{
	uatomic_dec(&entry->refcnt);
}

static int object_cache_flush_and_delete(struct object_cache *oc)
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
		if (push_cache_object(vid, idx, all, 1) !=
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

	if (req->rq.flags & SD_FLAG_CMD_DIRECT) {
		uint32_t vid = oid_to_vid(oid);
		struct object_cache *cache;

		cache = find_object_cache(vid, 0);
		if (!cache)
			return 1;
		if (req->rq.flags & SD_FLAG_CMD_WRITE) {
			object_cache_flush_and_delete(cache);
			return 1;
		} else  {
			/* For read requet, we can read cache if any */
			uint32_t idx = object_cache_oid_to_idx(oid);

			if (object_cache_lookup(cache, idx, 0, false) == 0)
				return 0;
			else
				return 1;
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
	struct sd_req *hdr = &req->rq;
	uint64_t oid = req->rq.obj.oid;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;
	struct object_cache_entry *entry;
	int ret, create = 0;

	dprintf("%08"PRIx32", len %"PRIu32", off %"PRIu64"\n", idx,
		hdr->data_length, hdr->obj.offset);

	cache = find_object_cache(vid, 1);

	if (req->rq.opcode == SD_OP_CREATE_AND_WRITE_OBJ)
		create = 1;

retry:
	ret = object_cache_lookup(cache, idx, create,
				  hdr->flags & SD_FLAG_CMD_CACHE);
	if (ret == SD_RES_NO_CACHE) {
		ret = object_cache_pull(cache, idx);
		if (ret != SD_RES_SUCCESS)
			return ret;
	} else if (ret == SD_RES_EIO)
		return ret;

	entry = get_cache_entry(cache, idx);
	if (!entry) {
		dprintf("retry oid %"PRIx64"\n", oid);
		/*
		 * For the case that object exists but isn't added to object
		 * list yet, we call pthread_yield() to expect other thread can
		 * add object to list ASAP.
		 */
		pthread_yield();
		goto retry;
	}

	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		ret = write_cache_object(entry, req->data, hdr->data_length,
					 hdr->obj.offset, create,
					 hdr->flags & SD_FLAG_CMD_CACHE);
		if (ret != SD_RES_SUCCESS)
			goto err;
	} else {
		ret = read_cache_object(entry, req->data, hdr->data_length,
					hdr->obj.offset);
		if (ret != SD_RES_SUCCESS)
			goto err;
		req->rp.data_length = hdr->data_length;
	}
err:
	put_cache_entry(entry);
	return ret;
}

int object_cache_write(uint64_t oid, char *data, unsigned int datalen,
		       uint64_t offset, uint16_t flags, int create)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;
	struct object_cache_entry *entry;
	int ret;

	cache = find_object_cache(vid, 0);

	dprintf("%" PRIx64 "\n", oid);

	entry = get_cache_entry(cache, idx);
	if (!entry) {
		dprintf("%" PRIx64 " doesn't exist\n", oid);
		return SD_RES_NO_CACHE;
	}

	ret = write_cache_object(entry, data, datalen, offset, create, false);

	put_cache_entry(entry);

	return ret;
}

int object_cache_read(uint64_t oid, char *data, unsigned int datalen,
		      uint64_t offset)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *cache;
	struct object_cache_entry *entry;
	int ret;

	cache = find_object_cache(vid, 0);

	dprintf("%" PRIx64 "\n", oid);

	entry = get_cache_entry(cache, idx);
	if (!entry) {
		dprintf("%" PRIx64 " doesn't exist\n", oid);
		return SD_RES_NO_CACHE;
	}

	ret = read_cache_object(entry, data, datalen, offset);

	put_cache_entry(entry);

	return ret;
}

int object_cache_flush_vdi(struct request *req)
{
	uint32_t vid = oid_to_vid(req->rq.obj.oid);
	struct object_cache *cache;

	cache = find_object_cache(vid, 0);
	if (!cache) {
		dprintf("%"PRIX32" not found\n", vid);
		return SD_RES_SUCCESS;
	}

	return object_cache_push(cache);
}

int object_cache_flush_and_del(struct request *req)
{
	uint32_t vid = oid_to_vid(req->rq.obj.oid);
	struct object_cache *cache;

	cache = find_object_cache(vid, 0);

	if (cache && object_cache_flush_and_delete(cache) < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}

void object_cache_remove(uint64_t oid)
{
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = object_cache_oid_to_idx(oid);
	struct object_cache *oc;
	struct object_cache_entry *entry;

	oc = find_object_cache(vid, 0);
	if (!oc)
		return;

	pthread_rwlock_wrlock(&oc->lock);
	entry = object_tree_search(&oc->object_tree, idx);
	if (!entry)
		goto out;
	if (!list_empty(&entry->dirty_list))
		del_from_dirty_tree_and_list(entry, &oc->dirty_tree);
	del_from_object_tree_and_list(entry, &oc->object_tree);
	free(entry);
out:
	pthread_rwlock_unlock(&oc->lock);
	return;
}

static int load_existing_cache_object(struct object_cache *cache)
{
	DIR *dir;
	struct dirent *d;
	uint32_t idx;
	struct strbuf idx_buf;
	int ret = 0;

	strbuf_init(&idx_buf, PATH_MAX);
	strbuf_addstr(&idx_buf, cache_dir);
	strbuf_addf(&idx_buf, "/%06"PRIx32, cache->vid);

	dir = opendir(idx_buf.buf);
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

		add_to_object_cache(cache, idx, 0);
		dprintf("load cache %06" PRIx32 "/%08" PRIx32 "\n",
			cache->vid, idx);
	}

out:
	strbuf_release(&idx_buf);
	return ret;
}

static int load_existing_cache(void)
{
	DIR *dir;
	struct dirent *d;
	uint32_t vid;
	struct object_cache *cache;
	struct strbuf vid_buf;
	int ret = 0;

	strbuf_init(&vid_buf, PATH_MAX);
	strbuf_addstr(&vid_buf, cache_dir);

	dir = opendir(vid_buf.buf);
	if (!dir) {
		dprintf("%m\n");
		ret = -1;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;
		vid = strtoul(d->d_name, NULL, 16);
		if (vid == ULLONG_MAX)
			continue;

		cache = find_object_cache(vid, 1);
		load_existing_cache_object(cache);
	}

out:
	strbuf_release(&vid_buf);
	return ret;
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

	CDS_INIT_LIST_HEAD(&sys_cache.cache_lru_list);
	uatomic_set(&sys_cache.cache_size, 0);
	uatomic_set(&sys_cache.in_reclaim, 0);

	ret = load_existing_cache();
err:
	strbuf_release(&buf);
	return ret;
}
