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

#include "sheep_priv.h"
#include "util.h"
#include "strbuf.h"
#include "rbtree.h"

#define HASH_BITS	5
#define HASH_SIZE	(1 << HASH_BITS)

static char cache_dir[PATH_MAX];
static int def_open_flags = O_DSYNC | O_RDWR;
extern mode_t def_fmode;
extern mode_t def_dmode;
extern struct store_driver *sd_store;

static pthread_mutex_t hashtable_lock[HASH_SIZE] = { [0 ... HASH_SIZE - 1] = PTHREAD_MUTEX_INITIALIZER };
static struct hlist_head cache_hashtable[HASH_SIZE];

static inline int hash(uint64_t vid)
{
	return hash_64(vid, HASH_BITS);
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
		else
			return entry; /* already has this entry */
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

struct object_cache *find_object_cache(uint32_t vid, int create)
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
		cache->dirty_rb = RB_ROOT;
		pthread_mutex_init(&cache->lock, NULL);
		INIT_LIST_HEAD(&cache->dirty_list);
		hlist_add_head(&cache->hash, head);
	} else
		cache = NULL;
out:
	pthread_mutex_unlock(&hashtable_lock[h]);
	return cache;
}

int object_cache_lookup(struct object_cache *oc, uint32_t idx)
{
	struct strbuf buf;
	int fd, ret = 0;

	strbuf_init(&buf, PATH_MAX);
	strbuf_addstr(&buf, cache_dir);
	strbuf_addf(&buf, "/%06"PRIx32"/%08"PRIx32, oc->vid, idx);

	fd = open(buf.buf, def_open_flags, def_fmode);
	if (fd < 0) {
		ret = -1;
		goto out;
	}
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int write_cache_object(uint32_t vid, uint32_t idx, void *buf, size_t count, off_t offset)
{
	size_t size;
	int fd, ret = SD_RES_SUCCESS;
	struct strbuf p;

	strbuf_init(&p, PATH_MAX);
	strbuf_addstr(&p, cache_dir);
	strbuf_addf(&p, "/%06"PRIx32"/%08"PRIx32, vid, idx);

	fd = open(p.buf, def_open_flags, def_fmode);
	size = xpwrite(fd, buf, count, offset);
	if (size != count)
		ret = SD_RES_EIO;
	close(fd);
	strbuf_release(&p);
	return ret;
}

static int read_cache_object(uint32_t vid, uint32_t idx, void *buf, size_t count, off_t offset)
{
	size_t size;
	int fd, ret = SD_RES_SUCCESS;
	struct strbuf p;

	strbuf_init(&p, PATH_MAX);
	strbuf_addstr(&p, cache_dir);
	strbuf_addf(&p, "/%06"PRIx32"/%08"PRIx32, vid, idx);

	fd = open(p.buf, def_open_flags, def_fmode);
	size = xpread(fd, buf, count, offset);
	if (size != count)
		ret = SD_RES_EIO;
	close(fd);
	strbuf_release(&p);
	return ret;
}

static void add_to_dirty_tree_and_list(struct object_cache *oc, uint32_t idx)
{
	struct object_cache_entry *entry = xzalloc(sizeof(*entry));

	entry->idx = idx;
	pthread_mutex_lock(&oc->lock);
	if (!dirty_tree_insert(&oc->dirty_rb, entry))
		list_add(&entry->list, &oc->dirty_list);
	else
		free(entry);
	pthread_mutex_unlock(&oc->lock);
}

int object_cache_rw(struct object_cache *oc, uint32_t idx, struct request *req)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	int ret;

	dprintf("%"PRIx64", len %"PRIu32", off %"PRIu64"\n", oc->oid, hdr->data_length, hdr->offset);
	if (hdr->flags & SD_FLAG_CMD_WRITE) {
		ret = write_cache_object(oc->vid, idx, req->data, hdr->data_length, hdr->offset);
		if (ret != SD_RES_SUCCESS)
			goto out;
		add_to_dirty_tree_and_list(oc, idx);
	} else {
		ret = read_cache_object(oc->vid, idx, req->data, hdr->data_length, hdr->offset);
		if (ret != SD_RES_SUCCESS)
			goto out;
		rsp->data_length = hdr->data_length;
	}
out:
	return ret;
}

static int create_cache_object(struct object_cache *oc, uint32_t idx, void *buffer,
		size_t buf_size)
{
	int flags = def_open_flags | O_CREAT | O_TRUNC, fd, ret;
	struct strbuf buf;

	strbuf_init(&buf, PATH_MAX);
	strbuf_addstr(&buf, cache_dir);
	strbuf_addf(&buf, "/%06"PRIx32"/%08"PRIx32, oc->vid, idx);

	fd = open(buf.buf, flags, def_fmode);
	if (fd < 0) {
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
int object_cache_pull(struct object_cache *oc, uint32_t idx)
{
	int i, n = 0, fd, ret = SD_RES_NO_MEM;
	unsigned wlen = 0, rlen, data_length, read_len;
	uint64_t oid = oc->oid;
	struct sd_obj_req hdr = { 0 };
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	struct sd_vnode *vnodes = sys->vnodes;
	void *buf;

	if (is_vdi_obj(oid))
		data_length = sizeof(struct sheepdog_inode);
	else
		data_length = SD_DATA_OBJ_SIZE;

	buf = valloc(data_length);
	if (buf == NULL) {
		eprintf("failed to allocate memory\n");
		goto out;
	}

	/* Check if we can read locally */
	for (i = 0; i < sys->nr_sobjs; i++) {
		n = obj_to_sheep(vnodes, sys->nr_vnodes, oid, i);
		if (is_myself(vnodes[n].addr, vnodes[n].port)) {
			struct siocb iocb = { 0 };
			iocb.epoch = sys->epoch;
			ret = sd_store->open(oid, &iocb, 0);
			if (ret != SD_RES_SUCCESS)
				goto out;

			iocb.buf = buf;
			iocb.length = data_length;
			iocb.offset = 0;
			ret = sd_store->read(oid, &iocb);
			if (ret != SD_RES_SUCCESS)
				goto out;
			sd_store->close(oid, &iocb);
			/* read succeed */
			read_len = iocb.length;
			dprintf("[local] %08"PRIx32"\n", idx);
			goto out;
		}
	}

	/* Okay, no luck, let's read remotely */
	hdr.opcode = SD_OP_READ_OBJ;
	hdr.oid = oid;
	hdr.epoch = sys->epoch;
	hdr.data_length = rlen = data_length;
	hdr.flags = SD_FLAG_CMD_IO_LOCAL;

	fd = get_sheep_fd(vnodes[n].addr, vnodes[n].port, vnodes[n].node_idx, hdr.epoch);
	if (fd < 0) {
		ret = SD_RES_NETWORK_ERROR;
		goto out;
	}
	ret = exec_req(fd, (struct sd_req *)&hdr, buf, &wlen, &rlen);
	if (ret) { /* network errors */
		del_sheep_fd(fd);
		ret = SD_RES_NETWORK_ERROR;
	} else
		ret = rsp->result;
	read_len = rlen;
	dprintf("[remote] %08"PRIx32", res:%"PRIx32"\n", idx, ret);
out:
	if (ret == SD_RES_SUCCESS)
		ret = create_cache_object(oc, idx, buf, read_len);
	free(buf);
	return ret;
}

static uint64_t idx_to_oid(uint32_t vid, uint32_t idx)
{
	if (idx & CACHE_VDI_BIT)
		return vid_to_vdi_oid(vid);
	else
		return vid_to_data_oid(vid, idx);
}

static int push_cache_object(int fd, uint64_t oid)
{
	dprintf("%"PRIx64"\n", oid);
	return 0;
}

/* Push back all the dirty objects to sheep cluster storage */
int object_cache_push(struct object_cache *oc)
{
	struct object_cache_entry *entry, *t;
	int ret = SD_RES_SUCCESS;

	if (node_in_recovery())
		/* We don't do flushing in recovery */
		return SD_RES_SUCCESS;

	list_for_each_entry_safe(entry, t, &oc->dirty_list, list) {
		ret = push_cache_object(oc->vid, entry->idx);
		if (ret != SD_RES_SUCCESS)
			goto out;
		pthread_mutex_lock(&oc->lock);
		rb_erase(&entry->rb, &oc->dirty_rb);
		list_del(&entry->list);
		pthread_mutex_unlock(&oc->lock);
		free(entry);
	}
out:
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
	memcpy(cache_dir, buf.buf, buf.len);
err:
	strbuf_release(&buf);
	return ret;
}
