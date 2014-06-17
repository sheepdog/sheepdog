/*
 * Copyright (C) 2012 Taobao Inc.
 *
 * Levin Li <xingke.lwp@taobao.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"

struct objlist_cache_entry {
	uint64_t oid;
	struct rb_node node;
};

struct objlist_cache {
	int tree_version;
	int buf_version;
	int cache_size;
	uint64_t *buf;
	struct rb_root root;
	struct sd_rw_lock lock;
};

struct objlist_deletion_work {
	uint32_t vid;
	struct work work;
};

static struct objlist_cache obj_list_cache = {
	.tree_version	= 1,
	.root		= RB_ROOT,
	.lock		= SD_RW_LOCK_INITIALIZER,
};

static int objlist_cache_cmp(const struct objlist_cache_entry *a,
			     const struct objlist_cache_entry *b)
{
	return intcmp(a->oid, b->oid);
}

static struct objlist_cache_entry *objlist_cache_rb_insert(struct rb_root *root,
		struct objlist_cache_entry *new)
{
	return rb_insert(root, new, node, objlist_cache_cmp);
}

static int objlist_cache_rb_remove(struct rb_root *root, uint64_t oid)
{
	struct objlist_cache_entry *entry,  key = { .oid = oid  };

	entry = rb_search(root, &key, node, objlist_cache_cmp);
	if (!entry)
		return -1;

	rb_erase(&entry->node, root);
	free(entry);

	return 0;
}

void objlist_cache_remove(uint64_t oid)
{
	sd_write_lock(&obj_list_cache.lock);
	if (!objlist_cache_rb_remove(&obj_list_cache.root, oid)) {
		obj_list_cache.cache_size--;
		obj_list_cache.tree_version++;
	}
	sd_rw_unlock(&obj_list_cache.lock);
}

int objlist_cache_insert(uint64_t oid)
{
	struct objlist_cache_entry *entry, *p;

	entry = xzalloc(sizeof(*entry));
	entry->oid = oid;
	rb_init_node(&entry->node);

	sd_write_lock(&obj_list_cache.lock);
	p = objlist_cache_rb_insert(&obj_list_cache.root, entry);
	if (p)
		free(entry);
	else {
		obj_list_cache.cache_size++;
		obj_list_cache.tree_version++;
	}
	sd_rw_unlock(&obj_list_cache.lock);

	return 0;
}

int get_obj_list(const struct sd_req *hdr, struct sd_rsp *rsp, void *data)
{
	int i = 0, j, copies;
	struct objlist_cache_entry *entry;
	struct node_id peer_nid;
	struct request *req = container_of(hdr, struct request, rq);
	struct vnode_info *peer_vinfo = req->vinfo;
	const struct sd_vnode *vnodes[SD_MAX_COPIES];
	int last = 0, end = 4096;
	uint64_t *oids = xmalloc(end * sizeof(uint64_t));

	memcpy(peer_nid.addr, hdr->node_addr.addr, sizeof(peer_nid.addr));
	peer_nid.port = hdr->node_addr.port;

	/* first try getting the cached buffer with only a read lock held */
	sd_read_lock(&obj_list_cache.lock);
	if (obj_list_cache.tree_version == obj_list_cache.buf_version)
		goto out;

	/* if that fails grab a write lock for the usually nessecary update */
	sd_rw_unlock(&obj_list_cache.lock);
	sd_write_lock(&obj_list_cache.lock);
	if (obj_list_cache.tree_version == obj_list_cache.buf_version)
		goto out;

	obj_list_cache.buf_version = obj_list_cache.tree_version;
	obj_list_cache.buf = xrealloc(obj_list_cache.buf,
				obj_list_cache.cache_size * sizeof(uint64_t));

	rb_for_each_entry(entry, &obj_list_cache.root, node) {
		obj_list_cache.buf[i++] = entry->oid;
	}

out:
	/* Screen out objects that don't belong to that node */
	for (i = 0; i < obj_list_cache.cache_size; i++) {
		copies = get_obj_copy_number(obj_list_cache.buf[i],
				peer_vinfo->nr_zones);
		oid_to_vnodes(obj_list_cache.buf[i],
				&peer_vinfo->vroot, copies, vnodes);
		for (j = 0; j < copies; j++) {
			if (!vnode_is_peer(vnodes[j], &peer_nid))
				continue;
			oids[last++] = obj_list_cache.buf[i];
			if (last >= end) {
				end *= 2;
				oids = xrealloc(oids, end * sizeof(uint64_t));
			}
		}
	}

	if (hdr->data_length < last * sizeof(uint64_t)) {
		sd_rw_unlock(&obj_list_cache.lock);
		sd_err("GET_OBJ_LIST buffer too small");
		free(oids);
		return SD_RES_BUFFER_SMALL;
	}

	rsp->data_length = last * sizeof(uint64_t);
	memcpy(data, oids, rsp->data_length);
	sd_rw_unlock(&obj_list_cache.lock);
	free(oids);
	return SD_RES_SUCCESS;
}

static void objlist_deletion_work(struct work *work)
{
	struct objlist_deletion_work *ow =
		container_of(work, struct objlist_deletion_work, work);
	struct objlist_cache_entry *entry;
	uint32_t vid = ow->vid, entry_vid;

	/*
	 * Before reclaiming the cache belonging to the VDI just deleted,
	 * we should test whether the VDI is exist, because after some node
	 * deleting it and before the notification is sent to all the node,
	 * another node may issus a VDI creation event and reused the VDI id
	 * again, in which case we should not reclaim the cached entry.
	 */
	if (vdi_exist(vid)) {
		sd_debug("VDI (%" PRIx32 ") is still in use, can not be"
			 " deleted", vid);
		return;
	}

	sd_write_lock(&obj_list_cache.lock);
	rb_for_each_entry(entry, &obj_list_cache.root, node) {
		entry_vid = oid_to_vid(entry->oid);
		if (entry_vid != vid)
			continue;

		/* VDI objects cannot be removed even after we delete images. */
		if (is_vdi_obj(entry->oid))
			continue;

		sd_debug("delete object entry %" PRIx64, entry->oid);
		rb_erase(&entry->node, &obj_list_cache.root);
		free(entry);
	}
	sd_rw_unlock(&obj_list_cache.lock);
}

static void objlist_deletion_done(struct work *work)
{
	struct objlist_deletion_work *ow =
		container_of(work, struct objlist_deletion_work, work);
	free(ow);
}

/*
 * During recovery, some objects may be migrated from one node to a
 * new one, but we can't remove the object list cache entry in this
 * case, it may causes recovery failure, so after recovery, we can
 * not locate the cache entry correctly, causing objlist_cache_remove()
 * fail to delete it, then we need this function to do the cleanup work
 * in all nodes.
 */
int objlist_cache_cleanup(uint32_t vid)
{
	struct objlist_deletion_work *ow;

	ow = xzalloc(sizeof(*ow));
	ow->vid = vid;
	ow->work.fn = objlist_deletion_work;
	ow->work.done = objlist_deletion_done;
	queue_work(sys->deletion_wqueue, &ow->work);

	return SD_RES_SUCCESS;
}
