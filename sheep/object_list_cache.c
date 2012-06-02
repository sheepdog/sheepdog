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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

#include "sheep_priv.h"
#include "strbuf.h"
#include "util.h"

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
	pthread_rwlock_t lock;
};

struct objlist_cache obj_list_cache = {
	.tree_version	= 1,
	.root		= RB_ROOT,
};

static struct objlist_cache_entry *objlist_cache_rb_insert(struct rb_root *root,
		struct objlist_cache_entry *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct objlist_cache_entry *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct objlist_cache_entry, node);

		if (new->oid < entry->oid)
			p = &(*p)->rb_left;
		else if (new->oid > entry->oid)
			p = &(*p)->rb_right;
		else
			return entry; /* already has this entry */
	}
	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return NULL; /* insert successfully */
}

static int objlist_cache_rb_remove(struct rb_root *root, uint64_t oid)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct objlist_cache_entry *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct objlist_cache_entry, node);

		if (oid < entry->oid)
			p = &(*p)->rb_left;
		else if (oid > entry->oid)
			p = &(*p)->rb_right;
		else {
			rb_erase(parent, root);
			free(entry);
			return 0;
		}
	}

	return -1; /* fail to remove */
}

void objlist_cache_remove(uint64_t oid)
{
	pthread_rwlock_wrlock(&obj_list_cache.lock);
	if (!objlist_cache_rb_remove(&obj_list_cache.root, oid)) {
		obj_list_cache.cache_size--;
		obj_list_cache.tree_version++;
	}
	pthread_rwlock_unlock(&obj_list_cache.lock);
}

int objlist_cache_insert(uint64_t oid)
{
	struct objlist_cache_entry *entry, *p;

	entry = zalloc(sizeof(*entry));

	if (!entry) {
		eprintf("no memory to allocate cache entry.\n");
		return -1;
	}

	entry->oid = oid;
	rb_init_node(&entry->node);

	pthread_rwlock_wrlock(&obj_list_cache.lock);
	p = objlist_cache_rb_insert(&obj_list_cache.root, entry);
	if (p)
		free(entry);
	else {
		obj_list_cache.cache_size++;
		obj_list_cache.tree_version++;
	}
	pthread_rwlock_unlock(&obj_list_cache.lock);

	return 0;
}

int get_obj_list(const struct sd_list_req *hdr, struct sd_list_rsp *rsp, void *data)
{
	int nr = 0;
	struct objlist_cache_entry *entry;
	struct rb_node *p;

	/* first try getting the cached buffer with only a read lock held */
	pthread_rwlock_rdlock(&obj_list_cache.lock);
	if (obj_list_cache.tree_version == obj_list_cache.buf_version)
		goto out;

	/* if that fails grab a write lock for the usually nessecary update */
	pthread_rwlock_unlock(&obj_list_cache.lock);
	pthread_rwlock_wrlock(&obj_list_cache.lock);
	if (obj_list_cache.tree_version == obj_list_cache.buf_version)
		goto out;

	obj_list_cache.buf_version = obj_list_cache.tree_version;
	obj_list_cache.buf = xrealloc(obj_list_cache.buf,
				obj_list_cache.cache_size * sizeof(uint64_t));

	for (p = rb_first(&obj_list_cache.root); p; p = rb_next(p)) {
		entry = rb_entry(p, struct objlist_cache_entry, node);
		obj_list_cache.buf[nr++] = entry->oid;
	}

out:
	if (hdr->data_length < obj_list_cache.cache_size * sizeof(uint64_t)) {
		pthread_rwlock_unlock(&obj_list_cache.lock);
		eprintf("GET_OBJ_LIST buffer too small\n");
		return SD_RES_EIO;
	}

	rsp->data_length = obj_list_cache.cache_size * sizeof(uint64_t);
	memcpy(data, obj_list_cache.buf, rsp->data_length);
	pthread_rwlock_unlock(&obj_list_cache.lock);
	return SD_RES_SUCCESS;
}
