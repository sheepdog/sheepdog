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

struct objlist_cache obj_list_cache;

int init_objlist_cache(void)
{
	int i;
	struct siocb iocb = { 0 };
	uint64_t *buf;

	pthread_rwlock_init(&obj_list_cache.lock, NULL);
	obj_list_cache.root = RB_ROOT;
	obj_list_cache.cache_size = 0;

	if (sd_store) {
		buf = zalloc(1 << 22);
		if (!buf) {
			eprintf("no memory to allocate.\n");
			return -1;
		}

		iocb.length = 0;
		iocb.buf = buf;
		sd_store->get_objlist(&iocb);

		for (i = 0; i < iocb.length; i++)
			check_and_insert_objlist_cache(buf[i]);

		free(buf);
	}

	return 0;
}

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

int objlist_cache_rb_remove(struct rb_root *root, uint64_t oid)
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
			return 0;
		}
	}

	return -1; /* fail to remove */
}

int check_and_insert_objlist_cache(uint64_t oid)
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
	else
		obj_list_cache.cache_size++;
	pthread_rwlock_unlock(&obj_list_cache.lock);

	return 0;
}

int get_obj_list(const struct sd_list_req *hdr, struct sd_list_rsp *rsp, void *data)
{
	uint64_t *list = (uint64_t *)data;
	int nr = 0;
	int res = SD_RES_SUCCESS;
	struct objlist_cache_entry *entry;
	struct rb_node *p;

	pthread_rwlock_rdlock(&obj_list_cache.lock);
	for (p = rb_first(&obj_list_cache.root); p; p = rb_next(p)) {
		entry = rb_entry(p, struct objlist_cache_entry, node);
		list[nr++] = entry->oid;
	}
	pthread_rwlock_unlock(&obj_list_cache.lock);

	rsp->data_length = nr * sizeof(uint64_t);

	return res;
}
