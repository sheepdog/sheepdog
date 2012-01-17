/*
 * Copyright (C) 2011 Taobao Inc.
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

/*
 * Trunk object is meta data that describes the structure of the data objects
 * at the time of snapshot being taken. It ties data objects together into a flat
 * directory structure.
 */
#include <pthread.h>
#include <dirent.h>

#include "farm.h"
#include "strbuf.h"
#include "list.h"
#include "util.h"
#include "sheepdog_proto.h"

#define TRUNK_ENTRY_DIRTY	0x00000001

#define HASH_BITS	10
#define HASH_SIZE	(1 << HASH_BITS)

static LIST_HEAD(trunk_active_list);
static pthread_mutex_t active_list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hlist_head trunk_hashtable[HASH_SIZE];
static pthread_mutex_t hashtable_lock[HASH_SIZE] = { [0 ... HASH_SIZE - 1] = PTHREAD_MUTEX_INITIALIZER };
static unsigned int trunk_entry_active_nr;

static inline int trunk_entry_is_dirty(struct trunk_entry_incore *entry)
{
	return entry->flags & TRUNK_ENTRY_DIRTY;
}

static inline void dirty_trunk_entry(struct trunk_entry_incore *entry)
{
	entry->flags |= TRUNK_ENTRY_DIRTY;
}

static inline void undirty_trunk_entry(struct trunk_entry_incore *entry)
{
	entry->flags &= ~TRUNK_ENTRY_DIRTY;
}

static inline int hash(uint64_t oid)
{
	return hash_64(oid, HASH_BITS);
}

static inline void get_entry(struct trunk_entry_incore *entry, struct hlist_head *head)
{
	hlist_add_head(&entry->hash, head);
	pthread_mutex_lock(&active_list_lock);
	list_add(&entry->active_list, &trunk_active_list);
	trunk_entry_active_nr++;
	pthread_mutex_unlock(&active_list_lock);
}

static struct trunk_entry_incore *lookup_trunk_entry(uint64_t oid, int create)
{
	int h = hash(oid);
	struct hlist_head *head = trunk_hashtable + h;
	struct trunk_entry_incore *entry = NULL;
	struct hlist_node *node;

	pthread_mutex_lock(&hashtable_lock[h]);
	if (hlist_empty(head))
		goto not_found;

	hlist_for_each_entry(entry, node, head, hash) {
		if (entry->raw.oid == oid)
			goto out;
	}
not_found:
	if (create) {
		entry = xzalloc(sizeof(*entry));
		entry->raw.oid = oid;
		get_entry(entry, head);
	}
out:
	pthread_mutex_unlock(&hashtable_lock[h]);
	return entry;
}

int trunk_init(void)
{
	DIR *dir;
	struct dirent *d;
	uint64_t oid;

	dir = opendir(obj_path);
	if (!dir)
		return -1;

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;
		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0 || oid == ULLONG_MAX)
			continue;
		lookup_trunk_entry(oid, 1);
	}
	closedir(dir);
	return 0;
}

static int fill_entry_new_sha1(struct trunk_entry_incore *entry)
{
	struct strbuf buf = STRBUF_INIT;
	int fd, ret = 0;
	struct sha1_file_hdr hdr = { .priv = 0 };

	memcpy(hdr.tag, TAG_DATA, TAG_LEN);
	strbuf_addstr(&buf, obj_path);
	strbuf_addf(&buf, "%016" PRIx64, entry->raw.oid);
	fd = open(buf.buf, O_RDONLY);
	strbuf_reset(&buf);

	if (fd < 0) {
		ret = -1;
		goto out;
	}
	if (!strbuf_read(&buf, fd, SD_DATA_OBJ_SIZE) == SD_DATA_OBJ_SIZE) {
		ret = -1;
		close(fd);
		goto out;
	}
	hdr.size = buf.len;
	strbuf_insert(&buf, 0, &hdr, sizeof(hdr));

	if (sha1_file_write((void *)buf.buf, buf.len, entry->raw.sha1) < 0) {
		ret = -1;
		close(fd);
		goto out;
	}
	dprintf("oid: %"PRIx64"\n", entry->raw.oid);
out:
	strbuf_release(&buf);
	return ret;
}

static inline int trunk_entry_no_sha1(struct trunk_entry_incore *entry)
{
	return !strlen((char *)entry->raw.sha1);
}

static inline void put_entry(struct trunk_entry_incore *entry)
{
	hlist_del(&entry->hash);
	pthread_mutex_lock(&active_list_lock);
	list_del(&entry->active_list);
	trunk_entry_active_nr--;
	pthread_mutex_unlock(&active_list_lock);
	free(entry);
}

int trunk_file_write(unsigned char *outsha1, int user)
{
	struct strbuf buf;
	uint64_t data_size = sizeof(struct trunk_entry) * trunk_entry_active_nr;
	struct sha1_file_hdr hdr = { .size = data_size,
				     .priv = trunk_entry_active_nr };
	struct trunk_entry_incore *entry, *t;
	int ret = 0;

	memcpy(hdr.tag, TAG_TRUNK, TAG_LEN);
	strbuf_init(&buf, sizeof(hdr) + data_size);

	strbuf_add(&buf, &hdr, sizeof(hdr));
	list_for_each_entry_safe(entry, t, &trunk_active_list, active_list) {
		if (trunk_entry_no_sha1(entry) || trunk_entry_is_dirty(entry)) {
			if (fill_entry_new_sha1(entry) < 0) {
				ret = -1;
				goto out;
			}
		}
		strbuf_add(&buf, &entry->raw, sizeof(struct trunk_entry));
		undirty_trunk_entry(entry);
	}
	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		ret = -1;
		goto out;
	}
	dprintf("trunk sha1: %s\n", sha1_to_hex(outsha1));
out:
	strbuf_release(&buf);
	return ret;
}

void *trunk_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr)
{
	void *buffer;

	dprintf("%s\n", sha1_to_hex(sha1));
	buffer = sha1_file_read(sha1, outhdr);
	if (!buffer)
		return NULL;
	if (strcmp(outhdr->tag, TAG_TRUNK) != 0) {
		free(buffer);
		return NULL;
	}

	return buffer;
}

int trunk_update_entry(uint64_t oid)
{
	struct trunk_entry_incore *entry;

	entry = lookup_trunk_entry(oid, 1);
	if (!trunk_entry_is_dirty(entry))
		dirty_trunk_entry(entry);

	return 0;
}

void trunk_reset(void)
{
	struct trunk_entry_incore *entry, *t;
	list_for_each_entry_safe(entry, t, &trunk_active_list, active_list) {
	/* This is supposed to be called by format operation, so no lock needed */
		put_entry(entry);
	}
	eprintf("%s\n", trunk_entry_active_nr ? "WARN: active_list not clean" :
						"clean");
}
