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
#include <sys/stat.h>
#include <unistd.h>

#include "farm.h"
#include "strbuf.h"
#include "list.h"
#include "util.h"
#include "sheepdog_proto.h"
#include "sheep_priv.h"

#define TRUNK_ENTRY_DIRTY	0x00000001

#define HASH_BITS	10
#define HASH_SIZE	(1 << HASH_BITS)

static LIST_HEAD(trunk_active_list);
static pthread_mutex_t active_list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct hlist_head trunk_hashtable[HASH_SIZE];
static pthread_mutex_t hashtable_lock[HASH_SIZE] = { [0 ... HASH_SIZE - 1] = PTHREAD_MUTEX_INITIALIZER };
static unsigned int trunk_entry_active_nr;

struct omap_entry {
	uint64_t oid;
	unsigned char sha1[SHA1_LEN];
};

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
	} else
		entry = NULL;
out:
	pthread_mutex_unlock(&hashtable_lock[h]);
	return entry;
}

static int create_files(void)
{
	int fd, ret = 0;
	struct strbuf buf = STRBUF_INIT;

	strbuf_addstr(&buf, farm_dir);
	strbuf_addf(&buf, "/%s", "sys_omap");

	fd = open(buf.buf, O_CREAT | O_EXCL, 0666);
	if (fd < 0) {
		if (errno != EEXIST) {
			ret = -1;
			goto out;
		}
	}
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
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

	if (create_files() < 0)
		return -1;

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
		goto out_close;
	}
	hdr.size = buf.len;
	strbuf_insert(&buf, 0, &hdr, sizeof(hdr));

	if (sha1_file_write((void *)buf.buf, buf.len, entry->raw.sha1) < 0) {
		ret = -1;
		goto out_close;
	}
	dprintf("data sha1:%s, %"PRIx64"\n", sha1_to_hex(entry->raw.sha1),
		entry->raw.oid);
out_close:
	close(fd);
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
	int h = hash(entry->raw.oid);

	pthread_mutex_lock(&hashtable_lock[h]);
	hlist_del(&entry->hash);
	pthread_mutex_unlock(&hashtable_lock[h]);

	pthread_mutex_lock(&active_list_lock);
	list_del(&entry->active_list);
	trunk_entry_active_nr--;
	pthread_mutex_unlock(&active_list_lock);
	free(entry);
}

static int omap_file_init(struct strbuf *outbuf)
{
	int fd;
	int len = -1;
	void *buffer = NULL;
	struct strbuf buf = STRBUF_INIT;
	struct stat st;

	strbuf_addf(&buf, "%s/%s", farm_dir, "sys_omap");
	fd = open(buf.buf, O_RDONLY);
	if (fd < 0)
		goto out;

	if (fstat(fd, &st) < 0) {
		dprintf("%m\n");
		goto out_close;
	}

	len = st.st_size;
	if (len == 0)
		goto out_close;

	buffer = xmalloc(len);
	len = xread(fd, buffer, len);
	if (len != st.st_size) {
		len = -1;
		goto out_close;
	}
	strbuf_add(outbuf, buffer, len);
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	free(buffer);
	return len;
}

static int omap_file_final(struct strbuf *omap_buf)
{
	int fd, ret = -1;
	struct strbuf buf = STRBUF_INIT;

	if (omap_buf->len == 0)
		return 0;

	strbuf_addf(&buf, "%s/%s", farm_dir, "sys_omap");
	fd = open(buf.buf, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		dprintf("%m\n");
		goto out;
	}

	ret = xwrite(fd, omap_buf->buf, omap_buf->len);
	if (ret != omap_buf->len)
		ret = -1;

	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static struct omap_entry *omap_file_insert(struct strbuf *buf, struct omap_entry *new)
{
	unsigned i, nr = buf->len / sizeof(struct omap_entry);
	struct omap_entry *omap_buf = (struct omap_entry *)buf->buf;
	for (i = 0; i < nr; i++, omap_buf++)
		if (omap_buf->oid == new->oid) {
			if (memcmp(omap_buf->sha1, new->sha1, SHA1_LEN) == 0)
				return NULL;
			else {
				struct omap_entry *old = xmalloc(sizeof(*old));
				memcpy(old, omap_buf, sizeof(*old));
				memcpy(omap_buf->sha1, new->sha1, SHA1_LEN);
				return old;
			}
		}
	dprintf("oid, %"PRIx64"\n", new->oid);
	strbuf_add(buf, new, sizeof(*new));
	return NULL;
}

static int oid_stale(uint64_t oid)
{
	int i, vidx;
	struct sd_vnode *vnodes = sys->vnodes;

	for (i = 0; i < sys->nr_sobjs; i++) {
		vidx = obj_to_sheep(vnodes, sys->nr_vnodes, oid, i);
		if (is_myself(vnodes[vidx].addr, vnodes[vidx].port))
			return 0;
	}
	return 1;
}

int trunk_file_write_recovery(unsigned char *outsha1)
{
	struct trunk_entry_incore *entry, *t;
	struct strbuf buf;
	char p[PATH_MAX];
	uint64_t data_size = sizeof(struct trunk_entry) * trunk_entry_active_nr;
	struct sha1_file_hdr hdr, *h;
	int ret = -1, active_nr = 0;
	uint64_t oid;

	memcpy(hdr.tag, TAG_TRUNK, TAG_LEN);
	strbuf_init(&buf, sizeof(hdr) + data_size);
	strbuf_add(&buf, &hdr, sizeof(hdr));

	list_for_each_entry_safe(entry, t, &trunk_active_list, active_list) {
		oid = entry->raw.oid;
		if (oid_stale(oid)) {
			dprintf("stale oid %"PRIx64"\n", oid);
			if (trunk_entry_no_sha1(entry) || trunk_entry_is_dirty(entry)) {
				if (fill_entry_new_sha1(entry) < 0) {
					eprintf("write sha1 object fail.\n");
					goto out;
				}
			}

			strbuf_add(&buf, &entry->raw, sizeof(struct trunk_entry));
			active_nr++;

			snprintf(p, sizeof(p), "%s%016"PRIx64, obj_path, entry->raw.oid);
			if (unlink(p) < 0) {
				eprintf("%s:%m\n", p);
				goto out;
			}
			dprintf("remove file %"PRIx64"\n", entry->raw.oid);
			put_entry(entry);
		}
	}

	h = (struct sha1_file_hdr*)buf.buf;
	h->size = sizeof(struct trunk_entry) * active_nr;
	h->priv = active_nr;

	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		dprintf("sha1 file write fail.\n");
		goto out;
	}

	ret = SD_RES_SUCCESS;
out:
	strbuf_release(&buf);
	return ret;
}

int trunk_file_write(unsigned char *outsha1, int user)
{
	struct strbuf buf, omap_buf = STRBUF_INIT;
	uint64_t data_size = sizeof(struct trunk_entry) * trunk_entry_active_nr;
	struct sha1_file_hdr hdr = { .size = data_size,
				     .priv = trunk_entry_active_nr };
	struct trunk_entry_incore *entry, *t;
	int ret = 0;

	memcpy(hdr.tag, TAG_TRUNK, TAG_LEN);
	strbuf_init(&buf, sizeof(hdr) + data_size);
	omap_file_init(&omap_buf);

	strbuf_add(&buf, &hdr, sizeof(hdr));
	list_for_each_entry_safe(entry, t, &trunk_active_list, active_list) {
		if (trunk_entry_no_sha1(entry) || trunk_entry_is_dirty(entry)) {
			if (fill_entry_new_sha1(entry) < 0) {
				ret = -1;
				goto out;
			}
		}
		strbuf_add(&buf, &entry->raw, sizeof(struct trunk_entry));
		if (!user) {
			struct omap_entry new = { .oid = entry->raw.oid }, *old;
			memcpy(new.sha1, entry->raw.sha1, SHA1_LEN);
			old = omap_file_insert(&omap_buf, &new);
			if (old) {
				dprintf("try delete stale snapshot object %"PRIx64"\n", old->oid);
				sha1_file_try_delete(old->sha1);
				free(old);
			}
		}
		undirty_trunk_entry(entry);
	}
	if (omap_file_final(&omap_buf) < 0)
		eprintf("omap_file_final failed\n");

	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		ret = -1;
		goto out;
	}
	dprintf("trunk sha1: %s\n", sha1_to_hex(outsha1));
out:
	strbuf_release(&buf);
	strbuf_release(&omap_buf);
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

void trunk_put_entry(uint64_t oid)
{
	struct trunk_entry_incore *entry;

	entry = lookup_trunk_entry(oid, 0);
	if (entry)
		put_entry(entry);
}

void trunk_get_entry(uint64_t oid)
{
	lookup_trunk_entry(oid, 1);
}

void trunk_reset(void)
{
	struct trunk_entry_incore *entry, *t;
	list_for_each_entry_safe(entry, t, &trunk_active_list, active_list) {
		put_entry(entry);
	}
	eprintf("%s\n", trunk_entry_active_nr ? "WARN: active_list not clean" :
						"clean");
}

int trunk_get_working_objlist(uint64_t *list)
{
	int nr = 0;
	struct trunk_entry_incore *entry;

	pthread_mutex_lock(&active_list_lock);
	list_for_each_entry(entry, &trunk_active_list, active_list) {
		list[nr++] = entry->raw.oid;
	}
	pthread_mutex_unlock(&active_list_lock);

	return nr;
}
