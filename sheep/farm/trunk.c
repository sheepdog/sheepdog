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
 * at the time of snapshot being taken. It ties data objects together into a
 * flat directory structure.
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

static int fill_entry_new_sha1(struct trunk_entry *entry)
{
	struct strbuf buf = STRBUF_INIT;
	int fd, ret = 0;
	struct sha1_file_hdr hdr = { .priv = 0 };

	memcpy(hdr.tag, TAG_DATA, TAG_LEN);
	strbuf_addstr(&buf, obj_path);
	strbuf_addf(&buf, "%016" PRIx64, entry->oid);
	fd = open(buf.buf, O_RDONLY);
	strbuf_reset(&buf);

	if (fd < 0) {
		dprintf("%m\n");
		ret = -1;
		goto out;
	}
	if (!strbuf_read(&buf, fd, SD_DATA_OBJ_SIZE) == SD_DATA_OBJ_SIZE) {
		dprintf("strbuf_read fail to read full\n");
		ret = -1;
		goto out_close;
	}
	hdr.size = buf.len;
	strbuf_insert(&buf, 0, &hdr, sizeof(hdr));

	if (sha1_file_write((void *)buf.buf, buf.len, entry->sha1) < 0) {
		ret = -1;
		goto out_close;
	}
	dprintf("data sha1:%s, %"PRIx64"\n", sha1_to_hex(entry->sha1),
		entry->oid);
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int inc_object_nr(uint64_t oid, void *arg)
{
	uint64_t *object_nr = arg;

	(*object_nr)++;

	return 0;
}

int trunk_file_write(unsigned char *outsha1)
{
	struct strbuf buf;
	struct sha1_file_hdr hdr = {};
	struct trunk_entry entry = {};
	struct dirent *d;
	DIR *dir;
	uint64_t data_size, oid, object_nr = 0;
	int ret = 0;

	/* Add the hdr first */
	for_each_object_in_wd(inc_object_nr, false, &object_nr);
	data_size = sizeof(struct trunk_entry) * object_nr;
	hdr.size = data_size;
	hdr.priv = object_nr;
	memcpy(hdr.tag, TAG_TRUNK, TAG_LEN);
	strbuf_init(&buf, sizeof(hdr) + data_size);
	strbuf_add(&buf, &hdr, sizeof(hdr));

	dir = opendir(obj_path);
	if (!dir) {
		ret = -1;
		goto out;
	}

	while ((d = readdir(dir))) {
		if (!strncmp(d->d_name, ".", 1))
			continue;

		oid = strtoull(d->d_name, NULL, 16);
		if (oid == 0 || oid == ULLONG_MAX)
			continue;

		entry.oid = oid;
		if (fill_entry_new_sha1(&entry) < 0) {
			ret = -1;
			goto out;
		}
		strbuf_add(&buf, &entry, sizeof(struct trunk_entry));
	}

	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		ret = -1;
		goto out;
	}
	dprintf("trunk sha1: %s\n", sha1_to_hex(outsha1));
out:
	closedir(dir);
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
