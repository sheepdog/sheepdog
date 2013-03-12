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
	strbuf_addstr(&buf, get_object_path(entry->oid));
	strbuf_addf(&buf, "/%016" PRIx64, entry->oid);
	fd = open(buf.buf, O_RDONLY);
	if (fd < 0) {
		sd_dprintf("%m, %s", buf.buf);
		ret = -1;
		goto out;
	}
	strbuf_reset(&buf);
	if (!strbuf_read(&buf, fd, SD_DATA_OBJ_SIZE) == SD_DATA_OBJ_SIZE) {
		sd_dprintf("strbuf_read fail to read full");
		ret = -1;
		goto out_close;
	}
	hdr.size = buf.len;
	strbuf_insert(&buf, 0, &hdr, sizeof(hdr));

	if (sha1_file_write((void *)buf.buf, buf.len, entry->sha1) < 0) {
		ret = -1;
		goto out_close;
	}
	sd_dprintf("data sha1:%s, %"PRIx64, sha1_to_hex(entry->sha1),
		   entry->oid);
out_close:
	close(fd);
out:
	strbuf_release(&buf);
	return ret;
}

static int inc_object_nr(uint64_t oid, char *wd, void *arg)
{
	uint64_t *object_nr = arg;

	(*object_nr)++;

	return SD_RES_SUCCESS;
}

static int init_trunk_entry(uint64_t oid, char *path, void *arg)
{
	struct trunk_entry entry = {};
	struct strbuf *buf = arg;

	entry.oid = oid;
	if (fill_entry_new_sha1(&entry) < 0)
		return SD_RES_UNKNOWN;

	strbuf_add(buf, &entry, sizeof(struct trunk_entry));
	return SD_RES_SUCCESS;
}

int trunk_file_write(unsigned char *outsha1)
{
	struct strbuf buf;
	struct sha1_file_hdr hdr = {};
	uint64_t data_size, object_nr = 0;
	int ret = 0;

	/* Add the hdr first */
	for_each_object_in_wd(inc_object_nr, false, &object_nr);
	if (ret != SD_RES_SUCCESS) {
		ret = -1;
		goto out;
	}
	data_size = sizeof(struct trunk_entry) * object_nr;
	hdr.size = data_size;
	hdr.priv = object_nr;
	memcpy(hdr.tag, TAG_TRUNK, TAG_LEN);
	strbuf_init(&buf, sizeof(hdr) + data_size);
	strbuf_add(&buf, &hdr, sizeof(hdr));

	ret = for_each_object_in_wd(init_trunk_entry, false,  &buf);
	if (ret != SD_RES_SUCCESS) {
		ret = -1;
		goto out;
	}

	if (sha1_file_write((void *)buf.buf, buf.len, outsha1) < 0) {
		ret = -1;
		goto out;
	}
	sd_dprintf("trunk sha1: %s", sha1_to_hex(outsha1));
out:
	strbuf_release(&buf);
	return ret;
}

void *trunk_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr)
{
	void *buffer;

	sd_dprintf("%s", sha1_to_hex(sha1));
	buffer = sha1_file_read(sha1, outhdr);
	if (!buffer)
		return NULL;
	if (strcmp(outhdr->tag, TAG_TRUNK) != 0) {
		free(buffer);
		return NULL;
	}

	return buffer;
}
