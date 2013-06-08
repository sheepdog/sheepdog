/*
 * Copyright (C) 2011 Taobao Inc.
 * Copyright (C) 2013 Zelin.io
 *
 * Liu Yuan <namei.unix@gmail.com>
 * Kai Zhang <kyle@zelin.io>
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

int trunk_file_write(unsigned char *trunk_sha1, struct strbuf *trunk_entries)
{
	struct strbuf buf;
	struct sha1_file_hdr hdr = {};
	uint64_t data_size, object_nr = 0;
	int ret = -1;

	/* Init trunk hdr */
	object_nr = object_tree_size();
	data_size = sizeof(struct trunk_entry) * object_nr;
	hdr.size = data_size;
	hdr.priv = object_nr;
	memcpy(hdr.tag, TAG_TRUNK, TAG_LEN);
	strbuf_init(&buf, sizeof(hdr) + data_size);
	strbuf_add(&buf, &hdr, sizeof(hdr));

	/* trunk entries */
	strbuf_addbuf(&buf, trunk_entries);

	/* write to sha1 file */
	if (sha1_file_write((void *)buf.buf, buf.len, trunk_sha1) < 0)
		goto out;

	ret = 0;
out:
	strbuf_release(&buf);
	return ret;
}

void *trunk_file_read(unsigned char *sha1, struct sha1_file_hdr *outhdr)
{
	void *buffer;

	buffer = sha1_file_read(sha1, outhdr);
	if (!buffer)
		return NULL;
	if (strcmp(outhdr->tag, TAG_TRUNK) != 0) {
		free(buffer);
		return NULL;
	}

	return buffer;
}

int for_each_entry_in_trunk(unsigned char *trunk_sha1,
			    int (*func)(struct trunk_entry *entry, void *data),
			    void *data)
{
	struct trunk_entry *trunk_entry, *trunk_free = NULL;
	struct sha1_file_hdr trunk_hdr;
	uint64_t nr_trunks;
	int ret = -1;

	trunk_free = trunk_entry = trunk_file_read(trunk_sha1, &trunk_hdr);

	if (!trunk_entry)
		goto out;

	nr_trunks = trunk_hdr.priv;
	for (uint64_t i = 0; i < nr_trunks; i++, trunk_entry++) {
		if (func(trunk_entry, data) < 0)
			goto out;
	}

	ret = 0;
out:
	free(trunk_free);
	return ret;
}
