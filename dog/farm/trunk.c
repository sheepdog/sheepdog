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

static uint64_t total_count;

int trunk_file_write(uint64_t nr_entries, struct trunk_entry *entries,
		     unsigned char *trunk_sha1)
{
	size_t size = sizeof(struct trunk_entry) * nr_entries;
	return sha1_file_write(entries, size, trunk_sha1);
}

static struct trunk_file *trunk_file_read(unsigned char *sha1)
{
	size_t size;
	struct trunk_file *trunk = NULL;
	void *buf = sha1_file_read(sha1, &size);

	if (!buf)
		return NULL;
	trunk = xmalloc(sizeof(struct trunk_file));
	trunk->nr_entries = size / sizeof(struct trunk_entry);
	trunk->entries = buf;

	return trunk;
}

int for_each_entry_in_trunk(unsigned char *trunk_sha1,
			    int (*func)(struct trunk_entry *entry, void *data),
			    void *data)
{
	struct trunk_file *trunk;
	struct trunk_entry *entry;
	int ret = -1;

	trunk = trunk_file_read(trunk_sha1);
	if (!trunk)
		goto out;

	total_count = trunk->nr_entries;
	entry = trunk->entries;
	for (uint64_t i = 0; i < trunk->nr_entries; i++, entry++) {
		if (func(entry, data) < 0)
			goto out;
	}

	ret = 0;
out:
	free(trunk->entries);
	free(trunk);
	return ret;
}

uint64_t trunk_get_count(void)
{
	return total_count;
}
