/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
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
#include <sys/time.h>
#include <openssl/sha.h>

#include "sheepdog_proto.h"
#include "meta.h"
#include "collie.h"

static int sheepdog_match(struct sheepdog_dir_entry *ent, char *name, int len)
{
	if (!ent->name_len)
		return 0;
	if (ent->name_len != len)
		return 0;
	return !memcmp(ent->name, name, len);
}

/* TODO: should be performed atomically */
static int create_inode_obj(struct sheepdog_node_list_entry *entries,
			    int nr_nodes, uint64_t epoch, int copies,
			    uint64_t oid, uint64_t size, uint64_t base_oid)
{
	struct sheepdog_inode inode, base;
	struct timeval tv;
	int ret;

	if (base_oid) {
		ret = read_object(entries, nr_nodes, epoch,
				  base_oid, (char *)&base, sizeof(base), 0,
				  copies);
		if (ret < 0)
			return SD_RES_BASE_VDI_READ;
	}

	gettimeofday(&tv, NULL);

	memset(&inode, 0, sizeof(inode));

	inode.oid = oid;
	inode.vdi_size = size;
	inode.block_size = SD_DATA_OBJ_SIZE;
	inode.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	inode.nr_copies = copies;

	if (base_oid) {
		int i;

		eprintf("%zd %zd\n", sizeof(inode.data_oid),
			ARRAY_SIZE(base.child_oid));
		inode.parent_oid = base_oid;
		memcpy(inode.data_oid, base.data_oid,
		       MAX_DATA_OBJS * sizeof(uint64_t));

		for (i = 0; i < ARRAY_SIZE(base.child_oid); i++) {
			if (!base.child_oid[i]) {
				base.child_oid[i] = oid;
				break;
			}
		}

		if (i == ARRAY_SIZE(base.child_oid))
			return SD_RES_NO_BASE_VDI;

		ret = write_object(entries, nr_nodes,
				   epoch, base_oid, (char *)&base,
				   sizeof(base), 0, copies, 0);
		if (ret < 0)
			return SD_RES_BASE_VDI_WRITE;
	}

	ret = write_object(entries, nr_nodes, epoch,
			   oid, (char *)&inode, sizeof(inode), 0, copies, 1);
	if (ret < 0)
		return SD_RES_VDI_WRITE;

	return ret;
}

#define DIR_BUF_LEN (UINT64_C(1) << 20)

/*
 * TODO: handle larger buffer
 */
int add_vdi(struct cluster_info *cluster, char *name, int len, uint64_t size,
	    uint64_t *added_oid, uint64_t base_oid, uint32_t tag)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes;
	struct sheepdog_dir_entry *prv, *ent;
	uint64_t oid = 0;
	char *buf;
	int ret, rest;
	struct sheepdog_super_block *sb;
	int copies;

	nr_nodes = build_node_list(&cluster->node_list, entries);

	eprintf("%s (%d) %" PRIu64 ", base: %" PRIu64 "\n", name, len, size,
		base_oid);

	buf = zalloc(DIR_BUF_LEN);
	if (!buf)
		return 1;

	ret = read_object(entries, nr_nodes, cluster->epoch,
			  SD_DIR_OID, buf, DIR_BUF_LEN, 0, nr_nodes);
	if (ret < 0) {
		ret = SD_RES_DIR_READ;
		goto out;
	}

	sb = (struct sheepdog_super_block *)buf;
	copies = sb->default_nr_copies;

	ret = read_object(entries, nr_nodes, cluster->epoch,
			  SD_DIR_OID, buf, DIR_BUF_LEN, sizeof(*sb), nr_nodes);
	if (ret < 0) {
		ret = SD_RES_DIR_READ;
		goto out;
	}

	ent = (struct sheepdog_dir_entry *)buf;
	rest = ret;
	while (rest > 0) {
		if (!ent->name_len)
			break;

		if (sheepdog_match(ent, name, len) && !tag) {
			ret = SD_RES_VDI_EXIST;
			goto out;
		}
		oid = ent->oid;
		prv = ent;
		ent = next_entry(prv);
		rest -= ((char *)ent - (char *)prv);
	}

	/* need to check if the buffer is large enough here. */
	oid += (1 << 18);

	ret = create_inode_obj(entries, nr_nodes, cluster->epoch, copies,
			       oid, size, base_oid);
	if (ret)
		goto out;

	ent->oid = oid;
	ent->tag = tag;

	ent->flags = FLAG_CURRENT;
	ent->name_len = len;
	memcpy(ent->name, name, len);

	if (tag) {
		struct sheepdog_dir_entry *e = (struct sheepdog_dir_entry *)buf;

		while (e < ent) {
			if (sheepdog_match(e, name, len))
				e->flags &= ~FLAG_CURRENT;
			e = next_entry(e);
		}
	}

	ent = next_entry(ent);

	ret = write_object(entries, nr_nodes, cluster->epoch,
			   SD_DIR_OID, buf, (char *)ent - buf, sizeof(*sb),
			   copies, 0);
	if (ret) {
		ret = SD_RES_DIR_WRITE;
		goto out;
	}

	*added_oid = oid;
out:
	free(buf);

	return ret;
}

int del_vdi(struct cluster_info *cluster, char *name, int len)
{
	return 0;
}

int lookup_vdi(struct cluster_info *cluster,
	       char *filename, uint64_t * oid, uint32_t tag, int do_lock,
	       int *current)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes;
	int rest, ret;
	char *buf;
	struct sheepdog_dir_entry *prv, *ent;

	nr_nodes = build_node_list(&cluster->node_list, entries);

	*current = 0;
	buf = zalloc(DIR_BUF_LEN);
	if (!buf)
		return 1;

	ret = read_object(entries, nr_nodes, cluster->epoch,
			  SD_DIR_OID, buf, DIR_BUF_LEN,
			  sizeof(struct sheepdog_super_block), nr_nodes);
	if (ret < 0) {
		ret = SD_RES_DIR_READ;
		goto out;
	}

	eprintf("looking for %s %zd, %d\n", filename, strlen(filename), ret);

	ent = (struct sheepdog_dir_entry *)buf;
	rest = ret;
	ret = SD_RES_NO_VDI;
	while (rest > 0) {
		if (!ent->name_len)
			break;

		eprintf("%s %d %" PRIu64 "\n", ent->name, ent->name_len,
			ent->oid);

		if (sheepdog_match(ent, filename, strlen(filename))) {
			if (ent->tag != tag && tag != -1) {
				ret = SD_RES_NO_TAG;
				goto next;
			}
			if (ent->tag != tag && !(ent->flags & FLAG_CURRENT)) {
				/* current vdi must exsit */
				ret = SD_RES_SYSTEM_ERROR;
				goto next;
			}

			*oid = ent->oid;
			ret = 0;

			if (ent->flags & FLAG_CURRENT)
				*current = 1;
			break;
		}
next:
		prv = ent;
		ent = next_entry(prv);
		rest -= ((char *)ent - (char *)prv);
	}
out:
	free(buf);
	return ret;
}
