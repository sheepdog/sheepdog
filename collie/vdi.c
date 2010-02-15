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

#include "sheepdog_proto.h"
#include "meta.h"
#include "collie.h"

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

/*
 * TODO: handle larger buffer
 */
int add_vdi(char *name, int len, uint64_t size,
	    uint64_t *added_oid, uint64_t base_oid, uint32_t tag, int copies,
	    uint16_t flags)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes, nr_reqs;
	uint64_t oid = 0;
	int ret;
	struct sd_so_req req;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&req;

	memset(&req, 0, sizeof(req));

	nr_nodes = build_node_list(&sys->node_list, entries);

	dprintf("%s (%d) %" PRIu64 ", base: %" PRIu64 "\n", name, len, size,
		base_oid);

	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_nodes)
		nr_reqs = nr_nodes;

	memset(&req, 0, sizeof(req));

	eprintf("%d %d\n", copies, sys->nr_sobjs);
	/* qemu doesn't specify the copies, then we use the default. */
	if (!copies)
		copies = sys->nr_sobjs;

	req.opcode = SD_OP_SO_NEW_VDI;
	req.copies = copies;
	req.tag = tag;
	req.flags |= flags;

	ret = exec_reqs(entries, nr_nodes, sys->epoch,
			SD_DIR_OID, (struct sd_req *)&req, name, len, 0,
			nr_reqs, nr_reqs);

	if (ret < 0)
		return rsp->result;

	oid = rsp->oid;
	*added_oid = oid;

	dprintf("%s (%d) %" PRIu64 ", base: %" PRIu64 "\n", name, len, size,
		oid);

	ret = create_inode_obj(entries, nr_nodes, sys->epoch, copies,
			       oid, size, base_oid);

	return ret;
}

int del_vdi(char *name, int len)
{
	return 0;
}

int lookup_vdi(char *filename, uint64_t * oid, uint32_t tag, int do_lock,
	       int *current)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes, nr_reqs;
	int ret;
	struct sd_so_req req;
	struct sd_so_rsp *rsp = (struct sd_so_rsp *)&req;

	memset(&req, 0, sizeof(req));

	nr_nodes = build_node_list(&sys->node_list, entries);

	*current = 0;

	dprintf("looking for %s %zd\n", filename, strlen(filename));

	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_nodes)
		nr_reqs = nr_nodes;

	memset(&req, 0, sizeof(req));

	req.opcode = SD_OP_SO_LOOKUP_VDI;
	req.tag = tag;

	ret = exec_reqs(entries, nr_nodes, sys->epoch,
			SD_DIR_OID, (struct sd_req *)&req, filename, strlen(filename), 0,
			nr_reqs, 1);

	*oid = rsp->oid;
	if (rsp->flags & SD_VDI_RSP_FLAG_CURRENT)
		*current = 1;

	dprintf("looking for %s %lx\n", filename, *oid);

	if (ret < 0)
		return rsp->result;

	return SD_RES_SUCCESS;
}

/* todo: cleanup with the above */
int make_super_object(struct sd_vdi_req *hdr)
{
	struct timeval tv;
	int nr_nodes, ret;
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	struct sd_so_req req;

	gettimeofday(&tv, NULL);
	memset(&req, 0, sizeof(req));

	req.oid = SD_DIR_OID;
	req.opcode = SD_OP_SO;
	req.ctime = (uint64_t)tv.tv_sec << 32 | tv.tv_usec * 1000;
	req.copies = ((struct sd_obj_req *)hdr)->copies;

	nr_nodes = build_node_list(&sys->node_list, entries);

	ret = exec_reqs(entries, nr_nodes, sys->epoch,
			SD_DIR_OID, (struct sd_req *)&req, NULL, 0, 0, req.copies,
			req.copies);

	if (ret < 0)
		return SD_RES_EIO;

	return SD_RES_SUCCESS;
}
