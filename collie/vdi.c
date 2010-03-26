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
static int create_vdi_obj(char *name, uint64_t new_oid, uint64_t size,
			  uint64_t base_oid, uint64_t cur_oid, uint32_t copies,
			  uint32_t snapid, int is_snapshot)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	/* we are not called concurrently */
	static struct sheepdog_inode new, base, cur;
	struct timeval tv;
	int ret, nr_nodes;
	unsigned long block_size = SD_DATA_OBJ_SIZE;

	nr_nodes = build_node_list(&sys->sd_node_list, entries);

	if (base_oid) {
		ret = read_object(entries, nr_nodes, sys->epoch,
				  base_oid, (char *)&base, sizeof(base), 0,
				  copies);
		if (ret < 0)
			return SD_RES_BASE_VDI_READ;
	}

	gettimeofday(&tv, NULL);

	if (is_snapshot) {
		if (cur_oid != base_oid) {
			vprintf(SDOG_INFO "tree snapshot %s %" PRIx64 " %" PRIx64 "\n",
				name, cur_oid, base_oid);

			ret = read_object(entries, nr_nodes, sys->epoch,
					  cur_oid, (char *)&cur, sizeof(cur), 0,
					  copies);
			if (ret < 0) {
				vprintf(SDOG_ERR "failed\n");
				return SD_RES_BASE_VDI_READ;
			}

			cur.snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
		} else
			base.snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	}

	memset(&new, 0, sizeof(new));

	strncpy(new.name, name, sizeof(new.name));
	new.oid = new_oid;
	new.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	new.vdi_size = size;
	new.copy_policy = 0;
	new.nr_copies = copies;
	new.block_size_shift = find_next_bit(&block_size, BITS_PER_LONG, 0);
	new.snap_id = snapid;

	if (base_oid) {
		int i;

		new.parent_oid = base_oid;
		memcpy(new.data_oid, base.data_oid,
		       MAX_DATA_OBJS * sizeof(uint64_t));

		for (i = 0; i < ARRAY_SIZE(base.child_oid); i++) {
			if (!base.child_oid[i]) {
				base.child_oid[i] = new_oid;
				break;
			}
		}

		if (i == ARRAY_SIZE(base.child_oid))
			return SD_RES_NO_BASE_VDI;

	}

	if (is_snapshot && cur_oid != base_oid) {
		ret = write_object(entries, nr_nodes, sys->epoch,
				   cur_oid, (char *)&cur, sizeof(cur), 0,
				   copies, 0);
		if (ret < 0) {
			vprintf(SDOG_ERR "failed\n");
			return SD_RES_BASE_VDI_READ;
		}
	}

	if (base_oid) {
		ret = write_object(entries, nr_nodes,
				   sys->epoch, base_oid, (char *)&base,
				   sizeof(base), 0, copies, 0);
		if (ret < 0) {
			vprintf(SDOG_ERR "failed\n");
			return SD_RES_BASE_VDI_WRITE;
		}
	}

	ret = write_object(entries, nr_nodes, sys->epoch,
			   new_oid, (char *)&new, sizeof(new), 0, copies, 1);
	if (ret < 0)
		return SD_RES_VDI_WRITE;

	return ret;
}

static int find_first_vdi(unsigned long start, unsigned long end,
			  char *name, int namelen, uint32_t snapid, uint64_t *oid,
			  unsigned long *deleted_nr, uint32_t *next_snap)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	static struct sheepdog_inode inode;
	unsigned long i;
	int nr_nodes, nr_reqs;
	int ret;

	nr_nodes = build_node_list(&sys->sd_node_list, entries);

	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_nodes)
		nr_reqs = nr_nodes;

	for (i = start; i >= end; i--) {
		ret = read_object(entries, nr_nodes, sys->epoch,
				  bit_to_oid(i), (char *)&inode, sizeof(inode), 0,
				  nr_reqs);
		if (ret < 0)
			return SD_RES_EIO;

		if (inode.name[0] == '\0') {
			*deleted_nr = i;
			continue; /* deleted */
		}

		if (!strncmp(inode.name, name, strlen(inode.name))) {
			if (snapid && snapid != inode.snap_id)
				continue;

			*next_snap = inode.snap_id + 1;
			*oid = inode.oid;
			return SD_RES_SUCCESS;
		}
	}
	return SD_RES_NO_VDI;
}


static int do_lookup_vdi(char *name, int namelen, uint64_t *oid, uint32_t snapid,
			 uint32_t *next_snapid,
			 unsigned long *right_nr,  unsigned long *deleted_nr)
{
	int ret;
	unsigned long nr, start_nr;

	start_nr = fnv_64a_buf(name, namelen, FNV1A_64_INIT) & (SD_NR_VDIS - 1);

	vprintf(SDOG_INFO "looking for %s %d, %lx\n", name, namelen, start_nr);

	/* bitmap search from the hash point */
	nr = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, start_nr);
	*right_nr = nr;
	if (nr == start_nr) {
		return SD_RES_NO_VDI;
	} else if (nr < SD_NR_VDIS) {
	right_side:
		/* look up on the right side of the hash point */
		ret = find_first_vdi(nr - 1, start_nr, name, namelen, snapid, oid,
				     deleted_nr, next_snapid);
		return ret;
	} else {
		/* round up... bitmap search from the head of the bitmap */
		nr = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, 0);
		*right_nr = nr;
		if (nr >= SD_NR_VDIS)
			return SD_RES_FULL_VDI;
		else if (nr) {
			/* look up on the left side of the hash point */
			ret = find_first_vdi(nr - 1, 0, name, namelen, snapid, oid,
					     deleted_nr, next_snapid);
			if (ret == SD_RES_NO_VDI)
				; /* we need to go to the right side */
			else
				return ret;
		}

		nr = SD_NR_VDIS;
		goto right_side;
	}
}

int lookup_vdi(char *data, int data_len, uint64_t *oid, uint32_t snapid)
{
	char *name = data;
	uint32_t dummy0;
	unsigned long dummy1, dummy2;

	if (data_len != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	return do_lookup_vdi(name, strlen(name), oid, snapid,
			     &dummy0, &dummy1, &dummy2);
}

int add_vdi(char *data, int data_len, uint64_t size,
	    uint64_t *new_oid, uint64_t base_oid, uint32_t copies, int is_snapshot)
{
	uint64_t cur_oid;
	uint32_t next_snapid;
	unsigned long nr, deleted_nr = SD_NR_VDIS, right_nr = SD_NR_VDIS;
	int ret;
	char *name;

	if (data_len != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	name = data;

	ret = do_lookup_vdi(name, strlen(name), &cur_oid, 0, &next_snapid,
			    &right_nr, &deleted_nr);

	if (is_snapshot) {
		if (ret != SD_RES_SUCCESS) {
			if (ret == SD_RES_NO_VDI)
				vprintf(SDOG_CRIT "we dont's have %s\n", name);
			return ret;
		}
		nr = right_nr;
	} else {
		/* we already have the same vdi or met other errors. */
		if (ret != SD_RES_NO_VDI) {
			if (ret == SD_RES_SUCCESS)
				ret = SD_RES_VDI_EXIST;
			return ret;
		}

		if (deleted_nr == SD_NR_VDIS)
			nr = right_nr;
		else
			nr = deleted_nr; /* we can recycle a deleted vdi */

		next_snapid = 1;
	}

	*new_oid = bit_to_oid(nr);

	vprintf(SDOG_INFO "we create a new vdi, %d %s (%zd) %" PRIu64 ", oid: %"
		PRIx64 ", base %" PRIx64 ", cur %" PRIx64 " \n",
		is_snapshot, name, strlen(name), size, *new_oid, base_oid, cur_oid);

	if (!copies) {
		vprintf(SDOG_WARNING "qemu doesn't specify the copies... %d\n",
			sys->nr_sobjs);
		copies = sys->nr_sobjs;
	}

	ret = create_vdi_obj(name, *new_oid, size, base_oid, cur_oid, copies,
			     next_snapid, is_snapshot);

	return ret;
}

int del_vdi(char *name, int len)
{
	return 0;
}

int read_vdis(char *data, int len, unsigned int *rsp_len)
{
	if (len != sizeof(sys->vdi_inuse))
		return SD_RES_INVALID_PARMS;

	memcpy(data, sys->vdi_inuse, sizeof(sys->vdi_inuse));
	*rsp_len = sizeof(sys->vdi_inuse);

	return SD_RES_SUCCESS;
}
