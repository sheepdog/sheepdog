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

	nr_nodes = get_ordered_sd_node_list(entries);

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

	nr_nodes = get_ordered_sd_node_list(entries);

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

int del_vdi(char *data, int data_len, uint32_t snapid)
{
	char *name = data;
	uint64_t oid;
	uint32_t dummy0;
	unsigned long dummy1, dummy2;
	int ret;
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes, nr_reqs;
	static struct sheepdog_inode inode;

	if (data_len != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	ret = do_lookup_vdi(name, strlen(name), &oid, snapid,
			     &dummy0, &dummy1, &dummy2);
	if (ret != SD_RES_SUCCESS)
		return ret;

	nr_nodes = get_ordered_sd_node_list(entries);
	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_nodes)
		nr_reqs = nr_nodes;

	ret = read_object(entries, nr_nodes, sys->epoch,
			  oid, (char *)&inode, sizeof(inode), 0,
			  nr_reqs);
	if (ret < 0)
		return SD_RES_EIO;

	memset(inode.name, 0, sizeof(inode.name));

	ret = write_object(entries, nr_nodes, sys->epoch,
			  oid, (char *)&inode, sizeof(inode), 0,
			   nr_reqs, 0);
	if (ret < 0)
		return SD_RES_EIO;

	ret = start_deletion(oid);
	if (ret < 0)
		return SD_RES_NO_MEM;

	return SD_RES_SUCCESS;
}

int read_vdis(char *data, int len, unsigned int *rsp_len)
{
	if (len != sizeof(sys->vdi_inuse))
		return SD_RES_INVALID_PARMS;

	memcpy(data, sys->vdi_inuse, sizeof(sys->vdi_inuse));
	*rsp_len = sizeof(sys->vdi_inuse);

	return SD_RES_SUCCESS;
}

struct deletion_work {
	uint32_t done;

	struct work work;
	struct list_head dw_siblings;

	uint64_t oid;

	int count;
	char *buf;
};

static LIST_HEAD(deletion_work_list);
static int deleting;

static void delete_one(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	uint64_t vdi_oid = *(((uint64_t *)dw->buf) + dw->count - dw->done - 1);
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes;
	int ret, i;
	static struct sheepdog_inode inode;

	eprintf("%d %d, %16lx\n", dw->done, dw->count, vdi_oid);

	nr_nodes = get_ordered_sd_node_list(entries);

	ret = read_object(entries, nr_nodes, sys->epoch,
			  vdi_oid, (void *)&inode, sizeof(inode), 0, sys->nr_sobjs);

	if (ret != sizeof(inode)) {
		eprintf("cannot find vdi object\n");
		return;
	}

	for (i = 0; i < MAX_DATA_OBJS; i++) {
		if (!inode.data_oid[i])
			continue;

		remove_object(entries, nr_nodes, sys->epoch,
			      inode.data_oid[i], inode.nr_copies);
	}

	if (remove_object(entries, nr_nodes, sys->epoch, vdi_oid, sys->nr_sobjs))
		eprintf("failed to remove vdi objects %lx\n", vdi_oid);
}

static void __start_deletion(struct work *work, int idx);
static void __start_deletion_done(struct work *work, int idx);

static void delete_one_done(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);

	dw->done++;
	if (dw->done < dw->count) {
		queue_work(&dw->work);
		return;
	}

	deleting--;

	list_del(&dw->dw_siblings);

	free(dw->buf);
	free(dw);

	if (!list_empty(&deletion_work_list)) {
		dw = list_first_entry(&deletion_work_list,
				      struct deletion_work, dw_siblings);

		deleting++;
		queue_work(&dw->work);
	}
}

static int fill_vdi_list(struct deletion_work *dw,
			 struct sheepdog_node_list_entry *entries,
			 int nr_entries, uint64_t root_oid)
{
	int ret, i;
	static struct sheepdog_inode inode;
	int done = dw->count;
	uint64_t oid;

	((uint64_t *)dw->buf)[dw->count++] = root_oid;
again:
	oid = ((uint64_t *)dw->buf)[done++];
	ret = read_object(entries, nr_entries, sys->epoch,
			  oid, (void *)&inode, sizeof(inode), 0, nr_entries);

	if (ret != sizeof(inode)) {
		eprintf("cannot find vdi object\n");
		return 0;
	}

	if (inode.name[0] != '\0')
		return 1;

	for (i = 0; i < ARRAY_SIZE(inode.child_oid); i++) {
		if (!inode.child_oid[i])
			continue;

		((uint64_t *)dw->buf)[dw->count++] = inode.child_oid[i];
	}

	if (((uint64_t *)dw->buf)[done])
		goto again;

	return 0;
}

static uint64_t get_vdi_root(struct sheepdog_node_list_entry *entries,
			     int nr_entries, uint64_t oid)
{
	int ret;
	static struct sheepdog_inode inode;

next:
	ret = read_object(entries, nr_entries, sys->epoch, oid,
			  (void *)&inode, sizeof(inode), 0, nr_entries);

	if (ret != sizeof(inode)) {
		eprintf("cannot find vdi object\n");
		return 0;
	}

	if (!inode.parent_oid)
		return oid;

	oid = inode.parent_oid;

	goto next;
}

static void __start_deletion(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes, ret;
	uint64_t root_oid;

	nr_nodes = get_ordered_sd_node_list(entries);

	root_oid = get_vdi_root(entries, nr_nodes, dw->oid);
	if (!root_oid)
		goto fail;

	ret = fill_vdi_list(dw, entries, nr_nodes, root_oid);
	if (ret)
		goto fail;

	return;

fail:
	dw->count = 0;
	return;
}

static void __start_deletion_done(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);

	dprintf("%d\n", dw->count);

	if (dw->count) {
		dw->work.fn = delete_one;
		dw->work.done = delete_one_done;

		queue_work(&dw->work);
		return;
	}

	deleting--;

	list_del(&dw->dw_siblings);

	free(dw->buf);
	free(dw);

	if (!list_empty(&deletion_work_list)) {
		dw = list_first_entry(&deletion_work_list,
				      struct deletion_work, dw_siblings);

		deleting++;
		queue_work(&dw->work);
	}
}

int start_deletion(uint64_t oid)
{
	struct deletion_work *dw;

	dw = zalloc(sizeof(struct deletion_work));
	if (!dw)
		return -1;

	dw->buf = zalloc(1 << 20); /* FIXME: handle larger buffer */
	if (!dw->buf) {
		free(dw);
		return -1;
	}

	dw->count = 0;
	dw->oid = oid;

	dw->work.fn = __start_deletion;
	dw->work.done = __start_deletion_done;

	list_add_tail(&dw->dw_siblings, &deletion_work_list);

	if (!deleting) {
		deleting++;
		queue_work(&dw->work);
	}

	return 0;
}
