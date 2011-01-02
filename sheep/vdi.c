/*
 * Copyright (C) 2009-2010 Nippon Telegraph and Telephone Corporation.
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
#include "sheep_priv.h"


/* TODO: should be performed atomically */
static int create_vdi_obj(uint32_t epoch, char *name, uint32_t new_vid, uint64_t size,
			  uint32_t base_vid, uint32_t cur_vid, uint32_t copies,
			  uint32_t snapid, int is_snapshot)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	/* we are not called concurrently */
	static struct sheepdog_inode new, base, cur;
	struct timeval tv;
	int ret, nr_nodes;
	unsigned long block_size = SD_DATA_OBJ_SIZE;

	nr_nodes = get_ordered_sd_node_list(entries);

	if (base_vid) {
		ret = read_object(entries, nr_nodes, epoch,
				  vid_to_vdi_oid(base_vid), (char *)&base,
				  sizeof(base), 0, copies);
		if (ret < 0)
			return SD_RES_BASE_VDI_READ;
	}

	gettimeofday(&tv, NULL);

	if (is_snapshot) {
		if (cur_vid != base_vid) {
			vprintf(SDOG_INFO "tree snapshot %s %" PRIx32 " %" PRIx32 "\n",
				name, cur_vid, base_vid);

			ret = read_object(entries, nr_nodes, epoch,
					  vid_to_vdi_oid(cur_vid), (char *)&cur,
					  sizeof(cur), 0, copies);
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
	new.vdi_id = new_vid;
	new.ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	new.vdi_size = size;
	new.copy_policy = 0;
	new.nr_copies = copies;
	new.block_size_shift = find_next_bit(&block_size, BITS_PER_LONG, 0);
	new.snap_id = snapid;

	if (base_vid) {
		int i;

		new.parent_vdi_id = base_vid;
		memcpy(new.data_vdi_id, base.data_vdi_id, sizeof(new.data_vdi_id));

		for (i = 0; i < ARRAY_SIZE(base.child_vdi_id); i++) {
			if (!base.child_vdi_id[i]) {
				base.child_vdi_id[i] = new_vid;
				break;
			}
		}

		if (i == ARRAY_SIZE(base.child_vdi_id))
			return SD_RES_NO_BASE_VDI;

	}

	if (is_snapshot && cur_vid != base_vid) {
		ret = write_object(entries, nr_nodes, epoch,
				   vid_to_vdi_oid(cur_vid), (char *)&cur,
				   sizeof(cur), 0, copies, 0);
		if (ret < 0) {
			vprintf(SDOG_ERR "failed\n");
			return SD_RES_BASE_VDI_READ;
		}
	}

	if (base_vid) {
		ret = write_object(entries, nr_nodes, epoch,
				   vid_to_vdi_oid(base_vid), (char *)&base,
				   sizeof(base), 0, copies, 0);
		if (ret < 0) {
			vprintf(SDOG_ERR "failed\n");
			return SD_RES_BASE_VDI_WRITE;
		}
	}

	ret = write_object(entries, nr_nodes, epoch,
			   vid_to_vdi_oid(new_vid), (char *)&new, sizeof(new),
			   0, copies, 1);
	if (ret < 0)
		return SD_RES_VDI_WRITE;

	return ret;
}

static int find_first_vdi(uint32_t epoch, unsigned long start, unsigned long end,
			  char *name, char *tag, uint32_t snapid, uint32_t *vid,
			  unsigned long *deleted_nr, uint32_t *next_snap)
{
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	static struct sheepdog_inode inode;
	unsigned long i;
	int nr_nodes, nr_reqs;
	int ret, vdi_found = 0;

	nr_nodes = get_ordered_sd_node_list(entries);

	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_nodes)
		nr_reqs = nr_nodes;

	for (i = start; i >= end; i--) {
		ret = read_object(entries, nr_nodes, epoch,
				  vid_to_vdi_oid(i), (char *)&inode,
				  sizeof(inode), 0, nr_reqs);
		if (ret < 0)
			return SD_RES_EIO;

		if (inode.name[0] == '\0') {
			*deleted_nr = i;
			continue; /* deleted */
		}

		if (!strncmp(inode.name, name, strlen(inode.name))) {
			vdi_found = 1;
			if (tag && tag[0] &&
			    strncmp(inode.tag, tag, sizeof(inode.tag)) != 0)
				continue;
			if (snapid && snapid != inode.snap_id)
				continue;

			*next_snap = inode.snap_id + 1;
			*vid = inode.vdi_id;
			return SD_RES_SUCCESS;
		}
	}

	if (vdi_found)
		return SD_RES_NO_TAG;

	return SD_RES_NO_VDI;
}


static int do_lookup_vdi(uint32_t epoch, char *name, int namelen, uint32_t *vid,
			 char *tag, uint32_t snapid, uint32_t *next_snapid,
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
		ret = find_first_vdi(epoch, nr - 1, start_nr, name, tag, snapid, vid,
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
			ret = find_first_vdi(epoch, nr - 1, 0, name, tag, snapid, vid,
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

int lookup_vdi(uint32_t epoch, char *data, int data_len, uint32_t *vid, uint32_t snapid)
{
	char *name = data, *tag;
	uint32_t dummy0;
	unsigned long dummy1, dummy2;

	if (data_len == SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN)
		tag = data + SD_MAX_VDI_LEN;
	else if (data_len == SD_MAX_VDI_LEN)
		tag = NULL;
	else
		return SD_RES_INVALID_PARMS;

	return do_lookup_vdi(epoch, name, strlen(name), vid, tag, snapid,
			     &dummy0, &dummy1, &dummy2);
}

int add_vdi(uint32_t epoch, char *data, int data_len, uint64_t size,
	    uint32_t *new_vid, uint32_t base_vid, uint32_t copies, int is_snapshot)
{
	uint32_t cur_vid;
	uint32_t next_snapid;
	unsigned long nr, deleted_nr = SD_NR_VDIS, right_nr = SD_NR_VDIS;
	int ret;
	char *name;

	if (data_len != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	name = data;

	ret = do_lookup_vdi(epoch, name, strlen(name), &cur_vid, NULL, 0, &next_snapid,
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

	*new_vid = nr;

	vprintf(SDOG_INFO "we create a new vdi, %d %s (%zd) %" PRIu64 ", vid: %"
		PRIx32 ", base %" PRIx32 ", cur %" PRIx32 " \n",
		is_snapshot, name, strlen(name), size, *new_vid, base_vid, cur_vid);

	if (!copies) {
		vprintf(SDOG_WARNING "qemu doesn't specify the copies... %d\n",
			sys->nr_sobjs);
		copies = sys->nr_sobjs;
	}

	ret = create_vdi_obj(epoch, name, *new_vid, size, base_vid, cur_vid, copies,
			     next_snapid, is_snapshot);

	return ret;
}

int start_deletion(uint32_t vid, uint32_t epoch);

int del_vdi(uint32_t epoch, char *data, int data_len, uint32_t *vid, uint32_t snapid)
{
	char *name = data;
	uint32_t dummy0;
	unsigned long dummy1, dummy2;
	int ret;
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes, nr_reqs;
	static struct sheepdog_inode inode;

	if (data_len != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	ret = do_lookup_vdi(epoch, name, strlen(name), vid, NULL, snapid,
			     &dummy0, &dummy1, &dummy2);
	if (ret != SD_RES_SUCCESS)
		return ret;

	nr_nodes = get_ordered_sd_node_list(entries);
	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_nodes)
		nr_reqs = nr_nodes;

	ret = read_object(entries, nr_nodes, epoch,
			  vid_to_vdi_oid(*vid), (char *)&inode, sizeof(inode), 0,
			  nr_reqs);
	if (ret < 0)
		return SD_RES_EIO;

	memset(inode.name, 0, sizeof(inode.name));

	ret = write_object(entries, nr_nodes, epoch,
			   vid_to_vdi_oid(*vid), (char *)&inode, sizeof(inode), 0,
			   nr_reqs, 0);
	if (ret < 0)
		return SD_RES_EIO;

	ret = start_deletion(*vid, epoch);
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
	uint32_t epoch;

	struct work work;
	struct list_head dw_siblings;

	uint32_t vid;

	int count;
	char *buf;
};

static LIST_HEAD(deletion_work_list);
static int deleting;

static void delete_one(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	uint32_t vdi_id = *(((uint32_t *)dw->buf) + dw->count - dw->done - 1);
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes;
	int ret, i;
	static struct sheepdog_inode inode;

	eprintf("%d %d, %16x\n", dw->done, dw->count, vdi_id);

	/*
	 * FIXME: can't use get_ordered_sd_node_list() here since this
	 * is called in threads and not serialized with cpg_event so
	 * we can't access to epoch and sd_node_list safely.
	 */
	nr_nodes = get_ordered_sd_node_list(entries);

	ret = read_object(entries, nr_nodes, dw->epoch,
			  vid_to_vdi_oid(vdi_id), (void *)&inode, sizeof(inode),
			  0, sys->nr_sobjs);

	if (ret != sizeof(inode)) {
		eprintf("cannot find vdi object\n");
		return;
	}

	for (i = 0; i < MAX_DATA_OBJS; i++) {
		if (!inode.data_vdi_id[i])
			continue;

		remove_object(entries, nr_nodes, dw->epoch,
			      vid_to_data_oid(inode.data_vdi_id[i], i),
			      inode.nr_copies);
	}
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
			 int nr_entries, uint32_t root_vid)
{
	int ret, i;
	static struct sheepdog_inode inode;
	int done = dw->count;
	uint32_t vid;

	((uint32_t *)dw->buf)[dw->count++] = root_vid;
again:
	vid = ((uint32_t *)dw->buf)[done++];
	ret = read_object(entries, nr_entries, dw->epoch,
			  vid_to_vdi_oid(vid), (void *)&inode, sizeof(inode),
			  0, nr_entries);

	if (ret != sizeof(inode)) {
		eprintf("cannot find vdi object\n");
		return 0;
	}

	if (inode.name[0] != '\0')
		return 1;

	for (i = 0; i < ARRAY_SIZE(inode.child_vdi_id); i++) {
		if (!inode.child_vdi_id[i])
			continue;

		((uint32_t *)dw->buf)[dw->count++] = inode.child_vdi_id[i];
	}

	if (((uint32_t *)dw->buf)[done])
		goto again;

	return 0;
}

static uint64_t get_vdi_root(struct sheepdog_node_list_entry *entries,
			     int nr_entries, uint32_t epoch, uint32_t vid)
{
	int ret;
	static struct sheepdog_inode inode;

next:
	ret = read_object(entries, nr_entries, epoch,
			  vid_to_vdi_oid(vid),
			  (void *)&inode, sizeof(inode), 0, nr_entries);

	if (ret != sizeof(inode)) {
		eprintf("cannot find vdi object\n");
		return 0;
	}

	if (!inode.parent_vdi_id)
		return vid;

	vid = inode.parent_vdi_id;

	goto next;
}

static void __start_deletion(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	struct sheepdog_node_list_entry entries[SD_MAX_NODES];
	int nr_nodes, ret;
	uint32_t root_vid;

	nr_nodes = get_ordered_sd_node_list(entries);

	root_vid = get_vdi_root(entries, nr_nodes, dw->epoch, dw->vid);
	if (!root_vid)
		goto fail;

	ret = fill_vdi_list(dw, entries, nr_nodes, root_vid);
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

int start_deletion(uint32_t vid, uint32_t epoch)
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
	dw->vid = vid;
	dw->epoch = epoch;

	dw->work.fn = __start_deletion;
	dw->work.done = __start_deletion_done;

	list_add_tail(&dw->dw_siblings, &deletion_work_list);

	if (!deleting) {
		deleting++;
		queue_work(&dw->work);
	}

	return 0;
}
