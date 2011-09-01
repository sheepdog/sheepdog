/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
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
	struct sheepdog_vnode_list_entry *entries;
	/* we are not called concurrently */
	struct sheepdog_inode *new = NULL, *base = NULL, *cur = NULL;
	struct timeval tv;
	int ret, nr_vnodes, nr_zones;
	unsigned long block_size = SD_DATA_OBJ_SIZE;

	entries = malloc(sizeof(*entries) * SD_MAX_VNODES);
	if (!entries) {
		eprintf("oom\n");
		ret = SD_RES_NO_MEM;
		goto out;
	}

	new = zalloc(sizeof(*new));
	if (!new) {
		eprintf("oom\n");
		ret = SD_RES_NO_MEM;
		goto out;
	}

	if (base_vid) {
		base = zalloc(sizeof(*base));
		if (!base) {
			eprintf("oom\n");
			ret = SD_RES_NO_MEM;
			goto out;
		}
	}

	if (is_snapshot && cur_vid != base_vid) {
		cur = zalloc(SD_INODE_HEADER_SIZE);
		if (!cur) {
			eprintf("oom\n");
			ret = SD_RES_NO_MEM;
			goto out;
		}
	}

	get_ordered_sd_vnode_list(entries, &nr_vnodes, &nr_zones);

	if (base_vid) {
		ret = read_object(entries, nr_vnodes, nr_zones, epoch,
				  vid_to_vdi_oid(base_vid), (char *)base,
				  sizeof(*base), 0, copies);
		if (ret < 0) {
			ret = SD_RES_BASE_VDI_READ;
			goto out;
		}
	}

	gettimeofday(&tv, NULL);

	if (is_snapshot) {
		if (cur_vid != base_vid) {
			vprintf(SDOG_INFO "tree snapshot %s %" PRIx32 " %" PRIx32 "\n",
				name, cur_vid, base_vid);

			ret = read_object(entries, nr_vnodes, nr_zones, epoch,
					  vid_to_vdi_oid(cur_vid), (char *)cur,
					  SD_INODE_HEADER_SIZE, 0, copies);
			if (ret < 0) {
				vprintf(SDOG_ERR "failed\n");
				ret = SD_RES_BASE_VDI_READ;
				goto out;
			}

			cur->snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
		} else
			base->snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	}

	strncpy(new->name, name, sizeof(new->name));
	new->vdi_id = new_vid;
	new->ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	new->vdi_size = size;
	new->copy_policy = 0;
	new->nr_copies = copies;
	new->block_size_shift = find_next_bit(&block_size, BITS_PER_LONG, 0);
	new->snap_id = snapid;

	if (base_vid) {
		int i;

		new->parent_vdi_id = base_vid;
		memcpy(new->data_vdi_id, base->data_vdi_id, sizeof(new->data_vdi_id));

		for (i = 0; i < ARRAY_SIZE(base->child_vdi_id); i++) {
			if (!base->child_vdi_id[i]) {
				base->child_vdi_id[i] = new_vid;
				break;
			}
		}

		if (i == ARRAY_SIZE(base->child_vdi_id)) {
			ret = SD_RES_NO_BASE_VDI;
			goto out;
		}
	}

	if (is_snapshot && cur_vid != base_vid) {
		ret = write_object(entries, nr_vnodes, nr_zones, epoch,
				   vid_to_vdi_oid(cur_vid), (char *)cur,
				   SD_INODE_HEADER_SIZE, 0, copies, 0);
		if (ret != 0) {
			vprintf(SDOG_ERR "failed\n");
			ret = SD_RES_BASE_VDI_READ;
			goto out;
		}
	}

	if (base_vid) {
		ret = write_object(entries, nr_vnodes, nr_zones, epoch,
				   vid_to_vdi_oid(base_vid), (char *)base,
				   SD_INODE_HEADER_SIZE, 0, copies, 0);
		if (ret != 0) {
			vprintf(SDOG_ERR "failed\n");
			ret = SD_RES_BASE_VDI_WRITE;
			goto out;
		}
	}

	ret = write_object(entries, nr_vnodes, nr_zones, epoch,
			   vid_to_vdi_oid(new_vid), (char *)new, sizeof(*new),
			   0, copies, 1);
	if (ret != 0)
		ret = SD_RES_VDI_WRITE;
out:
	free(entries);
	free(new);
	free(cur);
	free(base);
	return ret;
}

static int find_first_vdi(uint32_t epoch, unsigned long start, unsigned long end,
			  char *name, char *tag, uint32_t snapid, uint32_t *vid,
			  unsigned long *deleted_nr, uint32_t *next_snap,
			  unsigned int *nr_copies)
{
	struct sheepdog_vnode_list_entry *entries;
	struct sheepdog_inode *inode = NULL;
	unsigned long i;
	int nr_vnodes, nr_zones, nr_reqs;
	int ret, vdi_found = 0;

	entries = malloc(sizeof(*entries) * SD_MAX_VNODES);
	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode || !entries) {
		eprintf("oom\n");
		ret = SD_RES_NO_MEM;
		goto out;
	}

	get_ordered_sd_vnode_list(entries, &nr_vnodes, &nr_zones);

	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_zones)
		nr_reqs = nr_zones;

	for (i = start; i >= end; i--) {
		ret = read_object(entries, nr_vnodes, nr_zones, epoch,
				  vid_to_vdi_oid(i), (char *)inode,
				  SD_INODE_HEADER_SIZE, 0, nr_reqs);
		if (ret < 0) {
			ret = SD_RES_EIO;
			goto out;
		}

		if (inode->name[0] == '\0') {
			*deleted_nr = i;
			continue; /* deleted */
		}

		if (!strncmp(inode->name, name, strlen(inode->name))) {
			vdi_found = 1;
			if (tag && tag[0] &&
			    strncmp(inode->tag, tag, sizeof(inode->tag)) != 0)
				continue;
			if (snapid && snapid != inode->snap_id)
				continue;

			*next_snap = inode->snap_id + 1;
			*vid = inode->vdi_id;
			*nr_copies = inode->nr_copies;
			ret = SD_RES_SUCCESS;
			goto out;
		}
	}

	if (vdi_found)
		ret = SD_RES_NO_TAG;
	else
		ret = SD_RES_NO_VDI;
out:
	free(inode);
	free(entries);

	return ret;
}


static int do_lookup_vdi(uint32_t epoch, char *name, int namelen, uint32_t *vid,
			 char *tag, uint32_t snapid, uint32_t *next_snapid,
			 unsigned long *right_nr,  unsigned long *deleted_nr,
			 unsigned int *nr_copies)
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
				     deleted_nr, next_snapid, nr_copies);
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
					     deleted_nr, next_snapid, nr_copies);
			if (ret == SD_RES_NO_VDI)
				; /* we need to go to the right side */
			else
				return ret;
		}

		nr = SD_NR_VDIS;
		goto right_side;
	}
}

int lookup_vdi(uint32_t epoch, char *data, int data_len, uint32_t *vid,
	       uint32_t snapid, unsigned int *nr_copies)
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
			     &dummy0, &dummy1, &dummy2, nr_copies);
}

int add_vdi(uint32_t epoch, char *data, int data_len, uint64_t size,
	    uint32_t *new_vid, uint32_t base_vid, uint32_t copies,
	    int is_snapshot, unsigned int *nr_copies)
{
	uint32_t cur_vid = 0;
	uint32_t next_snapid;
	unsigned long nr, deleted_nr = SD_NR_VDIS, right_nr = SD_NR_VDIS;
	int ret;
	char *name;

	if (data_len != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	name = data;

	ret = do_lookup_vdi(epoch, name, strlen(name), &cur_vid, NULL, 0, &next_snapid,
			    &right_nr, &deleted_nr, nr_copies);

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

int del_vdi(uint32_t epoch, char *data, int data_len, uint32_t *vid,
	    uint32_t snapid, unsigned int *nr_copies)
{
	char *name = data, *tag;
	uint32_t dummy0;
	unsigned long dummy1, dummy2;
	int ret;
	struct sheepdog_vnode_list_entry *entries;
	int nr_vnodes, nr_zones, nr_reqs;
	struct sheepdog_inode *inode = NULL;

	inode = malloc(SD_INODE_HEADER_SIZE);
	entries = malloc(sizeof(*entries) * SD_MAX_VNODES);
	if (!inode || !entries) {
		eprintf("oom\n");
		ret = SD_RES_NO_MEM;
		goto out;
	}

	if (data_len == SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN)
		tag = data + SD_MAX_VDI_LEN;
	else if (data_len == SD_MAX_VDI_LEN)
		tag = NULL;
	else {
		ret = SD_RES_INVALID_PARMS;
		goto out;
	}

	ret = do_lookup_vdi(epoch, name, strlen(name), vid, tag, snapid,
			    &dummy0, &dummy1, &dummy2, nr_copies);
	if (ret != SD_RES_SUCCESS)
		goto out;

	get_ordered_sd_vnode_list(entries, &nr_vnodes, &nr_zones);
	nr_reqs = sys->nr_sobjs;
	if (nr_reqs > nr_zones)
		nr_reqs = nr_zones;

	ret = read_object(entries, nr_vnodes, nr_zones, epoch,
			  vid_to_vdi_oid(*vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0, nr_reqs);
	if (ret < 0) {
		ret = SD_RES_EIO;
		goto out;
	}

	memset(inode->name, 0, sizeof(inode->name));

	ret = write_object(entries, nr_vnodes, nr_zones, epoch,
			   vid_to_vdi_oid(*vid), (char *)inode,
			   SD_INODE_HEADER_SIZE, 0, nr_reqs, 0);
	if (ret != 0) {
		ret = SD_RES_EIO;
		goto out;
	}

	ret = start_deletion(*vid, epoch);
out:
	free(inode);
	free(entries);

	return ret;
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

static void delete_one(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	uint32_t vdi_id = *(((uint32_t *)dw->buf) + dw->count - dw->done - 1);
	struct sheepdog_vnode_list_entry *entries;
	int nr_vnodes, nr_zones;
	int ret, i;
	struct sheepdog_inode *inode = NULL;

	eprintf("%d %d, %16x\n", dw->done, dw->count, vdi_id);

	entries = malloc(sizeof(*entries) * SD_MAX_VNODES);
	inode = malloc(sizeof(*inode));
	if (!inode || !entries) {
		eprintf("oom\n");
		goto out;
	}

	/*
	 * FIXME: can't use get_ordered_sd_node_list() here since this
	 * is called in threads and not serialized with cpg_event so
	 * we can't access to epoch and sd_node_list safely.
	 */
	get_ordered_sd_vnode_list(entries, &nr_vnodes, &nr_zones);

	ret = read_object(entries, nr_vnodes, nr_zones, dw->epoch,
			  vid_to_vdi_oid(vdi_id), (void *)inode, sizeof(*inode),
			  0, sys->nr_sobjs);

	if (ret != sizeof(*inode)) {
		eprintf("cannot find vdi object\n");
		goto out;
	}

	for (i = 0; i < MAX_DATA_OBJS; i++) {
		if (!inode->data_vdi_id[i])
			continue;

		remove_object(entries, nr_vnodes, nr_zones, dw->epoch,
			      vid_to_data_oid(inode->data_vdi_id[i], i),
			      inode->nr_copies);
	}
out:
	free(entries);
	free(inode);
}

static void delete_one_done(struct work *work, int idx)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);

	dw->done++;
	if (dw->done < dw->count) {
		queue_work(sys->deletion_wqueue, &dw->work);
		return;
	}

	list_del(&dw->dw_siblings);

	free(dw->buf);
	free(dw);

	if (!list_empty(&deletion_work_list)) {
		dw = list_first_entry(&deletion_work_list,
				      struct deletion_work, dw_siblings);

		queue_work(sys->deletion_wqueue, &dw->work);
	}
}

static int fill_vdi_list(struct deletion_work *dw,
			 struct sheepdog_vnode_list_entry *entries,
			 int nr_vnodes, int nr_zones, uint32_t root_vid)
{
	int ret, i;
	struct sheepdog_inode *inode = NULL;
	int done = dw->count;
	uint32_t vid;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		eprintf("oom\n");
		goto err;
	}

	((uint32_t *)dw->buf)[dw->count++] = root_vid;
again:
	vid = ((uint32_t *)dw->buf)[done++];
	ret = read_object(entries, nr_vnodes, nr_zones, dw->epoch,
			  vid_to_vdi_oid(vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0, sys->nr_sobjs);

	if (ret != SD_INODE_HEADER_SIZE) {
		eprintf("cannot find vdi object\n");
		goto err;
	}

	if (inode->name[0] != '\0')
		goto out;

	for (i = 0; i < ARRAY_SIZE(inode->child_vdi_id); i++) {
		if (!inode->child_vdi_id[i])
			continue;

		((uint32_t *)dw->buf)[dw->count++] = inode->child_vdi_id[i];
	}

	if (((uint32_t *)dw->buf)[done])
		goto again;
err:
	free(inode);
	return 0;
out:
	free(inode);
	return 1;
}

static uint64_t get_vdi_root(struct sheepdog_vnode_list_entry *entries,
			     int nr_vnodes, int nr_zones, uint32_t epoch,
			     uint32_t vid)
{
	int ret;
	struct sheepdog_inode *inode = NULL;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		eprintf("oom\n");
		vid = 0;
		goto out;
	}
next:
	ret = read_object(entries, nr_vnodes, nr_zones, epoch,
			  vid_to_vdi_oid(vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0, sys->nr_sobjs);

	if (ret != SD_INODE_HEADER_SIZE) {
		eprintf("cannot find vdi object\n");
		vid = 0;
		goto out;
	}

	if (!inode->parent_vdi_id)
		goto out;

	vid = inode->parent_vdi_id;

	goto next;
out:
	free(inode);

	return vid;
}

int start_deletion(uint32_t vid, uint32_t epoch)
{
	struct deletion_work *dw = NULL;
	struct sheepdog_vnode_list_entry *entries;
	int nr_vnodes, nr_zones, ret;
	uint32_t root_vid;

	entries = malloc(sizeof(*entries) * SD_MAX_VNODES);
	if (!entries) {
		eprintf("oom\n");
		ret = SD_RES_NO_MEM;
		goto err;
	}
	dw = zalloc(sizeof(struct deletion_work));
	if (!dw) {
		ret = SD_RES_NO_MEM;
		goto err;
	}

	dw->buf = zalloc(1 << 20); /* FIXME: handle larger buffer */
	if (!dw->buf) {
		ret = SD_RES_NO_MEM;
		goto err;
	}

	dw->count = 0;
	dw->vid = vid;
	dw->epoch = epoch;

	dw->work.fn = delete_one;
	dw->work.done = delete_one_done;

	get_ordered_sd_vnode_list(entries, &nr_vnodes, &nr_zones);

	root_vid = get_vdi_root(entries, nr_vnodes, nr_zones, dw->epoch, dw->vid);
	if (!root_vid) {
		ret = SD_RES_EIO;
		goto err;
	}

	ret = fill_vdi_list(dw, entries, nr_vnodes, nr_zones, root_vid);
	if (ret)
		return SD_RES_SUCCESS;

	dprintf("%d\n", dw->count);

	if (dw->count == 0)
		goto out;

	if (!list_empty(&deletion_work_list)) {
		list_add_tail(&dw->dw_siblings, &deletion_work_list);
		goto out;
	}

	list_add_tail(&dw->dw_siblings, &deletion_work_list);
	queue_work(sys->deletion_wqueue, &dw->work);
out:
	free(entries);

	return SD_RES_SUCCESS;
err:
	free(entries);
	if (dw)
		free(dw->buf);
	free(dw);

	return ret;
}

int get_vdi_attr(uint32_t epoch, char *data, int data_len, uint32_t vid,
		 uint32_t *attrid, int copies, int creat, int excl)
{
	struct sheepdog_vnode_list_entry *entries;
	char attr_buf[SD_ATTR_HEADER_SIZE];
	uint64_t oid;
	uint32_t end;
	int ret, nr_zones, nr_vnodes;

	entries = malloc(sizeof(*entries) * SD_MAX_VNODES);
	if (!entries) {
		eprintf("oom\n");
		ret = SD_RES_NO_MEM;
		goto out;
	}

	if (data_len != SD_ATTR_HEADER_SIZE) {
		ret = SD_RES_INVALID_PARMS;
		goto out;
	}

	get_ordered_sd_vnode_list(entries, &nr_vnodes, &nr_zones);

	*attrid = fnv_64a_buf(data, data_len, FNV1A_64_INIT);
	*attrid &= (UINT64_C(1) << VDI_SPACE_SHIFT) - 1;

	end = *attrid - 1;
	while (*attrid != end) {
		oid = vid_to_attr_oid(vid, *attrid);
		ret = read_object(entries, nr_vnodes, nr_zones, epoch, oid, attr_buf,
				  sizeof(attr_buf), 0, copies);

		if (ret == -SD_RES_NO_OBJ && creat) {
			ret = write_object(entries, nr_vnodes, nr_zones, epoch, oid, data,
					   data_len, 0, copies, 1);
			if (ret)
				ret = SD_RES_EIO;
			else
				ret = SD_RES_SUCCESS;
			goto out;
		}

		if (ret < 0)
			return -ret;

		if (memcmp(attr_buf, data, sizeof(attr_buf)) == 0) {
			if (excl)
				ret = SD_RES_VDI_EXIST;
			else
				ret = SD_RES_SUCCESS;
			goto out;
		}

		(*attrid)++;
	}

	dprintf("there is no space for new vdis\n");
	ret = SD_RES_FULL_VDI;
out:
	free(entries);

	return ret;
}
