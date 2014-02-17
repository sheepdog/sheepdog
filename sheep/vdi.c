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

#include "sheep_priv.h"

struct vdi_state_entry {
	uint32_t vid;
	unsigned int nr_copies;
	bool snapshot;
	uint8_t copy_policy;
	struct rb_node node;
};

static struct rb_root vdi_state_root = RB_ROOT;
static struct sd_rw_lock vdi_state_lock = SD_RW_LOCK_INITIALIZER;

/*
 * ec_max_data_strip represent max number of data strips in the cluster. When
 * nr_zones < it, we don't purge the stale objects because for erasure coding,
 * there is only one copy of data.
 */
int ec_max_data_strip;

int sheep_bnode_writer(uint64_t oid, void *mem, unsigned int len,
		       uint64_t offset, uint32_t flags, int copies,
		       int copy_policy, bool create, bool direct)
{
	return sd_write_object(oid, mem, len, offset, create);
}

int sheep_bnode_reader(uint64_t oid, void **mem, unsigned int len,
		       uint64_t offset)
{
	return sd_read_object(oid, *mem, len, offset);
}

static int vdi_state_cmp(const struct vdi_state_entry *a,
			 const struct vdi_state_entry *b)
{
	return intcmp(a->vid, b->vid);
}

static struct vdi_state_entry *vdi_state_search(struct rb_root *root,
						uint32_t vid)
{
	struct vdi_state_entry key = { .vid = vid };

	return rb_search(root, &key, node, vdi_state_cmp);
}

static struct vdi_state_entry *vdi_state_insert(struct rb_root *root,
						struct vdi_state_entry *new)
{
	return rb_insert(root, new, node, vdi_state_cmp);
}

static bool vid_is_snapshot(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		sd_err("No VDI entry for %" PRIx32 " found", vid);
		return 0;
	}

	return entry->snapshot;
}

bool oid_is_readonly(uint64_t oid)
{
	/* we allow changing snapshot attributes */
	if (!is_data_obj(oid))
		return false;

	return vid_is_snapshot(oid_to_vid(oid));
}

int get_vdi_copy_number(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		sd_alert("copy number for %" PRIx32 " not found, set %d", vid,
			 sys->cinfo.nr_copies);
		return sys->cinfo.nr_copies;
	}

	return entry->nr_copies;
}

int get_vdi_copy_policy(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_rw_unlock(&vdi_state_lock);

	if (!entry) {
		sd_alert("copy policy for %" PRIx32 " not found, set %d", vid,
			 sys->cinfo.copy_policy);
		return sys->cinfo.copy_policy;
	}

	return entry->copy_policy;
}

int get_obj_copy_number(uint64_t oid, int nr_zones)
{
	return min(get_vdi_copy_number(oid_to_vid(oid)), nr_zones);
}

int get_req_copy_number(struct request *req)
{
	int nr_copies;

	nr_copies = min((int)req->rq.obj.copies, req->vinfo->nr_zones);
	if (!nr_copies)
		nr_copies = get_obj_copy_number(req->rq.obj.oid,
						req->vinfo->nr_zones);

	return nr_copies;
}

int add_vdi_state(uint32_t vid, int nr_copies, bool snapshot, uint8_t cp)
{
	struct vdi_state_entry *entry, *old;

	entry = xzalloc(sizeof(*entry));
	entry->vid = vid;
	entry->nr_copies = nr_copies;
	entry->snapshot = snapshot;
	entry->copy_policy = cp;

	if (cp) {
		int d;

		ec_policy_to_dp(cp, &d, NULL);
		ec_max_data_strip = max(d, ec_max_data_strip);
	}

	sd_debug("%" PRIx32 ", %d, %d", vid, nr_copies, cp);

	sd_write_lock(&vdi_state_lock);
	old = vdi_state_insert(&vdi_state_root, entry);
	if (old) {
		free(entry);
		entry = old;
		entry->nr_copies = nr_copies;
		entry->snapshot = snapshot;
		entry->copy_policy = cp;
	}

	sd_rw_unlock(&vdi_state_lock);

	return SD_RES_SUCCESS;
}

int fill_vdi_state_list(void *data)
{
	int nr = 0;
	struct vdi_state *vs = data;
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	rb_for_each_entry(entry, &vdi_state_root, node) {
		memset(vs, 0, sizeof(*vs));
		vs->vid = entry->vid;
		vs->nr_copies = entry->nr_copies;
		vs->snapshot = entry->snapshot;
		vs->copy_policy = entry->copy_policy;
		vs++;
		nr++;
	}
	sd_rw_unlock(&vdi_state_lock);

	return nr * sizeof(*vs);
}

static inline bool vdi_is_deleted(struct sd_inode *inode)
{
	return *inode->name == '\0';
}

int vdi_exist(uint32_t vid)
{
	struct sd_inode *inode;
	int ret = 1;

	inode = xzalloc(sizeof(*inode));
	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     sizeof(*inode), 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("fail to read vdi inode (%" PRIx32 ")", vid);
		ret = 0;
		goto out;
	}

	if (vdi_is_deleted(inode)) {
		ret = 0;
		goto out;
	}
	ret = 1;
out:
	free(inode);
	return ret;
}

static struct sd_inode *alloc_inode(const struct vdi_iocb *iocb,
				    uint32_t new_snapid, uint32_t new_vid,
				    uint32_t *data_vdi_id)
{
	struct sd_inode *new = xzalloc(sizeof(*new));
	unsigned long block_size = SD_DATA_OBJ_SIZE;

	pstrcpy(new->name, sizeof(new->name), iocb->name);
	new->vdi_id = new_vid;
	new->create_time = iocb->time;
	new->vdi_size = iocb->size;
	new->copy_policy = iocb->copy_policy;
	new->store_policy = iocb->store_policy;
	new->nr_copies = iocb->nr_copies;
	new->block_size_shift = find_next_bit(&block_size, BITS_PER_LONG, 0);
	new->snap_id = new_snapid;
	new->parent_vdi_id = iocb->base_vid;
	if (data_vdi_id)
		sd_inode_copy_vdis(sheep_bnode_writer, sheep_bnode_reader,
				   data_vdi_id, iocb->store_policy,
				   iocb->nr_copies, iocb->copy_policy, new);
	else if (new->store_policy)
		sd_inode_init(new->data_vdi_id, 1);

	return new;
}

/* Find the first zeroed index to be used for a child vid. */
static int find_free_idx(uint32_t *vdi_id, size_t max_idx)
{
	for (int i = 0; i < max_idx; i++) {
		if (vdi_id[i] == 0)
			return i;
	}

	return -1;
}

/* Create a fresh vdi */
static int create_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
		      uint32_t new_vid)
{
	struct sd_inode *new = alloc_inode(iocb, new_snapid, new_vid, NULL);
	int ret;

	sd_debug("%s: size %" PRIu64 ", new_vid %" PRIx32 ", copies %d, "
		 "snapid %" PRIu32 " copy policy %"PRIu8 "store policy %"PRIu8,
		 iocb->name, iocb->size, new_vid, iocb->nr_copies, new_snapid,
		 new->copy_policy, new->store_policy);

	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

	free(new);
	return ret;
}

/*
 * Create a clone vdi from the existing snapshot
 *
 * This creates a working vdi 'new' based on the snapshot 'base'.  For example:
 *
 * [before]
 *                base
 *            o----o----o----x
 *
 * [after]
 *                base
 *            o----o----o----x
 *                  \
 *                   x new
 * x: working vdi
 * o: snapshot vdi
 */
static int clone_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
		     uint32_t new_vid, uint32_t base_vid)
{
	struct sd_inode *new = NULL, *base = xzalloc(sizeof(*base));
	int ret, idx;

	sd_debug("%s: size %" PRIu64 ", vid %" PRIx32 ", base %" PRIx32 ", "
		 "copies %d, snapid %" PRIu32, iocb->name, iocb->size, new_vid,
		 base_vid, iocb->nr_copies, new_snapid);

	ret = sd_read_object(vid_to_vdi_oid(base_vid), (char *)base,
			     sizeof(*base), 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_READ;
		goto out;
	}

	idx = find_free_idx(base->child_vdi_id, ARRAY_SIZE(base->child_vdi_id));
	if (idx < 0) {
		ret = SD_RES_FULL_VDI;
		goto out;
	}

	/* TODO: multiple sd_write_object should be performed atomically */

	/* update a base vdi */
	ret = sd_write_object(vid_to_vdi_oid(base_vid), (char *)&new_vid,
			      sizeof(new_vid),
			      offsetof(struct sd_inode, child_vdi_id[idx]),
			      false);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_WRITE;
		goto out;
	}

	/* create a new vdi */
	new = alloc_inode(iocb, new_snapid, new_vid, base->data_vdi_id);
	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(base);
	return ret;
}

/*
 * Create a snapshot vdi
 *
 * This makes the current working vdi 'base' a snapshot, and create a working
 * vdi 'new'.  For example:
 *
 * [before]
 *            o----o----o----x base
 *
 * [after]
 *                          base
 *            o----o----o----o----x new
 *
 * x: working vdi
 * o: snapshot vdi
 */
static int snapshot_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
			uint32_t new_vid, uint32_t base_vid)
{
	struct sd_inode *new = NULL, *base = xzalloc(sizeof(*base));
	int ret, idx;

	sd_debug("%s: size %" PRIu64 ", vid %" PRIx32 ", base %" PRIx32 ", "
		 "copies %d, snapid %" PRIu32, iocb->name, iocb->size, new_vid,
		 base_vid, iocb->nr_copies, new_snapid);

	ret = sd_read_object(vid_to_vdi_oid(base_vid), (char *)base,
			     sizeof(*base), 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_READ;
		goto out;
	}

	idx = find_free_idx(base->child_vdi_id, ARRAY_SIZE(base->child_vdi_id));
	if (idx < 0) {
		ret = SD_RES_FULL_VDI;
		goto out;
	}

	/* TODO: multiple sd_write_object should be performed atomically */

	/* update a base vdi */
	base->snap_ctime = iocb->time;
	base->child_vdi_id[idx] = new_vid;
	ret = sd_write_object(vid_to_vdi_oid(base_vid), (char *)base,
			      SD_INODE_HEADER_SIZE, 0, false);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_WRITE;
		goto out;
	}

	/* create a new vdi */
	new = alloc_inode(iocb, new_snapid, new_vid, base->data_vdi_id);
	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(base);
	return ret;
}

/*
 * Rebase onto another snapshot vdi
 *
 * This makes the current working vdi 'base' a snapshot, and create a new
 * working vdi 'new' based on the snapshot 'base'.  We use this operation when
 * rollbacking to the snapshot or writing data to the snapshot.  Here is an
 * example:
 *
 * [before]
 *                base
 *            o----o----o----x cur
 *
 * [after]
 *                base
 *            o----o----o----o cur
 *                  \
 *                   x new
 * x: working vdi
 * o: snapshot vdi
 */
static int rebase_vdi(const struct vdi_iocb *iocb, uint32_t new_snapid,
		      uint32_t new_vid, uint32_t base_vid, uint32_t cur_vid)
{
	struct sd_inode *new = NULL, *base = xzalloc(sizeof(*base));
	int ret, idx;

	sd_debug("%s: size %" PRIu64 ", vid %" PRIx32 ", base %" PRIx32 ", "
		 "cur %" PRIx32 ", copies %d, snapid %" PRIu32, iocb->name,
		 iocb->size, new_vid, base_vid, cur_vid, iocb->nr_copies,
		 new_snapid);

	ret = sd_read_object(vid_to_vdi_oid(base_vid), (char *)base,
			     sizeof(*base), 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_READ;
		goto out;
	}

	idx = find_free_idx(base->child_vdi_id, ARRAY_SIZE(base->child_vdi_id));
	if (idx < 0) {
		ret = SD_RES_FULL_VDI;
		goto out;
	}

	/* TODO: multiple sd_write_object should be performed atomically */

	/* update current working vdi */
	ret = sd_write_object(vid_to_vdi_oid(cur_vid), (char *)&iocb->time,
			      sizeof(iocb->time),
			      offsetof(struct sd_inode, snap_ctime), false);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_VDI_WRITE;
		goto out;
	}

	/* update base vdi */
	ret = sd_write_object(vid_to_vdi_oid(base_vid), (char *)&new_vid,
			      sizeof(new_vid),
			      offsetof(struct sd_inode, child_vdi_id[idx]),
			      false);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_BASE_VDI_WRITE;
		goto out;
	}

	/* create a new vdi */
	new = alloc_inode(iocb, new_snapid, new_vid, base->data_vdi_id);
	ret = sd_write_object(vid_to_vdi_oid(new_vid), (char *)new,
			      sizeof(*new), 0, true);
	if (ret != SD_RES_SUCCESS)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(base);
	return ret;
}

/*
 * Return SUCCESS (range of bits set):
 * Iff we get a bitmap range [left, right) that VDI might be set between. if
 * right < start, this means a wrap around case where we should examine the
 * two split ranges, [left, SD_NR_VDIS - 1] and [0, right). 'Right' is the free
 * bit that might be used by newly created VDI.
 *
 * Otherwise:
 * Return NO_VDI (bit not set) or FULL_VDI (bitmap fully set)
 */
static int get_vdi_bitmap_range(const char *name, unsigned long *left,
				unsigned long *right)
{
	*left = sd_hash_vdi(name);
	*right = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, *left);
	if (*left == *right)
		return SD_RES_NO_VDI;

	if (*right == SD_NR_VDIS) {
		/* Wrap around */
		*right = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, 0);
		if (*right == SD_NR_VDIS)
			return SD_RES_FULL_VDI;
	}
	return SD_RES_SUCCESS;
}

static inline bool vdi_has_tag(const struct vdi_iocb *iocb)
{
	if ((iocb->tag && iocb->tag[0]) || iocb->snapid)
		return true;
	return false;
}

static inline bool vdi_tag_match(const struct vdi_iocb *iocb,
				 const struct sd_inode *inode)
{
	const char *tag = iocb->tag;

	if (inode->tag[0] && !strncmp(inode->tag, tag, sizeof(inode->tag)))
		return true;
	if (iocb->snapid == inode->snap_id)
		return true;
	return false;
}

static int fill_vdi_info_range(uint32_t left, uint32_t right,
			       const struct vdi_iocb *iocb,
			       struct vdi_info *info)
{
	struct sd_inode *inode;
	bool vdi_found = false;
	int ret;
	uint32_t i;
	const char *name = iocb->name;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		sd_err("failed to allocate memory");
		ret = SD_RES_NO_MEM;
		goto out;
	}
	for (i = right - 1; i >= left; i--) {
		ret = sd_read_object(vid_to_vdi_oid(i), (char *)inode,
				     SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS)
			goto out;

		if (vdi_is_deleted(inode)) {
			/* Recycle the deleted inode for fresh vdi create */
			if (!iocb->create_snapshot)
				info->free_bit = i;
			continue;
		}

		if (!strncmp(inode->name, name, sizeof(inode->name))) {
			sd_debug("%s = %s, %u = %u", iocb->tag, inode->tag,
				 iocb->snapid, inode->snap_id);
			if (vdi_has_tag(iocb)) {
				/* Read, delete, clone on snapshots */
				if (!vdi_is_snapshot(inode)) {
					vdi_found = true;
					continue;
				}
				if (!vdi_tag_match(iocb, inode))
					continue;
			} else {
				/*
				 * Rollback & snap create, read, delete on
				 * current working VDI
				 */
				info->snapid = inode->snap_id + 1;
				if (vdi_is_snapshot(inode))
					/* Current workding VDI is deleted */
					break;
			}
			info->create_time = inode->create_time;
			info->vid = inode->vdi_id;
			goto out;
		}
	}
	ret = vdi_found ? SD_RES_NO_TAG : SD_RES_NO_VDI;
out:
	free(inode);
	return ret;
}

/* Fill the VDI information from right to left in the bitmap */
static int fill_vdi_info(unsigned long left, unsigned long right,
			 const struct vdi_iocb *iocb, struct vdi_info *info)
{
	int ret;

	if (left < right)
		return fill_vdi_info_range(left, right, iocb, info);

	ret = fill_vdi_info_range(0, right, iocb, info);
	switch (ret) {
	case SD_RES_NO_VDI:
	case SD_RES_NO_TAG:
		ret = fill_vdi_info_range(left, SD_NR_VDIS - 1, iocb, info);
		break;
	default:
		break;
	}
	return ret;
}

/* Return SUCCESS if we find targeted VDI specified by iocb and fill info */
int vdi_lookup(const struct vdi_iocb *iocb, struct vdi_info *info)
{
	unsigned long left, right;
	int ret;

	ret = get_vdi_bitmap_range(iocb->name, &left, &right);
	info->free_bit = right;
	sd_debug("%s left %lx right %lx, %x", iocb->name, left, right, ret);
	switch (ret) {
	case SD_RES_NO_VDI:
	case SD_RES_FULL_VDI:
		return ret;
	case SD_RES_SUCCESS:
		break;
	}
	return fill_vdi_info(left, right, iocb, info);
}

static int notify_vdi_add(uint32_t vdi_id, uint32_t nr_copies, uint32_t old_vid,
			  uint8_t copy_policy)
{
	int ret = SD_RES_SUCCESS;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_ADD);
	hdr.vdi_state.old_vid = old_vid;
	hdr.vdi_state.new_vid = vdi_id;
	hdr.vdi_state.copies = nr_copies;
	hdr.vdi_state.set_bitmap = false;
	hdr.vdi_state.copy_policy = copy_policy;

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		sd_err("fail to notify vdi add event(%" PRIx32 ", %d, %" PRIx32
		       ")", vdi_id, nr_copies, old_vid);

	return ret;
}

static void vdi_flush(uint32_t vid)
{
	struct sd_req hdr;
	int ret;

	sd_init_req(&hdr, SD_OP_FLUSH_VDI);
	hdr.obj.oid = vid_to_vdi_oid(vid);

	ret = exec_local_req(&hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		sd_err("fail to flush vdi %" PRIx32 ", %s", vid,
		       sd_strerror(ret));
}

/*
 * This function creates another working vdi with a new name.  The parent of the
 * newly created vdi is iocb->base_vid.
 *
 * There are 2 vdi create operation in SD:
 * 1. fresh create (base_vid == 0)
 * 2. clone create (base_vid != 0)
 *
 * This function expects NO_VDI returned from vdi_lookup().  Fresh create
 * started with id = 1 when there are no snapshot with the same name.  Working
 * VDI always has the highest snapid.
 */
int vdi_create(const struct vdi_iocb *iocb, uint32_t *new_vid)
{
	struct vdi_info info = {};
	int ret;

	ret = vdi_lookup(iocb, &info);
	switch (ret) {
	case SD_RES_SUCCESS:
		return SD_RES_VDI_EXIST;
	case SD_RES_NO_VDI:
		break;
	default:
		sd_err("%s", sd_strerror(ret));
		return ret;
	}

	if (info.snapid == 0)
		info.snapid = 1;
	*new_vid = info.free_bit;
	ret = notify_vdi_add(*new_vid, iocb->nr_copies, info.vid,
			     iocb->copy_policy);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (iocb->base_vid == 0)
		return create_vdi(iocb, info.snapid, *new_vid);
	else
		return clone_vdi(iocb, info.snapid, *new_vid, iocb->base_vid);
}

/*
 * This function makes the current working vdi a snapshot, and create a new
 * working vdi with the same name.  The parent of the newly created vdi is
 * iocb->base_vid.
 *
 * There are 2 snapshot create operation in SD:
 * 1. snapshot create (base_vid == current_vid)
 * 2. rollback create (base_vid != current_vid)
 *
 * This function expects SUCCESS returned from vdi_lookup().  Both rollback and
 * snap create started with current working VDI's snap_id + 1. Working VDI
 * always has the highest snapid.
 */
int vdi_snapshot(const struct vdi_iocb *iocb, uint32_t *new_vid)
{
	struct vdi_info info = {};
	int ret;

	ret = vdi_lookup(iocb, &info);
	if (ret == SD_RES_SUCCESS) {
		if (sys->enable_object_cache)
			vdi_flush(iocb->base_vid);
	} else {
		sd_err("%s", sd_strerror(ret));
		return ret;
	}

	assert(info.snapid > 0);
	*new_vid = info.free_bit;
	ret = notify_vdi_add(*new_vid, iocb->nr_copies, info.vid,
			     iocb->copy_policy);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (iocb->base_vid == info.vid)
		return snapshot_vdi(iocb, info.snapid, *new_vid,
				    iocb->base_vid);
	else
		return rebase_vdi(iocb, info.snapid, *new_vid, iocb->base_vid,
				  info.vid);
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
	struct work work;

	uint32_t target_vid;
	int delete_vid_count;
	uint32_t *delete_vid_array;

	int finish_fd;		/* eventfd for notifying finish */
};

static int delete_inode(uint32_t vid)
{
	struct sd_inode *inode = NULL;
	int ret = SD_RES_SUCCESS;

	inode = xzalloc(sizeof(*inode));
	ret = sd_read_object(vid_to_vdi_oid(vid), (char *)inode,
			     SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_EIO;
		goto out;
	}

	memset(inode->name, 0, sizeof(inode->name));

	ret = sd_write_object(vid_to_vdi_oid(vid), (char *)inode,
			      SD_INODE_HEADER_SIZE, 0, false);
	if (ret != 0) {
		ret = SD_RES_EIO;
		goto out;
	}

out:
	free(inode);
	return ret;
}

static int notify_vdi_deletion(uint32_t vdi_id)
{
	struct sd_req hdr;
	int ret = SD_RES_SUCCESS;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_DEL);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(vdi_id);

	ret = exec_local_req(&hdr, &vdi_id);
	if (ret != SD_RES_SUCCESS)
		sd_err("fail to notify vdi deletion(%" PRIx32 "), %d", vdi_id,
		       ret);

	return ret;
}

struct delete_arg {
	const struct sd_inode *inode;
	uint32_t *nr_deleted;
};

static void delete_cb(void *data, enum btree_node_type type, void *arg)
{
	struct sd_extent *ext;
	struct delete_arg *darg = (struct delete_arg *)arg;
	uint64_t oid;
	int ret;

	if (type != BTREE_EXT)
		return;

	ext = (struct sd_extent *)data;
	if (ext->vdi_id) {
		oid = vid_to_data_oid(ext->vdi_id, ext->idx);
		if (ext->vdi_id != darg->inode->vdi_id)
			sd_debug("object %" PRIx64 " is base's data, would"
				 " not be deleted.", oid);
		else {
			ret = sd_remove_object(oid);
			if (ret != SD_RES_SUCCESS)
				sd_err("remove object %" PRIx64 " fail, %d",
				       oid, ret);
			(*(darg->nr_deleted))++;
		}
	}
}

static int delete_one_vdi(uint32_t vdi_id)
{
	int ret = 0;
	uint32_t i, nr_deleted, nr_objs;
	struct sd_inode *inode = NULL;

	inode = malloc(sizeof(*inode));
	if (!inode) {
		sd_err("failed to allocate memory");
		return -1;
	}

	ret = read_backend_object(vid_to_vdi_oid(vdi_id),
				  (void *)inode, sizeof(*inode), 0);

	if (ret != SD_RES_SUCCESS) {
		sd_err("cannot find VDI object");
		ret = -1;
		goto out;
	}

	if (inode->vdi_size == 0 && vdi_is_deleted(inode))
		goto out;

	if (inode->store_policy == 0) {
		nr_objs = count_data_objs(inode);
		for (nr_deleted = 0, i = 0; i < nr_objs; i++) {
			uint64_t oid;
			uint32_t vid = INODE_GET_VID(inode, i);

			if (!vid)
				continue;

			oid = vid_to_data_oid(vid, i);

			if (vid != inode->vdi_id) {
				sd_debug("object %" PRIx64 " is base's data, "
					 "would not be deleted.", oid);
				continue;
			}

			ret = sd_remove_object(oid);
			if (ret != SD_RES_SUCCESS)
				sd_err("remove object %" PRIx64 " fail, %d",
				       oid, ret);

			nr_deleted++;
		}
	} else {
		struct delete_arg arg = {inode, &nr_deleted};
		traverse_btree(sheep_bnode_reader, inode, delete_cb, &arg);
	}

	if (vdi_is_deleted(inode))
		goto out;

	inode->vdi_size = 0;
	memset(inode->name, 0, sizeof(inode->name));

	sd_write_object(vid_to_vdi_oid(vdi_id), (void *)inode,
			sizeof(*inode), 0, false);

	if (nr_deleted)
		notify_vdi_deletion(vdi_id);
out:
	free(inode);
	return ret;
}

static void delete_vdis_work(struct work *work)
{
	struct deletion_work *dw =
		container_of(work, struct deletion_work, work);

	for (int i = 0; i < dw->delete_vid_count; i++) {
		int ret;

		ret = delete_one_vdi(dw->delete_vid_array[i]);
		if (ret < 0)
			sd_err("deleting VDI %x failed",
			       dw->delete_vid_array[i]);
	}
}

static void delete_vdis_done(struct work *work)
{
	struct deletion_work *dw =
		container_of(work, struct deletion_work, work);

	eventfd_xwrite(dw->finish_fd, 1);

	/* the deletion info is completed */
	free(dw->delete_vid_array);
	free(dw);
}

static int fill_delete_vid_array(struct deletion_work *dw, uint32_t root_vid)
{
	int ret = 0;
	struct sd_inode *inode = NULL;
	int done = 0;
	uint32_t vid;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		sd_err("failed to allocate memory");
		return -1;
	}

	dw->delete_vid_array[dw->delete_vid_count++] = root_vid;

	do {
		vid = dw->delete_vid_array[done++];
		ret = read_backend_object(vid_to_vdi_oid(vid), (char *)inode,
					  SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("cannot find VDI object");
			ret = -1;
			break;
		}

		if (!vdi_is_deleted(inode) && vid != dw->target_vid) {
			ret = 1;
			break;
		}

		for (int i = 0; i < ARRAY_SIZE(inode->child_vdi_id); i++) {
			if (!inode->child_vdi_id[i])
				continue;

			dw->delete_vid_array[dw->delete_vid_count++] =
				inode->child_vdi_id[i];
		}
	} while (dw->delete_vid_array[done]);

	free(inode);
	return ret;
}

static uint64_t get_vdi_root(uint32_t vid, bool *cloned)
{
	int ret;
	struct sd_inode *inode = NULL;

	*cloned = false;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		sd_err("failed to allocate memory");
		return 0;
	}

	do {
		ret = read_backend_object(vid_to_vdi_oid(vid), (char *)inode,
					  SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS) {
			sd_err("cannot find VDI object");
			vid = 0;
			break;
		}

		if (vid == inode->vdi_id && inode->snap_id == 1
		    && inode->parent_vdi_id != 0 && !inode->snap_ctime) {
			sd_debug("vdi %" PRIx32 " is a cloned vdi.", vid);
			/* current vdi is a cloned vdi */
			*cloned = true;
		}

		if (!inode->parent_vdi_id)
			break;

		vid = inode->parent_vdi_id;
	} while (true);

	free(inode);
	return vid;
}

static void clear_parent_child_vdi(uint32_t vid)
{
	struct sd_inode * inode = xmalloc(SD_INODE_HEADER_SIZE);
	uint32_t pvid, i;
	int ret;

	ret = read_backend_object(vid_to_vdi_oid(vid), (char *)inode,
				  SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read inode %"PRIx32, vid);
		goto out;
	}

	pvid = inode->parent_vdi_id;
	if (!pvid)
		goto out;
	ret = read_backend_object(vid_to_vdi_oid(pvid), (char *)inode,
				  SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to read parent inode %"PRIx32, pvid);
		goto out;
	}

	for (i = 0; i < MAX_CHILDREN; i++)
		if (inode->child_vdi_id[i] == vid) {
			inode->child_vdi_id[i] = 0;
			break;
		}

	if (i == MAX_CHILDREN) {
		sd_info("failed to find child %"PRIx32, vid);
		goto out;
	}

	ret = sd_write_object(vid_to_vdi_oid(pvid), (char *)inode,
			      SD_INODE_HEADER_SIZE, 0, false);
	if (ret != SD_RES_SUCCESS) {
		sd_err("failed to update parent %"PRIx32, pvid);
		goto out;
	}
	sd_debug("parent %"PRIx32, pvid);
out:
	free(inode);
}

static int start_deletion(struct request *req, uint32_t vid)
{
	struct deletion_work *dw = NULL;
	int ret = SD_RES_SUCCESS, finish_fd;
	bool cloned;
	uint32_t root_vid;

	dw = xzalloc(sizeof(*dw));
	dw->delete_vid_array = xzalloc(SD_INODE_SIZE - SD_INODE_HEADER_SIZE);
	dw->delete_vid_count = 0;
	dw->target_vid = vid;
	finish_fd = dw->finish_fd = eventfd(0, 0);
	if (dw->finish_fd < 0) {
		sd_err("cannot create an eventfd for notifying finish of"
		       " deletion info: %m");
		goto out;
	}

	root_vid = get_vdi_root(dw->target_vid, &cloned);
	if (!root_vid) {
		ret = SD_RES_EIO;
		goto out;
	}

	clear_parent_child_vdi(vid);

	ret = fill_delete_vid_array(dw, root_vid);
	if (ret < 0) {
		ret = SD_RES_EIO;
		goto out;
	} else if (ret == 1) {
		/*
		 * if the VDI is a cloned VDI, delete its objects
		 * no matter whether the VDI tree is clear.
		 */
		ret = SD_RES_SUCCESS;

		if (cloned) {
			dw->delete_vid_array[0] = vid;
			dw->delete_vid_count = 1;
		} else {
			sd_debug("snapshot chain has valid vdi, just mark vdi %"
				 PRIx32 " as deleted.", dw->target_vid);
			delete_inode(dw->target_vid);
			goto out;
		}
	}

	sd_debug("number of VDI deletion: %d", dw->delete_vid_count);

	if (dw->delete_vid_count == 0)
		goto out;

	dw->work.fn = delete_vdis_work;
	dw->work.done = delete_vdis_done;

	queue_work(sys->deletion_wqueue, &dw->work);

	/*
	 * the event fd is written by delete_one_vdi_done(), when all vdis of
	 * deletion_work are deleted
	 */
	eventfd_xread(finish_fd);
	close(finish_fd);

	return ret;
out:
	if (dw)
		free(dw->delete_vid_array);
	free(dw);

	return ret;
}

int vdi_delete(const struct vdi_iocb *iocb, struct request *req)
{
	struct vdi_info info;
	int ret;

	ret = vdi_lookup(iocb, &info);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = start_deletion(req, info.vid);
out:
	return ret;
}

/* Calculate a vdi attribute id from sheepdog_vdi_attr. */
static uint32_t hash_vdi_attr(const struct sheepdog_vdi_attr *attr)
{
	uint64_t hval;

	/* We cannot use sd_hash for backward compatibility. */
	hval = fnv_64a_buf(attr->name, sizeof(attr->name), FNV1A_64_INIT);
	hval = fnv_64a_buf(attr->tag, sizeof(attr->tag), hval);
	hval = fnv_64a_buf(&attr->snap_id, sizeof(attr->snap_id), hval);
	hval = fnv_64a_buf(attr->key, sizeof(attr->key), hval);

	return (uint32_t)(hval & ((UINT64_C(1) << VDI_SPACE_SHIFT) - 1));
}

int get_vdi_attr(struct sheepdog_vdi_attr *vattr, int data_len,
		 uint32_t vid, uint32_t *attrid, uint64_t create_time,
		 bool wr, bool excl, bool delete)
{
	struct sheepdog_vdi_attr tmp_attr;
	uint64_t oid;
	uint32_t end;
	int ret;

	vattr->ctime = create_time;

	*attrid = hash_vdi_attr(vattr);

	end = *attrid - 1;
	while (*attrid != end) {
		oid = vid_to_attr_oid(vid, *attrid);
		ret = sd_read_object(oid, (char *)&tmp_attr,
				     sizeof(tmp_attr), 0);

		if (ret == SD_RES_NO_OBJ && wr) {
			ret = sd_write_object(oid, (char *)vattr, data_len, 0,
					      true);
			if (ret)
				ret = SD_RES_EIO;
			else
				ret = SD_RES_SUCCESS;
			goto out;
		}

		if (ret != SD_RES_SUCCESS)
			goto out;

		/* compare attribute header */
		if (strcmp(tmp_attr.name, vattr->name) == 0 &&
		    strcmp(tmp_attr.tag, vattr->tag) == 0 &&
		    tmp_attr.snap_id == vattr->snap_id &&
		    strcmp(tmp_attr.key, vattr->key) == 0) {
			if (excl)
				ret = SD_RES_VDI_EXIST;
			else if (delete) {
				ret = sd_write_object(oid, (char *)"", 1,
				offsetof(struct sheepdog_vdi_attr, name),
						      false);
				if (ret)
					ret = SD_RES_EIO;
				else
					ret = SD_RES_SUCCESS;
			} else if (wr) {
				ret = sd_write_object(oid, (char *)vattr,
						      SD_ATTR_OBJ_SIZE, 0,
						      false);

				if (ret)
					ret = SD_RES_EIO;
				else
					ret = SD_RES_SUCCESS;
			} else
				ret = SD_RES_SUCCESS;
			goto out;
		}

		(*attrid)++;
	}

	sd_debug("there is no space for new VDIs");
	ret = SD_RES_FULL_VDI;
out:
	return ret;
}

void clean_vdi_state(void)
{
	sd_write_lock(&vdi_state_lock);
	rb_destroy(&vdi_state_root, struct vdi_state_entry, node);
	INIT_RB_ROOT(&vdi_state_root);
	sd_rw_unlock(&vdi_state_lock);
}

int sd_delete_vdi(const char *name)
{
	struct sd_req hdr;
	char data[SD_MAX_VDI_LEN] = {0};
	int ret;

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(data);
	pstrcpy(data, SD_MAX_VDI_LEN, name);

	ret = exec_local_req(&hdr, data);
	if (ret != SD_RES_SUCCESS)
		sd_err("Failed to delete vdi %s %s", name, sd_strerror(ret));

	return ret;
}

int sd_lookup_vdi(const char *name, uint32_t *vid)
{
	int ret;
	struct vdi_info info = {};
	struct vdi_iocb iocb = {
		.name = name,
		.data_len = strlen(name),
	};

	ret = vdi_lookup(&iocb, &info);
	switch (ret) {
	case SD_RES_SUCCESS:
		*vid = info.vid;
		break;
	case SD_RES_NO_VDI:
		break;
	default:
		sd_err("Failed to lookup name %s, %s", name, sd_strerror(ret));
	}

	return ret;
}

int sd_create_hyper_volume(const char *name, uint32_t *vdi_id)
{
	struct sd_req hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[SD_MAX_VDI_LEN] = {};
	int ret;

	pstrcpy(buf, SD_MAX_VDI_LEN, name);

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;

	hdr.vdi.vdi_size = SD_MAX_VDI_SIZE;
	hdr.vdi.copies = sys->cinfo.nr_copies;
	hdr.vdi.copy_policy = sys->cinfo.copy_policy;
	hdr.vdi.store_policy = 1;

	ret = exec_local_req(&hdr, buf);
	if (ret != SD_RES_SUCCESS) {
		sd_err("Failed to create VDI %s: %s", name, sd_strerror(ret));
		goto out;
	}

	if (vdi_id)
		*vdi_id = rsp->vdi.vdi_id;
out:
	return ret;
}
