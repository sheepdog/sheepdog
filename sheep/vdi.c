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
	struct rb_node node;
};

static uint32_t max_copies;
static struct rb_root vdi_state_root = RB_ROOT;
static struct sd_lock vdi_state_lock = SD_LOCK_INITIALIZER;

static struct vdi_state_entry *vdi_state_search(struct rb_root *root,
						uint32_t vid)
{
	struct rb_node *n = root->rb_node;
	struct vdi_state_entry *t;

	while (n) {
		t = rb_entry(n, struct vdi_state_entry, node);

		if (vid < t->vid)
			n = n->rb_left;
		else if (vid > t->vid)
			n = n->rb_right;
		else
			return t;
	}

	return NULL;
}

static struct vdi_state_entry *vdi_state_insert(struct rb_root *root,
						struct vdi_state_entry *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct vdi_state_entry *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct vdi_state_entry, node);

		if (new->vid < entry->vid)
			p = &(*p)->rb_left;
		else if (new->vid > entry->vid)
			p = &(*p)->rb_right;
		else
			return entry; /* already has this entry */
	}
	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);

	return NULL; /* insert successfully */
}

static bool vid_is_snapshot(uint32_t vid)
{
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	entry = vdi_state_search(&vdi_state_root, vid);
	sd_unlock(&vdi_state_lock);

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
	sd_unlock(&vdi_state_lock);

	if (!entry) {
		sd_alert("copy number for %" PRIx32 " not found, set %d", vid,
			 sys->cinfo.nr_copies);
		return sys->cinfo.nr_copies;
	}

	return entry->nr_copies;
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

int get_max_copy_number(void)
{
	int nr_copies = uatomic_read(&max_copies);

	if (nr_copies == 0)
		nr_copies = sys->cinfo.nr_copies;

	return nr_copies;
}

int add_vdi_state(uint32_t vid, int nr_copies, bool snapshot)
{
	struct vdi_state_entry *entry, *old;

	entry = xzalloc(sizeof(*entry));
	entry->vid = vid;
	entry->nr_copies = nr_copies;
	entry->snapshot = snapshot;

	sd_debug("%" PRIx32 ", %d", vid, nr_copies);

	sd_write_lock(&vdi_state_lock);
	old = vdi_state_insert(&vdi_state_root, entry);
	if (old) {
		free(entry);
		entry = old;
		entry->nr_copies = nr_copies;
		entry->snapshot = snapshot;
	}

	if (uatomic_read(&max_copies) == 0 ||
	    nr_copies > uatomic_read(&max_copies))
		uatomic_set(&max_copies, nr_copies);
	sd_unlock(&vdi_state_lock);

	return SD_RES_SUCCESS;
}

int fill_vdi_state_list(void *data)
{
	int nr = 0;
	struct rb_node *n;
	struct vdi_state *vs = data;
	struct vdi_state_entry *entry;

	sd_read_lock(&vdi_state_lock);
	for (n = rb_first(&vdi_state_root); n; n = rb_next(n)) {
		entry = rb_entry(n, struct vdi_state_entry, node);
		memset(vs, 0, sizeof(*vs));
		vs->vid = entry->vid;
		vs->nr_copies = entry->nr_copies;
		vs->snapshot = entry->snapshot;
		vs++;
		nr++;
	}
	sd_unlock(&vdi_state_lock);

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
	ret = read_object(vid_to_vdi_oid(vid), (char *)inode,
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

/* TODO: should be performed atomically */
static int create_vdi_obj(struct vdi_iocb *iocb, uint32_t new_vid,
			  uint32_t cur_vid)
{
	/* we are not called concurrently */
	struct sd_inode *new = NULL, *base = NULL, *cur = NULL;
	struct timeval tv;
	int ret = SD_RES_NO_MEM;
	unsigned long block_size = SD_DATA_OBJ_SIZE;
	const char *name = iocb->name;

	new = xzalloc(sizeof(*new));
	if (iocb->base_vid)
		base = xzalloc(sizeof(*base));

	if (iocb->create_snapshot && cur_vid != iocb->base_vid)
		cur = xzalloc(SD_INODE_HEADER_SIZE);

	if (iocb->base_vid) {
		ret = read_object(vid_to_vdi_oid(iocb->base_vid), (char *)base,
				  sizeof(*base), 0);
		if (ret != SD_RES_SUCCESS) {
			ret = SD_RES_BASE_VDI_READ;
			goto out;
		}
	}

	gettimeofday(&tv, NULL);

	if (iocb->create_snapshot) {
		if (cur_vid != iocb->base_vid) {
			sd_info("tree snapshot %s %" PRIx32 " %" PRIx32, name,
				cur_vid, iocb->base_vid);

			ret = read_object(vid_to_vdi_oid(cur_vid), (char *)cur,
					  SD_INODE_HEADER_SIZE, 0);
			if (ret != SD_RES_SUCCESS) {
				sd_err("failed");
				ret = SD_RES_BASE_VDI_READ;
				goto out;
			}

			cur->snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
		} else
			base->snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	}

	pstrcpy(new->name, sizeof(new->name), name);
	new->vdi_id = new_vid;
	new->create_time = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	new->vdi_size = iocb->size;
	new->copy_policy = 0;
	new->nr_copies = iocb->nr_copies;
	new->block_size_shift = find_next_bit(&block_size, BITS_PER_LONG, 0);
	new->snap_id = iocb->snapid;

	if (iocb->base_vid) {
		int i;

		new->parent_vdi_id = iocb->base_vid;
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

	if (iocb->create_snapshot && cur_vid != iocb->base_vid) {
		ret = write_object(vid_to_vdi_oid(cur_vid), (char *)cur,
				   SD_INODE_HEADER_SIZE, 0, false);
		if (ret != 0) {
			sd_err("failed");
			ret = SD_RES_BASE_VDI_READ;
			goto out;
		}
	}

	if (iocb->base_vid) {
		ret = write_object(vid_to_vdi_oid(iocb->base_vid), (char *)base,
				   SD_INODE_HEADER_SIZE, 0, false);
		if (ret != 0) {
			sd_err("failed");
			ret = SD_RES_BASE_VDI_WRITE;
			goto out;
		}
	}

	ret = write_object(vid_to_vdi_oid(new_vid), (char *)new, sizeof(*new),
			   0, true);
	if (ret != 0)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(cur);
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
	*left = fnv_64a_buf(name, strlen(name), FNV1A_64_INIT) &
		(SD_NR_VDIS - 1);
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

static inline bool vdi_has_tag(struct vdi_iocb *iocb)
{
	if ((iocb->tag && iocb->tag[0]) || iocb->snapid)
		return true;
	return false;
}

static inline bool vdi_tag_match(struct vdi_iocb *iocb,
			     struct sd_inode *inode)
{
	const char *tag = iocb->tag;

	if (inode->tag[0] && !strncmp(inode->tag, tag, sizeof(inode->tag)))
		return true;
	if (iocb->snapid == inode->snap_id)
		return true;
	return false;
}

static int fill_vdi_info_range(uint32_t left, uint32_t right,
			      struct vdi_iocb *iocb, struct vdi_info *info)
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
		ret = read_object(vid_to_vdi_oid(i), (char *)inode,
				  SD_INODE_HEADER_SIZE, 0);
		if (ret != SD_RES_SUCCESS)
			goto out;

		if (vdi_is_deleted(inode)) {
			/* Recycle the deleted inode for fresh vdi create */
			if (!iocb->create_snapshot)
				info->free_bit = i;
			continue;
		}

		if (!strncmp(inode->name, name, strlen(inode->name))) {
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
				iocb->snapid = inode->snap_id + 1;
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
			 struct vdi_iocb *iocb, struct vdi_info *info)
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
int vdi_lookup(struct vdi_iocb *iocb, struct vdi_info *info)
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

static int notify_vdi_add(uint32_t vdi_id, uint32_t nr_copies, uint32_t old_vid)
{
	int ret = SD_RES_SUCCESS;
	struct sd_req hdr;

	sd_init_req(&hdr, SD_OP_NOTIFY_VDI_ADD);
	hdr.vdi_state.old_vid = old_vid;
	hdr.vdi_state.new_vid = vdi_id;
	hdr.vdi_state.copies = nr_copies;
	hdr.vdi_state.set_bitmap = false;

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
 * There are 3 create operation in SD:
 * 1. fresh create (expect NO_VDI returned from vdi_lookup)
 * 2. snapshot create (expect SUCCESS)
 * 3. rollback create (expect NO_VDI)
 *
 * Fresh create started with id = 1. Both rollback & snap create started with
 * current working VDI's snap_id + 1. Working VDI always has the highest snapid.
 */
int vdi_create(struct vdi_iocb *iocb, uint32_t *new_vid)
{
	const char *name = iocb->name;
	struct vdi_info info = {};
	int ret;

	ret = vdi_lookup(iocb, &info);
	switch (ret) {
	case SD_RES_SUCCESS:
		if (!iocb->create_snapshot)
			return SD_RES_VDI_EXIST;
		if (sys->enable_object_cache)
			vdi_flush(iocb->base_vid);
		break;
	case SD_RES_NO_VDI:
		if (iocb->create_snapshot)
			return ret;
		break;
	default:
		sd_err("%s", sd_strerror(ret));
		return ret;
	}
	if (!iocb->snapid)
		iocb->snapid = 1;
	*new_vid = info.free_bit;
	ret = notify_vdi_add(*new_vid, iocb->nr_copies, info.vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	sd_debug("%s %s: size %" PRIu64 ", vid %" PRIx32 ", base %" PRIx32
		 ", cur %" PRIx32 ", copies %d, snapid %" PRIu32,
		 iocb->create_snapshot ? "snapshot" : "vdi", name, iocb->size,
		 *new_vid, iocb->base_vid, info.vid, iocb->nr_copies,
		 iocb->snapid);

	return create_vdi_obj(iocb, *new_vid, info.vid);
}

static int start_deletion(struct request *req, uint32_t vid);

int vdi_delete(struct vdi_iocb *iocb, struct request *req)
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
	struct list_head list;
	struct request *req;

	uint32_t vid;

	int count;
	uint32_t *buf;
};

static LIST_HEAD(deletion_work_list);

static int delete_inode(struct deletion_work *dw)
{
	struct sd_inode *inode = NULL;
	int ret = SD_RES_SUCCESS;

	inode = xzalloc(sizeof(*inode));
	ret = read_object(vid_to_vdi_oid(dw->vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_EIO;
		goto out;
	}

	memset(inode->name, 0, sizeof(inode->name));

	ret = write_object(vid_to_vdi_oid(dw->vid), (char *)inode,
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

static void delete_one(struct work *work)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	uint32_t vdi_id = *(dw->buf + dw->count - dw->done - 1);
	int ret, i, nr_deleted;
	struct sd_inode *inode = NULL;

	sd_debug("%d %d, %16x", dw->done, dw->count, vdi_id);

	inode = malloc(sizeof(*inode));
	if (!inode) {
		sd_err("failed to allocate memory");
		return;
	}

	ret = read_backend_object(vid_to_vdi_oid(vdi_id),
			  (void *)inode, sizeof(*inode), 0);

	if (ret != SD_RES_SUCCESS) {
		sd_err("cannot find VDI object");
		goto out;
	}

	if (inode->vdi_size == 0 && vdi_is_deleted(inode))
		goto out;

	for (nr_deleted = 0, i = 0; i < MAX_DATA_OBJS; i++) {
		uint64_t oid;

		if (!inode->data_vdi_id[i])
			continue;

		oid = vid_to_data_oid(inode->data_vdi_id[i], i);

		if (inode->data_vdi_id[i] != inode->vdi_id) {
			sd_debug("object %" PRIx64 " is base's data, would"
				 " not be deleted.", oid);
			continue;
		}

		ret = remove_object(oid);
		if (ret != SD_RES_SUCCESS)
			sd_err("remove object %" PRIx64 " fail, %d", oid, ret);

		nr_deleted++;
	}

	if (vdi_is_deleted(inode))
		goto out;

	inode->vdi_size = 0;
	memset(inode->name, 0, sizeof(inode->name));

	write_object(vid_to_vdi_oid(vdi_id), (void *)inode,
		     sizeof(*inode), 0, false);

	if (nr_deleted)
		notify_vdi_deletion(vdi_id);
out:
	free(inode);
}

static void delete_one_done(struct work *work)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	struct request *req = dw->req;

	dw->done++;
	if (dw->done < dw->count) {
		queue_work(sys->deletion_wqueue, &dw->work);
		return;
	}

	list_del(&dw->list);

	put_request(req);

	free(dw->buf);
	free(dw);

	if (!list_empty(&deletion_work_list)) {
		dw = list_first_entry(&deletion_work_list,
				      struct deletion_work, list);

		queue_work(sys->deletion_wqueue, &dw->work);
	}
}

static int fill_vdi_list(struct deletion_work *dw, uint32_t root_vid)
{
	int ret, i;
	struct sd_inode *inode = NULL;
	int done = dw->count;
	uint32_t vid;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		sd_err("failed to allocate memory");
		goto err;
	}

	dw->buf[dw->count++] = root_vid;
again:
	vid = dw->buf[done++];
	ret = read_backend_object(vid_to_vdi_oid(vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0);

	if (ret != SD_RES_SUCCESS) {
		sd_err("cannot find VDI object");
		goto err;
	}

	if (!vdi_is_deleted(inode) && vid != dw->vid)
		goto out;

	for (i = 0; i < ARRAY_SIZE(inode->child_vdi_id); i++) {
		if (!inode->child_vdi_id[i])
			continue;

		dw->buf[dw->count++] = inode->child_vdi_id[i];
	}

	if (dw->buf[done])
		goto again;
err:
	free(inode);
	return 0;
out:
	free(inode);
	return 1;
}

static uint64_t get_vdi_root(uint32_t vid, bool *cloned)
{
	int ret;
	struct sd_inode *inode = NULL;

	*cloned = false;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		sd_err("failed to allocate memory");
		vid = 0;
		goto out;
	}
next:
	ret = read_backend_object(vid_to_vdi_oid(vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0);

	if (vid == inode->vdi_id && inode->snap_id == 1
			&& inode->parent_vdi_id != 0
			&& !inode->snap_ctime) {
		sd_debug("vdi %" PRIx32 " is a cloned vdi.", vid);
		/* current vdi is a cloned vdi */
		*cloned = true;
	}

	if (ret != SD_RES_SUCCESS) {
		sd_err("cannot find VDI object");
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

static int start_deletion(struct request *req, uint32_t vid)
{
	struct deletion_work *dw = NULL;
	int ret = SD_RES_NO_MEM;
	bool cloned;
	uint32_t root_vid;

	dw = xzalloc(sizeof(struct deletion_work));
	/* buf is to store vdi id of every object */
	dw->buf = xzalloc(SD_INODE_SIZE - SD_INODE_HEADER_SIZE);
	dw->count = 0;
	dw->vid = vid;
	dw->req = req;

	dw->work.fn = delete_one;
	dw->work.done = delete_one_done;

	root_vid = get_vdi_root(dw->vid, &cloned);
	if (!root_vid) {
		ret = SD_RES_EIO;
		goto out;
	}

	ret = fill_vdi_list(dw, root_vid);
	if (ret) {
		/*
		 * if the VDI is a cloned VDI, delete its objects
		 * no matter whether the VDI tree is clear.
		 */
		if (cloned) {
			dw->buf[0] = vid;
			dw->count = 1;
		} else {
			sd_debug("snapshot chain has valid vdi, just mark vdi %"
				 PRIx32 " as deleted.", dw->vid);
			delete_inode(dw);
			ret = SD_RES_SUCCESS;
			goto out;
		}
	}

	sd_debug("%d", dw->count);

	ret = SD_RES_SUCCESS;
	if (dw->count == 0)
		goto out;

	refcount_inc(&req->refcnt);

	if (list_empty(&deletion_work_list)) {
		list_add_tail(&dw->list, &deletion_work_list);
		queue_work(sys->deletion_wqueue, &dw->work);
	} else
		list_add_tail(&dw->list, &deletion_work_list);

	return ret;
out:
	if (dw)
		free(dw->buf);
	free(dw);

	return ret;
}

int get_vdi_attr(struct sheepdog_vdi_attr *vattr, int data_len,
		 uint32_t vid, uint32_t *attrid, uint64_t create_time,
		 bool wr, bool excl, bool delete)
{
	struct sheepdog_vdi_attr tmp_attr;
	uint64_t oid, hval;
	uint32_t end;
	int ret;

	vattr->ctime = create_time;

	/* we cannot include value_len for calculating the hash value */
	hval = fnv_64a_buf(vattr->name, sizeof(vattr->name), FNV1A_64_INIT);
	hval = fnv_64a_buf(vattr->tag, sizeof(vattr->tag), hval);
	hval = fnv_64a_buf(&vattr->snap_id, sizeof(vattr->snap_id), hval);
	hval = fnv_64a_buf(vattr->key, sizeof(vattr->key), hval);
	*attrid = hval & ((UINT64_C(1) << VDI_SPACE_SHIFT) - 1);

	end = *attrid - 1;
	while (*attrid != end) {
		oid = vid_to_attr_oid(vid, *attrid);
		ret = read_object(oid, (char *)&tmp_attr,
				  sizeof(tmp_attr), 0);

		if (ret == SD_RES_NO_OBJ && wr) {
			ret = write_object(oid, (char *)vattr, data_len, 0,
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
				ret = write_object(oid, (char *)"", 1,
						   offsetof(struct sheepdog_vdi_attr, name),
						   false);
				if (ret)
					ret = SD_RES_EIO;
				else
					ret = SD_RES_SUCCESS;
			} else if (wr) {
				ret = write_object(oid, (char *)vattr,
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
	struct rb_node *current_node = rb_first(&vdi_state_root);
	struct vdi_state_entry *entry = NULL;

	sd_write_lock(&vdi_state_lock);
	while (current_node) {
		entry = rb_entry(current_node, struct vdi_state_entry, node);
		rb_erase(current_node, &vdi_state_root);
		free(entry);
		entry = NULL;
		current_node = rb_first(&vdi_state_root);
	}
	INIT_RB_ROOT(&vdi_state_root);
	sd_unlock(&vdi_state_lock);
}
