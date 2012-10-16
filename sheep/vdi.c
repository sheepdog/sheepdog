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
#include <pthread.h>
#include <sys/time.h>

#include "sheepdog_proto.h"
#include "sheep_priv.h"

struct vdi_copy_entry {
	uint32_t vid;
	unsigned int nr_copies;
	struct rb_node node;
};

static uint32_t max_copies;
static struct rb_root vdi_copy_root = RB_ROOT;
static pthread_rwlock_t vdi_copy_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct vdi_copy_entry *vdi_copy_search(struct rb_root *root,
					      uint32_t vid)
{
	struct rb_node *n = root->rb_node;
	struct vdi_copy_entry *t;

	while (n) {
		t = rb_entry(n, struct vdi_copy_entry, node);

		if (vid < t->vid)
			n = n->rb_left;
		else if (vid > t->vid)
			n = n->rb_right;
		else
			return t;
	}

	return NULL;
}

static struct vdi_copy_entry *vdi_copy_insert(struct rb_root *root,
					      struct vdi_copy_entry *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct vdi_copy_entry *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct vdi_copy_entry, node);

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

int get_vdi_copy_number(uint32_t vid)
{
	struct vdi_copy_entry *entry;

	pthread_rwlock_rdlock(&vdi_copy_lock);
	entry = vdi_copy_search(&vdi_copy_root, vid);
	pthread_rwlock_unlock(&vdi_copy_lock);

	if (!entry) {
		eprintf("No VDI copy entry for %" PRIx32 " found\n", vid);
		return 0;
	}

	return entry->nr_copies;
}

int get_obj_copy_number(uint64_t oid, int nr_zones)
{
	uint32_t vid;
	if (is_vdi_attr_obj(oid))
		vid = attr_oid_to_vid(oid);
	else
		vid = oid_to_vid(oid);

	return min(get_vdi_copy_number(vid), nr_zones);
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
	return uatomic_read(&max_copies);
}

int add_vdi_copy_number(uint32_t vid, int nr_copies)
{
	struct vdi_copy_entry *entry, *old;

	entry = xzalloc(sizeof(*entry));
	entry->vid = vid;
	entry->nr_copies = nr_copies;

	dprintf("%" PRIx32 ", %d\n", vid, nr_copies);

	pthread_rwlock_wrlock(&vdi_copy_lock);
	old = vdi_copy_insert(&vdi_copy_root, entry);
	if (old) {
		free(entry);
		entry = old;
		entry->nr_copies = nr_copies;
	}

	if (uatomic_read(&max_copies) == 0 ||
	    nr_copies > uatomic_read(&max_copies))
		uatomic_set(&max_copies, nr_copies);
	pthread_rwlock_unlock(&vdi_copy_lock);

	return SD_RES_SUCCESS;
}

int fill_vdi_copy_list(void *data)
{
	int nr = 0;
	struct rb_node *n;
	struct vdi_copy *vc = data;
	struct vdi_copy_entry *entry;

	pthread_rwlock_rdlock(&vdi_copy_lock);
	for (n = rb_first(&vdi_copy_root); n; n = rb_next(n)) {
		entry = rb_entry(n, struct vdi_copy_entry, node);
		vc->vid = entry->vid;
		vc->nr_copies = entry->nr_copies;
		vc++;
		nr++;
	}
	pthread_rwlock_unlock(&vdi_copy_lock);

	return nr * sizeof(*vc);
}

int vdi_exist(uint32_t vid)
{
	struct sheepdog_inode *inode;
	int ret = 1;
	int nr_copies;

	inode = zalloc(sizeof(*inode));
	if (!inode) {
		ret = 0;
		goto out;
	}

	nr_copies = get_vdi_copy_number(vid);

	ret = read_object(vid_to_vdi_oid(vid), (char *)inode,
			  sizeof(*inode), 0, nr_copies);
	if (ret != SD_RES_SUCCESS) {
		eprintf("fail to read vdi inode (%" PRIx32 ")\n", vid);
		ret = 0;
		goto out;
	}

	if (*inode->name == '\0') {
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
			  uint32_t cur_vid, uint32_t snapid)
{
	/* we are not called concurrently */
	struct sheepdog_inode *new = NULL, *base = NULL, *cur = NULL;
	struct timeval tv;
	int ret = SD_RES_NO_MEM;
	unsigned long block_size = SD_DATA_OBJ_SIZE;
	char *name = iocb->name;

	new = zalloc(sizeof(*new));
	if (!new) {
		eprintf("failed to allocate memory\n");
		goto out;
	}

	if (iocb->base_vid) {
		base = zalloc(sizeof(*base));
		if (!base) {
			eprintf("failed to allocate memory\n");
			goto out;
		}
	}

	if (iocb->snapid && cur_vid != iocb->base_vid) {
		cur = zalloc(SD_INODE_HEADER_SIZE);
		if (!cur) {
			eprintf("failed to allocate memory\n");
			goto out;
		}
	}

	if (iocb->base_vid) {
		ret = read_object(vid_to_vdi_oid(iocb->base_vid), (char *)base,
				  sizeof(*base), 0, 0);
		if (ret != SD_RES_SUCCESS) {
			ret = SD_RES_BASE_VDI_READ;
			goto out;
		}
	}

	gettimeofday(&tv, NULL);

	if (iocb->snapid) {
		if (cur_vid != iocb->base_vid) {
			vprintf(SDOG_INFO, "tree snapshot %s %" PRIx32 " %" PRIx32 "\n",
				name, cur_vid, iocb->base_vid);

			ret = read_object(vid_to_vdi_oid(cur_vid), (char *)cur,
					  SD_INODE_HEADER_SIZE, 0, 0);
			if (ret != SD_RES_SUCCESS) {
				vprintf(SDOG_ERR, "failed\n");
				ret = SD_RES_BASE_VDI_READ;
				goto out;
			}

			cur->snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
		} else
			base->snap_ctime = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	}

	strncpy(new->name, name, sizeof(new->name));
	new->vdi_id = new_vid;
	new->create_time = (uint64_t) tv.tv_sec << 32 | tv.tv_usec * 1000;
	new->vdi_size = iocb->size;
	new->copy_policy = 0;
	new->nr_copies = iocb->nr_copies;
	new->block_size_shift = find_next_bit(&block_size, BITS_PER_LONG, 0);
	new->snap_id = snapid;

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

	if (iocb->snapid && cur_vid != iocb->base_vid) {
		ret = write_object(vid_to_vdi_oid(cur_vid), (char *)cur,
				   SD_INODE_HEADER_SIZE, 0, 0, false, 0);
		if (ret != 0) {
			vprintf(SDOG_ERR, "failed\n");
			ret = SD_RES_BASE_VDI_READ;
			goto out;
		}
	}

	if (iocb->base_vid) {
		ret = write_object(vid_to_vdi_oid(iocb->base_vid), (char *)base,
				   SD_INODE_HEADER_SIZE, 0, 0, false, 0);
		if (ret != 0) {
			vprintf(SDOG_ERR, "failed\n");
			ret = SD_RES_BASE_VDI_WRITE;
			goto out;
		}
	}

	ret = write_object(vid_to_vdi_oid(new_vid), (char *)new, sizeof(*new),
			   0, 0, true, iocb->nr_copies);
	if (ret != 0)
		ret = SD_RES_VDI_WRITE;

out:
	free(new);
	free(cur);
	free(base);
	return ret;
}

static int find_first_vdi(unsigned long start, unsigned long end, char *name,
			  char *tag, uint32_t snapid, uint32_t *vid,
			  unsigned long *deleted_nr, uint32_t *next_snap,
			  unsigned int *inode_nr_copies, uint64_t *create_time)
{
	struct sheepdog_inode *inode = NULL;
	unsigned long i;
	int ret = SD_RES_NO_MEM;
	bool vdi_found = false;
	int nr_copies;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		eprintf("failed to allocate memory\n");
		goto out;
	}

	for (i = start; i >= end; i--) {
		nr_copies = get_vdi_copy_number(i);
		ret = read_object(vid_to_vdi_oid(i), (char *)inode,
				  SD_INODE_HEADER_SIZE, 0, nr_copies);
		if (ret != SD_RES_SUCCESS) {
			ret = SD_RES_EIO;
			goto out_free_inode;
		}

		if (inode->name[0] == '\0') {
			*deleted_nr = i;
			continue; /* deleted */
		}

		if (!strncmp(inode->name, name, strlen(inode->name))) {
			if (!(tag && tag[0]) && !snapid && inode->snap_ctime)
				continue;

			vdi_found = true;
			if (tag && tag[0] &&
			    strncmp(inode->tag, tag, sizeof(inode->tag)) != 0)
				continue;
			if (snapid && snapid != inode->snap_id)
				continue;

			*next_snap = inode->snap_id + 1;
			*vid = inode->vdi_id;
			*inode_nr_copies = inode->nr_copies;
			if (create_time)
				*create_time = inode->create_time;
			ret = SD_RES_SUCCESS;
			goto out_free_inode;
		}
	}

	if (vdi_found)
		ret = SD_RES_NO_TAG;
	else
		ret = SD_RES_NO_VDI;

out_free_inode:
	free(inode);
out:
	return ret;
}

static int do_lookup_vdi(char *name, int namelen, uint32_t *vid, char *tag,
		uint32_t snapid, uint32_t *next_snapid, unsigned long *right_nr,
		unsigned long *deleted_nr, unsigned int *nr_copies,
		uint64_t *create_time)
{
	int ret;
	unsigned long nr, start_nr;

	start_nr = fnv_64a_buf(name, namelen, FNV1A_64_INIT) & (SD_NR_VDIS - 1);

	vprintf(SDOG_INFO, "looking for %s (%lx)\n", name, start_nr);

	/* bitmap search from the hash point */
	nr = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, start_nr);
	*right_nr = nr;
	if (nr == start_nr) {
		return SD_RES_NO_VDI;
	} else if (nr < SD_NR_VDIS) {
	right_side:
		/* look up on the right side of the hash point */
		ret = find_first_vdi(nr - 1, start_nr, name,
				     tag, snapid, vid, deleted_nr, next_snapid,
				     nr_copies, create_time);
		return ret;
	} else {
		/* round up... bitmap search from the head of the bitmap */
		nr = find_next_zero_bit(sys->vdi_inuse, SD_NR_VDIS, 0);
		*right_nr = nr;
		if (nr >= SD_NR_VDIS)
			return SD_RES_FULL_VDI;
		else if (nr) {
			/* look up on the left side of the hash point */
			ret = find_first_vdi(nr - 1, 0, name,
					     tag, snapid, vid, deleted_nr,
					     next_snapid, nr_copies,
					     create_time);
			if (ret == SD_RES_NO_VDI)
				; /* we need to go to the right side */
			else
				return ret;
		}

		nr = SD_NR_VDIS;
		goto right_side;
	}
}

int lookup_vdi(char *name, char *tag, uint32_t *vid, uint32_t snapid,
	       unsigned int *nr_copies, uint64_t *create_time)
{
	uint32_t dummy0;
	unsigned long dummy1, dummy2;

	return do_lookup_vdi(name, strlen(name), vid, tag,
			     snapid, &dummy0, &dummy1, &dummy2, nr_copies,
			     create_time);
}

int add_vdi(struct vdi_iocb *iocb, uint32_t *new_vid)
{
	uint32_t cur_vid = 0;
	uint32_t next_snapid;
	unsigned long nr, deleted_nr = SD_NR_VDIS, right_nr = SD_NR_VDIS;
	unsigned int dummy;
	int ret;
	char *name;

	if (iocb->data_len != SD_MAX_VDI_LEN)
		return SD_RES_INVALID_PARMS;

	name = iocb->name;

	ret = do_lookup_vdi(name, strlen(name), &cur_vid,
			    NULL, 0, &next_snapid, &right_nr, &deleted_nr,
			    &dummy, NULL);

	if (iocb->snapid) {
		if (ret != SD_RES_SUCCESS) {
			if (ret == SD_RES_NO_VDI)
				vprintf(SDOG_CRIT, "VDI %s does not exist\n", name);
			return ret;
		}
		nr = right_nr;
	} else {
		/* we already have the same VDI or met other errors. */
		if (ret != SD_RES_NO_VDI) {
			if (ret == SD_RES_SUCCESS)
				ret = SD_RES_VDI_EXIST;
			return ret;
		}

		if (deleted_nr == SD_NR_VDIS)
			nr = right_nr;
		else
			nr = deleted_nr; /* we can recycle a deleted VDI */

		next_snapid = 1;
	}

	*new_vid = nr;

	vprintf(SDOG_INFO, "creating new %s %s: size %" PRIu64 ", vid %"
		PRIx32 ", base %" PRIx32 ", cur %" PRIx32 ", copies %d\n",
		iocb->snapid ? "snapshot" : "vdi", name, iocb->size,
		*new_vid, iocb->base_vid, cur_vid, iocb->nr_copies);

	return create_vdi_obj(iocb, *new_vid, cur_vid, next_snapid);
}

static int start_deletion(struct request *req, uint32_t vid);

int del_vdi(struct request *req, char *data, int data_len,
	    uint32_t *vid, uint32_t snapid, unsigned int *nr_copies)
{
	char *name = data, *tag;
	uint32_t dummy0;
	unsigned long dummy1, dummy2;
	int ret;

	if (data_len == SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN)
		tag = data + SD_MAX_VDI_LEN;
	else if (data_len == SD_MAX_VDI_LEN)
		tag = NULL;
	else {
		ret = SD_RES_INVALID_PARMS;
		goto out;
	}

	ret = do_lookup_vdi(name, strlen(name), vid, tag,
			    snapid, &dummy0, &dummy1, &dummy2,
			    nr_copies, NULL);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = start_deletion(req, *vid);
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
	struct list_head dw_siblings;
	struct request *req;

	uint32_t vid;
	int nr_copies;

	int count;
	uint32_t *buf;
};

static LIST_HEAD(deletion_work_list);

static int delete_inode(struct deletion_work *dw)
{
	struct sheepdog_inode *inode = NULL;
	int ret = SD_RES_SUCCESS;

	inode = zalloc(sizeof(*inode));
	if (!inode) {
		eprintf("no memory to allocate inode.\n");
		goto out;
	}

	ret = read_object(vid_to_vdi_oid(dw->vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0, dw->nr_copies);
	if (ret != SD_RES_SUCCESS) {
		ret = SD_RES_EIO;
		goto out;
	}

	memset(inode->name, 0, sizeof(inode->name));

	ret = write_object(vid_to_vdi_oid(dw->vid), (char *)inode,
			   SD_INODE_HEADER_SIZE, 0, 0, false, dw->nr_copies);
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
		eprintf("fail to notify vdi deletion(%" PRIx32 "), %d\n",
			vdi_id, ret);

	return ret;
}

static void delete_one(struct work *work)
{
	struct deletion_work *dw = container_of(work, struct deletion_work, work);
	uint32_t vdi_id = *(dw->buf + dw->count - dw->done - 1);
	int ret, i, nr_deleted;
	struct sheepdog_inode *inode = NULL;
	int nr_copies;

	eprintf("%d %d, %16x\n", dw->done, dw->count, vdi_id);

	inode = malloc(sizeof(*inode));
	if (!inode) {
		eprintf("failed to allocate memory\n");
		goto out;
	}

	nr_copies = get_vdi_copy_number(vdi_id);
	ret = read_backend_object(vid_to_vdi_oid(vdi_id),
			  (void *)inode, sizeof(*inode), 0, nr_copies);

	if (ret != SD_RES_SUCCESS) {
		eprintf("cannot find VDI object\n");
		goto out;
	}

	if (inode->vdi_size == 0 && inode->name[0] == '\0')
		goto out;

	for (nr_deleted = 0, i = 0; i < MAX_DATA_OBJS; i++) {
		uint64_t oid;

		if (!inode->data_vdi_id[i])
			continue;

		oid = vid_to_data_oid(inode->data_vdi_id[i], i);

		if (inode->data_vdi_id[i] != inode->vdi_id) {
			dprintf("object %" PRIx64 " is base's data, would not be deleted.\n",
				oid);
			continue;
		}

		ret = remove_object(oid, nr_copies);
		if (ret != SD_RES_SUCCESS)
			eprintf("remove object %" PRIx64 " fail, %d\n", oid, ret);

		nr_deleted++;
	}

	if (nr_deleted)
		notify_vdi_deletion(vdi_id);

	if (*(inode->name) == '\0')
		goto out;

	inode->vdi_size = 0;
	memset(inode->name, 0, sizeof(inode->name));

	write_object(vid_to_vdi_oid(vdi_id), (void *)inode,
		     sizeof(*inode), 0, 0, false, nr_copies);
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

	list_del(&dw->dw_siblings);

	put_request(req);

	free(dw->buf);
	free(dw);

	if (!list_empty(&deletion_work_list)) {
		dw = list_first_entry(&deletion_work_list,
				      struct deletion_work, dw_siblings);

		queue_work(sys->deletion_wqueue, &dw->work);
	}
}

static int fill_vdi_list(struct deletion_work *dw, uint32_t root_vid)
{
	int ret, i;
	struct sheepdog_inode *inode = NULL;
	int done = dw->count;
	uint32_t vid;
	int nr_copies;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		eprintf("failed to allocate memory\n");
		goto err;
	}

	dw->buf[dw->count++] = root_vid;
again:
	vid = dw->buf[done++];
	nr_copies = get_vdi_copy_number(vid);
	ret = read_backend_object(vid_to_vdi_oid(vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0, nr_copies);

	if (ret != SD_RES_SUCCESS) {
		eprintf("cannot find VDI object\n");
		goto err;
	}

	if (inode->name[0] != '\0' && vid != dw->vid)
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
	int ret, nr_copies;
	struct sheepdog_inode *inode = NULL;

	*cloned = false;

	inode = malloc(SD_INODE_HEADER_SIZE);
	if (!inode) {
		eprintf("failed to allocate memory\n");
		vid = 0;
		goto out;
	}
next:
	nr_copies = get_vdi_copy_number(vid);
	ret = read_backend_object(vid_to_vdi_oid(vid), (char *)inode,
			  SD_INODE_HEADER_SIZE, 0, nr_copies);

	if (vid == inode->vdi_id && inode->snap_id == 1
			&& inode->parent_vdi_id != 0
			&& !inode->snap_ctime) {
		dprintf("vdi %" PRIx32 " is a cloned vdi.\n", vid);
		/* current vdi is a cloned vdi */
		*cloned = true;
	}

	if (ret != SD_RES_SUCCESS) {
		eprintf("cannot find VDI object\n");
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

	dw = zalloc(sizeof(struct deletion_work));
	if (!dw)
		goto err;

	/* buf is to store vdi id of every object */
	dw->buf = zalloc(SD_INODE_SIZE - SD_INODE_HEADER_SIZE);
	if (!dw->buf)
		goto err;

	dw->count = 0;
	dw->vid = vid;
	dw->req = req;
	dw->nr_copies = get_vdi_copy_number(vid);

	dw->work.fn = delete_one;
	dw->work.done = delete_one_done;

	root_vid = get_vdi_root(dw->vid, &cloned);
	if (!root_vid) {
		ret = SD_RES_EIO;
		goto err;
	}

	ret = fill_vdi_list(dw, root_vid);
	if (ret) {
		/* if the VDI is a cloned VDI, delete its objects
		 * no matter whether the VDI tree is clear. */
		if (cloned) {
			dw->buf[0] = vid;
			dw->count = 1;
		} else {
			dprintf("snapshot chain has valid vdi, "
				"just mark vdi %" PRIx32 " as deleted.\n",
				dw->vid);
			delete_inode(dw);
			return SD_RES_SUCCESS;
		}
	}

	dprintf("%d\n", dw->count);

	if (dw->count == 0)
		goto out;

	uatomic_inc(&req->refcnt);

	if (list_empty(&deletion_work_list)) {
		list_add_tail(&dw->dw_siblings, &deletion_work_list);
		queue_work(sys->deletion_wqueue, &dw->work);
	} else
		list_add_tail(&dw->dw_siblings, &deletion_work_list);
out:
	return SD_RES_SUCCESS;
err:
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
	int ret, nr_copies;

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
		nr_copies = get_vdi_copy_number(vid);
		ret = read_object(oid, (char *)&tmp_attr,
				  sizeof(tmp_attr), 0, nr_copies);

		if (ret == SD_RES_NO_OBJ && wr) {
			ret = write_object(oid, (char *)vattr,
					   data_len, 0, 0, true, nr_copies);
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
						   0, false, nr_copies);
				if (ret)
					ret = SD_RES_EIO;
				else
					ret = SD_RES_SUCCESS;
			} else if (wr) {
				ret = write_object(oid, (char *)vattr,
						   SD_ATTR_OBJ_SIZE, 0, 0,
						   false, nr_copies);

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

	dprintf("there is no space for new VDIs\n");
	ret = SD_RES_FULL_VDI;
out:
	return ret;
}
