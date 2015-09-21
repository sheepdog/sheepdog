/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheepdog.h"
#include "internal.h"
#include "sheep.h"

static int lock_vdi(struct sd_cluster *c, struct sd_vdi *vdi)
{
	struct sd_req hdr = {};
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	hdr.opcode = SD_OP_LOCK_VDI;
	hdr.data_length = SD_MAX_VDI_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE;
	ret = sd_run_sdreq(c, &hdr, vdi->name);
	if (ret != SD_RES_SUCCESS)
		return ret;

	vdi->vid = rsp->vdi.vdi_id;

	return SD_RES_SUCCESS;
}

static int unlock_vdi(struct sd_cluster *c, struct sd_vdi *vdi)
{
	struct sd_req hdr = {};
	int ret;

	hdr.opcode = SD_OP_RELEASE_VDI;
	hdr.vdi.type = LOCK_TYPE_NORMAL;
	hdr.vdi.base_vdi_id = vdi->vid;
	ret = sd_run_sdreq(c, &hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return SD_RES_SUCCESS;
}

static struct sd_vdi *alloc_vdi(struct sd_cluster *c, char *name)
{
	struct sd_vdi *new = xzalloc(sizeof(*new));

	new->name = name;
	new->inode = xmalloc(sizeof(struct sd_inode));
	sd_init_rw_lock(&new->lock);

	return new;
}

static void free_vdi(struct sd_vdi *vdi)
{
	sd_destroy_rw_lock(&vdi->lock);
	free(vdi->inode);
	free(vdi);
}

struct sd_vdi *sd_vdi_open(struct sd_cluster *c, char *name)
{
	struct sd_req hdr = {};
	struct sd_vdi *new = alloc_vdi(c, name);
	int ret;

	ret = lock_vdi(c, new);
	if (ret != SD_RES_SUCCESS) {
		errno = ret;
		goto out_free;
	}

	hdr.opcode = SD_OP_READ_OBJ;
	hdr.data_length = SD_INODE_SIZE;
	hdr.obj.oid = vid_to_vdi_oid(new->vid);
	hdr.obj.offset = 0;
	ret = sd_run_sdreq(c, &hdr, new->inode);
	if (ret != SD_RES_SUCCESS) {
		errno = ret;
		goto out_unlock;
	}

	if (vdi_is_snapshot(new->inode)) {
		errno = SD_RES_INVALID_PARMS;
		goto out_unlock;
	}

	return new;
out_unlock:
	unlock_vdi(c, new);
out_free:
	free_vdi(new);
	return NULL;
}

void queue_request(struct sd_request *req)
{
	struct sd_cluster *c = req->cluster;

	sd_write_lock(&c->request_lock);
	list_add_tail(&req->list, &c->request_list);
	sd_rw_unlock(&c->request_lock);

	eventfd_xwrite(c->request_fd, 1);
}

void free_request(struct sd_request *req)
{
	close(req->efd);
	free(req);
}

struct sd_request *alloc_request(struct sd_cluster *c,
	void *data, size_t count, uint8_t op)
{
	struct sd_request *req;
	int fd;

	fd = eventfd(0, 0);
	if (fd < 0) {
		errno = SD_RES_SYSTEM_ERROR;
		return NULL;
	}
	req = xzalloc(sizeof(*req));
	req->efd = fd;
	req->cluster = c;
	req->data = data;
	req->length = count;
	req->opcode = op;
	INIT_LIST_NODE(&req->list);

	return req;
}

int sd_vdi_read(struct sd_cluster *c, struct sd_vdi *vdi,
			void *buf, size_t count, off_t offset)
{
	struct sd_request *req = alloc_request(c, buf,
					count, VDI_READ);
	int ret;

	if (!req)
		return errno;

	req->vdi = vdi;
	req->offset = offset;
	queue_request(req);

	eventfd_xread(req->efd);
	ret = req->ret;
	free_request(req);

	return ret;
}

int sd_vdi_write(struct sd_cluster *c, struct sd_vdi *vdi, void *buf,
			size_t count, off_t offset)
{
	struct sd_request *req = alloc_request(c, buf,
					count, VDI_WRITE);
	int ret;

	if (!req)
		return errno;

	req->vdi = vdi;
	req->offset = offset;
	queue_request(req);

	eventfd_xread(req->efd);
	ret = req->ret;
	free_request(req);

	return ret;
}

int sd_vdi_close(struct sd_cluster *c, struct sd_vdi *vdi)
{
	int ret;

	ret = unlock_vdi(c, vdi);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to unlock %s\n", vdi->name);
		return ret;
	}
	free_vdi(vdi);
	return 0;
}

static int do_vdi_create(struct sd_cluster *c, char *name, uint64_t vdi_size,
	uint32_t base_vid, bool snapshot,
	uint8_t nr_copies, uint8_t copy_policy,
	uint8_t store_policy, uint8_t block_size_shift)
{
	struct sd_req hdr = {};
	int ret;

	sd_init_req(&hdr, SD_OP_NEW_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = SD_MAX_VDI_LEN;

	hdr.vdi.base_vdi_id = base_vid;
	hdr.vdi.snapid = snapshot ? 1 : 0;
	hdr.vdi.vdi_size = vdi_size;
	hdr.vdi.copies = nr_copies;
	hdr.vdi.copy_policy = copy_policy;
	hdr.vdi.store_policy = store_policy;
	hdr.vdi.block_size_shift = block_size_shift;

	ret = sd_run_sdreq(c, &hdr, name);

	return ret;
}

static int write_object(struct sd_cluster *c, uint64_t oid, uint64_t cow_oid,
	void *data, unsigned int datalen, uint64_t offset, uint32_t flags,
	uint8_t copies, uint8_t copy_policy, bool create, bool direct)
{
	struct sd_req hdr = {};
	int ret;

	if (create)
		sd_init_req(&hdr, SD_OP_CREATE_AND_WRITE_OBJ);
	else
		sd_init_req(&hdr, SD_OP_WRITE_OBJ);

	hdr.data_length = datalen;
	hdr.flags = flags | SD_FLAG_CMD_WRITE;

	if (cow_oid)
		hdr.flags |= SD_FLAG_CMD_COW;
	if (direct)
		hdr.flags |= SD_FLAG_CMD_DIRECT;

	hdr.obj.copies = copies;
	hdr.obj.copy_policy = copy_policy;
	hdr.obj.oid = oid;
	hdr.obj.cow_oid = cow_oid;
	hdr.obj.offset = offset;

	ret = sd_run_sdreq(c, &hdr, data);

	return ret;
}

static int read_object(struct sd_cluster *c, uint64_t oid, void *data,
		unsigned int datalen, uint64_t offset, bool direct)
{
	struct sd_req hdr = {};
	int ret;

	sd_init_req(&hdr, SD_OP_READ_OBJ);
	hdr.data_length = datalen;
	hdr.obj.oid = oid;
	hdr.obj.offset = offset;
	if (direct)
		hdr.flags |= SD_FLAG_CMD_DIRECT;

	ret = sd_run_sdreq(c, &hdr, data);

	return ret;
}

static int find_vdi(struct sd_cluster *c, char *name,
		char *tag, uint32_t *vid)
{
	struct sd_req hdr = {};
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	char buf[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];
	int ret;

	memset(buf, 0, sizeof(buf));
	pstrcpy(buf, SD_MAX_VDI_LEN, name);
	if (tag)
		pstrcpy(buf + SD_MAX_VDI_LEN, SD_MAX_VDI_TAG_LEN, tag);

	sd_init_req(&hdr, SD_OP_GET_VDI_INFO);
	hdr.data_length = SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE;

	ret = sd_run_sdreq(c, &hdr, buf);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (vid)
		*vid = rsp->vdi.vdi_id;

	return SD_RES_SUCCESS;
}

static int vdi_read_inode(struct sd_cluster *c, char *name,
		char *tag, struct sd_inode *inode, bool onlyheader)
{
	int ret;
	uint32_t vid = 0;
	size_t len;

	ret = find_vdi(c, name, tag, &vid);
	if (ret != SD_RES_SUCCESS)
		return ret;

	if (onlyheader)
		len = SD_INODE_HEADER_SIZE;
	else
		len = SD_INODE_SIZE;

	ret = read_object(c, vid_to_vdi_oid(vid), inode, len, 0, true);

	return SD_RES_SUCCESS;
}

/** FIXME: tgtd multi-path support **/
int sd_vdi_snapshot(struct sd_cluster *c, char *name, char *snap_tag)
{
	char buf[SD_INODE_HEADER_SIZE];
	struct sd_inode *inode = (struct sd_inode *)buf;
	int ret = 0;

	if (!name || *name == '\0') {
		fprintf(stderr, "VDI name can NOT be null\n");
		return SD_RES_INVALID_PARMS;
	}
	if (!snap_tag || *snap_tag == '\0') {
		fprintf(stderr, "Snapshot tag can NOT be null for snapshot\n");
		return SD_RES_INVALID_PARMS;
	}

	ret = find_vdi(c, name, snap_tag, NULL);
	if (ret == SD_RES_SUCCESS) {
			fprintf(stderr, "VDI %s(tag: %s) is already existed\n",
				name, snap_tag);
			return SD_RES_INVALID_PARMS;

	} else if (ret == SD_RES_NO_TAG) {
		ret = vdi_read_inode(c, name, NULL, inode, true);
		if (ret != SD_RES_SUCCESS)
			return ret;

	} else {
		fprintf(stderr, "Failed to create snapshot:%s\n",
				sd_strerror(ret));
		return ret;
	}

	if (inode->store_policy) {
		fprintf(stderr, "Creating a snapshot of hypervolume"
				" is not supported\n");
		return SD_RES_INVALID_PARMS;
	}

	ret = write_object(c, vid_to_vdi_oid(inode->vdi_id), 0, snap_tag,
			SD_MAX_VDI_TAG_LEN, offsetof(struct sd_inode, tag), 0,
			inode->nr_copies, inode->copy_policy, false, false);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to write object: %s\n",
				sd_strerror(ret));
		goto out;
	}

	ret = do_vdi_create(c, inode->name, inode->vdi_size,
			inode->vdi_id, true, inode->nr_copies,
			inode->copy_policy,	inode->store_policy,
			inode->block_size_shift);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to create VDI: %s\n", sd_strerror(ret));
		goto out;
	}

out:
	return ret;
}

int sd_vdi_create(struct sd_cluster *c, char *name, uint64_t size)
{
	struct sd_req hdr = {};
	struct cluster_info ci;
	int ret;

	if (size > SD_MAX_VDI_SIZE) {
		fprintf(stderr, "VDI size is too large\n");
		return SD_RES_INVALID_PARMS;
	} else if (size == 0) {
		fprintf(stderr, "VDI size can NOT be ZERO\n");
		return SD_RES_INVALID_PARMS;
	}

	if (!name || *name == '\0') {
		fprintf(stderr, "VDI name can NOT be null\n");
		return SD_RES_INVALID_PARMS;
	}

	sd_init_req(&hdr, SD_OP_CLUSTER_INFO);
	hdr.data_length = sizeof(ci);
	ret = sd_run_sdreq(c, &hdr, &ci);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to get cluster info: %s\n",
				sd_strerror(ret));
		return ret;
	}
	if (!ci.ctime) {
		fprintf(stderr, "%s\n", sd_strerror(SD_RES_WAIT_FOR_FORMAT));
		return SD_RES_WAIT_FOR_FORMAT;
	}

	uint8_t store_policy = 0;
	if (size > SD_OLD_MAX_VDI_SIZE)
		store_policy = 1;/** for hyper volume **/

	ret = do_vdi_create(c, name, size,
			0, false, ci.nr_copies, ci.copy_policy,
			store_policy, SD_DEFAULT_BLOCK_SIZE_SHIFT);
	if (ret != SD_RES_SUCCESS)
		fprintf(stderr, "Failed to create VDI %s: %s\n",
				name, sd_strerror(ret));

	return ret;
}

int sd_vdi_clone(struct sd_cluster *c, char *srcname,
		char *srctag, char *dstname)
{
	int ret;
	struct sd_inode *inode = NULL;

	if (!srcname || *srcname == '\0') {
		ret = SD_RES_INVALID_PARMS;
		fprintf(stderr, "VDI name can NOT  be null\n");
		goto out;
	}
	if (!dstname || *dstname == '\0') {
		ret = SD_RES_INVALID_PARMS;
		fprintf(stderr, "Destination VDI name can NOT  be null\n");
		goto out;
	}
	if (!srctag || *srctag == '\0') {
		ret = SD_RES_INVALID_PARMS;
		fprintf(stderr, "Snapshot tag can NOT be null when clone\n");
		goto out;
	}

	inode = xmalloc(sizeof(struct sd_inode));
	ret = vdi_read_inode(c, srcname, srctag, inode, false);
	if (ret != SD_RES_SUCCESS)
		goto out;

	ret = do_vdi_create(c, dstname, inode->vdi_size, inode->vdi_id, false,
			   inode->nr_copies, inode->copy_policy,
			   inode->store_policy, inode->block_size_shift);
	if (ret != SD_RES_SUCCESS)
		fprintf(stderr, "Clone VDI failed: %s\n", sd_strerror(ret));

out:
	free(inode);
	return ret;
}

#define NR_BATCHED_DISCARD 128	/* TODO: the value should be optional */

int sd_vdi_delete(struct sd_cluster *c, char *name, char *tag)
{
	int ret;
	struct sd_req hdr = {};
	char data[SD_MAX_VDI_LEN + SD_MAX_VDI_TAG_LEN];
	uint32_t vid;
	struct sd_inode *inode = NULL;

	if (!name || *name == '\0') {
		ret = SD_RES_INVALID_PARMS;
		fprintf(stderr, "VDI name can NOT be null\n");
		goto out;
	}

	ret = find_vdi(c, name, tag, &vid);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Maybe VDI %s(tag: %s) does NOT exist: %s\n",
				name, tag, sd_strerror(ret));
		goto out;
	}

	sd_init_req(&hdr, SD_OP_DELETE_CACHE);
	hdr.obj.oid = vid_to_vdi_oid(vid);
	ret = sd_run_sdreq(c, &hdr, NULL);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to delete cache :%s\n",
				sd_strerror(ret));
		goto out;
	}

	inode = xmalloc(sizeof(*inode));
	ret = vdi_read_inode(c, name, tag, inode, false);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to read inode : %s\n",
				sd_strerror(ret));
		goto out;
	}
	int i = 0, nr_obj = count_data_objs(inode);
	while (i < nr_obj) {
		int start_idx, filled_idx;
		while (i < nr_obj && !inode->data_vdi_id[i])
			++i;

		start_idx = i;
		filled_idx = 0;
		while (i < nr_obj && filled_idx < NR_BATCHED_DISCARD) {
			if (inode->data_vdi_id[i]) {
				inode->data_vdi_id[i] = 0;
				++filled_idx;
			}

			++i;
		}

		ret = write_object(c, vid_to_vdi_oid(vid), 0,
				&inode->data_vdi_id[start_idx],
				(i - start_idx) * sizeof(uint32_t),
				offsetof(struct sd_inode,
				data_vdi_id[start_idx]),
				0, inode->nr_copies, inode->copy_policy,
				false, true);
		if (ret != SD_RES_SUCCESS) {
			fprintf(stderr,
					"failed to update inode for discarding\n");
			goto out;
		}
	}

	sd_init_req(&hdr, SD_OP_DEL_VDI);
	hdr.flags = SD_FLAG_CMD_WRITE;
	hdr.data_length = sizeof(data);
	memset(data, 0, sizeof(data));
	pstrcpy(data, SD_MAX_VDI_LEN, name);
	if (tag)
		pstrcpy(data + SD_MAX_VDI_LEN, SD_MAX_VDI_TAG_LEN, tag);

	ret = sd_run_sdreq(c, &hdr, data);
	if (ret != SD_RES_SUCCESS)
		fprintf(stderr, "Failed to delete %s: %s\n",
				name, sd_strerror(ret));

out:
	free(inode);
	return ret;
}

int sd_vdi_rollback(struct sd_cluster *c, char *name, char *tag)
{
	int ret;
	char buf[SD_INODE_HEADER_SIZE];
	struct sd_inode *inode = (struct sd_inode *)buf;

	if (!tag || *tag == '\0') {
		fprintf(stderr, "Snapshot tag can NOT be null for rollback\n");
		return SD_RES_INVALID_PARMS;
	}
	if (!name || *name == '\0') {
		fprintf(stderr, "VDI name can NOT be null\n");
		return SD_RES_INVALID_PARMS;
	}

	ret = find_vdi(c, name, NULL, NULL);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Working VDI %s does NOT exist\n", name);
		return SD_RES_INVALID_PARMS;
	}

	ret = find_vdi(c, name, tag, NULL);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Snapshot VDI %s(tag: %s) does NOT exist\n",
				name, tag);
		return SD_RES_INVALID_PARMS;
	}

	ret = vdi_read_inode(c, name, tag, inode, true);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Read inode for VDI %s failed: %s\n",
				name, sd_strerror(ret));
		return ret;
	}

	ret = sd_vdi_delete(c, name, NULL);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to delete current VDI state: %s\n",
				sd_strerror(ret));
		return ret;
	}

	ret = do_vdi_create(c, name, inode->vdi_size, inode->vdi_id,
			false, inode->nr_copies, inode->copy_policy,
			inode->store_policy, inode->block_size_shift);

	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "Failed to rollback VDI: %s\n",
				sd_strerror(ret));
		return ret;
	}

	return SD_RES_SUCCESS;
}
