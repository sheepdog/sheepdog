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

static int lock_vdi(struct sd_vdi *vdi)
{
	struct sd_req hdr = {};
	struct sd_rsp *rsp = (struct sd_rsp *)&hdr;
	int ret;

	hdr.opcode = SD_OP_LOCK_VDI;
	hdr.data_length = SD_MAX_VDI_LEN;
	hdr.flags = SD_FLAG_CMD_WRITE;
	ret = sd_run_sdreq(vdi->cluster, &hdr, vdi->name);
	if (ret != SD_RES_SUCCESS)
		return ret;

	vdi->vid = rsp->vdi.vdi_id;

	return SD_RES_SUCCESS;
}

static int unlock_vdi(struct sd_vdi *vdi)
{
	struct sd_req hdr = {};
	int ret;

	hdr.opcode = SD_OP_RELEASE_VDI;
	hdr.vdi.type = LOCK_TYPE_NORMAL;
	hdr.vdi.base_vdi_id = vdi->vid;
	ret = sd_run_sdreq(vdi->cluster, &hdr, NULL);
	if (ret != SD_RES_SUCCESS)
		return ret;

	return SD_RES_SUCCESS;
}

static struct sd_vdi *alloc_vdi(struct sd_cluster *c, char *name)
{
	struct sd_vdi *new = xzalloc(sizeof(*new));

	new->cluster = c;
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

	ret = lock_vdi(new);
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
	unlock_vdi(new);
out_free:
	free_vdi(new);
	return NULL;
}

static void queue_request(struct sd_request *req)
{
	struct sd_cluster *c = req->vdi->cluster;

	sd_write_lock(&c->request_lock);
	list_add_tail(&req->list, &c->request_list);
	sd_rw_unlock(&c->request_lock);

	eventfd_xwrite(c->request_fd, 1);
}

static void free_request(struct sd_request *req)
{
	close(req->efd);
	free(req);
}

static struct sd_request *alloc_request(struct sd_vdi *vdi, void *buf,
			size_t count, off_t offset, bool iswrite)
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
	req->data = buf;
	req->length = count;
	req->offset = offset;
	req->write = iswrite;
	INIT_LIST_NODE(&req->list);
	req->vdi = vdi;

	return req;
}

int sd_vdi_read(struct sd_vdi *vdi, void *buf, size_t count, off_t offset)
{
	struct sd_request *req = alloc_request(vdi, buf, count, offset, false);
	int ret;

	if (!req)
		return errno;

	queue_request(req);

	eventfd_xread(req->efd);
	ret = req->ret;
	free_request(req);

	return ret;
}

int sd_vdi_write(struct sd_vdi *vdi, void *buf, size_t count, off_t offset)
{
	struct sd_request *req = alloc_request(vdi, buf, count, offset, true);
	int ret;

	if (!req)
		return errno;

	queue_request(req);

	eventfd_xread(req->efd);
	ret = req->ret;
	free_request(req);

	return ret;
}

int sd_vdi_close(struct sd_vdi *vdi)
{
	int ret;

	ret = unlock_vdi(vdi);
	if (ret != SD_RES_SUCCESS) {
		fprintf(stderr, "failed to unlock %s\n", vdi->name);
		return ret;
	}
	free_vdi(vdi);
	return 0;
}
