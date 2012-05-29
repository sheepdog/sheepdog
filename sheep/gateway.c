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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>

#include "sheep_priv.h"


static int bypass_object_cache(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;

	if (!(req->rq.flags & SD_FLAG_CMD_CACHE)) {
		uint32_t vid = oid_to_vid(oid);
		struct object_cache *cache;

		cache = find_object_cache(vid, 0);
		if (!cache)
			return 1;
		if (req->rq.flags & SD_FLAG_CMD_WRITE) {
			object_cache_flush_and_delete(req->vnodes, cache);
			return 1;
		} else  {
			/* For read requet, we can read cache if any */
			uint32_t idx = data_oid_to_idx(oid);
			if (is_vdi_obj(oid))
				idx |= 1 << CACHE_VDI_SHIFT;

			if (object_cache_lookup(cache, idx, 0) < 0)
				return 1;
			else
				return 0;
		}
	}

	/*
	 * For vmstate && vdi_attr object, we don't do caching
	 */
	if (is_vmstate_obj(oid) || is_vdi_attr_obj(oid) ||
	    req->rq.flags & SD_FLAG_CMD_COW)
		return 1;
	return 0;
}

static int object_cache_handle_request(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;
	uint32_t vid = oid_to_vid(oid);
	uint32_t idx = data_oid_to_idx(oid);
	struct object_cache *cache;
	int ret, create = 0;

	if (is_vdi_obj(oid))
		idx |= 1 << CACHE_VDI_SHIFT;

	cache = find_object_cache(vid, 1);

	if (req->rq.opcode == SD_OP_CREATE_AND_WRITE_OBJ)
		create = 1;

	if (object_cache_lookup(cache, idx, create) < 0) {
		ret = object_cache_pull(req->vnodes, cache, idx);
		if (ret != SD_RES_SUCCESS)
			return ret;
	}
	return object_cache_rw(cache, idx, req);
}

int forward_read_obj_req(struct request *req)
{
	int i, fd, ret = SD_RES_SUCCESS;
	unsigned wlen, rlen;
	struct sd_req fwd_hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&fwd_hdr;
	struct sd_vnode *v;
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	uint64_t oid = req->rq.obj.oid;
	int nr_copies;

	memcpy(&fwd_hdr, &req->rq, sizeof(fwd_hdr));
	fwd_hdr.flags |= SD_FLAG_CMD_IO_LOCAL;

	if (fwd_hdr.obj.copies)
		nr_copies = fwd_hdr.obj.copies;
	else
		nr_copies = get_nr_copies(req->vnodes);

	/* TODO: we can do better; we need to check this first */
	oid_to_vnodes(req->vnodes, oid, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			ret = do_local_io(req, fwd_hdr.epoch);
			if (ret != SD_RES_SUCCESS)
				goto read_remote;
			return ret;
		}
	}

read_remote:
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v))
			continue;

		fd = get_sheep_fd(v->addr, v->port, v->node_idx, fwd_hdr.epoch);
		if (fd < 0) {
			ret = SD_RES_NETWORK_ERROR;
			continue;
		}

		wlen = 0;
		rlen = fwd_hdr.data_length;

		ret = exec_req(fd, &fwd_hdr, req->data, &wlen, &rlen);

		if (ret) { /* network errors */
			del_sheep_fd(fd);
			ret = SD_RES_NETWORK_ERROR;
			continue;
		} else {
			memcpy(&req->rp, rsp, sizeof(*rsp));
			ret = rsp->result;
			break;
		}
	}
	return ret;
}

int forward_write_obj_req(struct request *req)
{
	int i, fd, ret, pollret;
	unsigned wlen;
	char name[128];
	struct sd_req fwd_hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&req->rp;
	struct sd_vnode *v;
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	uint64_t oid = req->rq.obj.oid;
	int nr_copies;
	struct pollfd pfds[SD_MAX_REDUNDANCY];
	int nr_fds, local = 0;

	dprintf("%"PRIx64"\n", oid);

	nr_fds = 0;
	memset(pfds, 0, sizeof(pfds));
	for (i = 0; i < ARRAY_SIZE(pfds); i++)
		pfds[i].fd = -1;

	memcpy(&fwd_hdr, &req->rq, sizeof(fwd_hdr));
	fwd_hdr.flags |= SD_FLAG_CMD_IO_LOCAL;

	wlen = fwd_hdr.data_length;

	nr_copies = get_nr_copies(req->vnodes);
	oid_to_vnodes(req->vnodes, oid, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];

		addr_to_str(name, sizeof(name), v->addr, 0);

		if (vnode_is_local(v)) {
			local = 1;
			continue;
		}

		fd = get_sheep_fd(v->addr, v->port, v->node_idx, fwd_hdr.epoch);
		if (fd < 0) {
			eprintf("failed to connect to %s:%"PRIu32"\n", name, v->port);
			ret = SD_RES_NETWORK_ERROR;
			goto out;
		}

		ret = send_req(fd, &fwd_hdr, req->data, &wlen);
		if (ret) { /* network errors */
			del_sheep_fd(fd);
			ret = SD_RES_NETWORK_ERROR;
			dprintf("fail %"PRIu32"\n", ret);
			goto out;
		}

		pfds[nr_fds].fd = fd;
		pfds[nr_fds].events = POLLIN;
		nr_fds++;
	}

	if (local) {
		ret = do_local_io(req, fwd_hdr.epoch);
		rsp->result = ret;

		if (nr_fds == 0) {
			eprintf("exit %"PRIu32"\n", ret);
			goto out;
		}

		if (rsp->result != SD_RES_SUCCESS) {
			eprintf("fail %"PRIu32"\n", ret);
			goto out;
		}
	}

	ret = SD_RES_SUCCESS;
again:
	pollret = poll(pfds, nr_fds, DEFAULT_SOCKET_TIMEOUT * 1000);
	if (pollret < 0) {
		if (errno == EINTR)
			goto again;

		ret = SD_RES_EIO;
	} else if (pollret == 0) { /* poll time out */
		eprintf("timeout\n");

		for (i = 0; i < nr_fds; i++)
			del_sheep_fd(pfds[i].fd);

		ret = SD_RES_NETWORK_ERROR;
		goto out;
	}

	for (i = 0; i < nr_fds; i++) {
		if (pfds[i].fd < 0)
			break;

		if (pfds[i].revents & POLLERR || pfds[i].revents & POLLHUP || pfds[i].revents & POLLNVAL) {
			del_sheep_fd(pfds[i].fd);
			ret = SD_RES_NETWORK_ERROR;
			break;
		}

		if (!(pfds[i].revents & POLLIN))
			continue;

		if (do_read(pfds[i].fd, rsp, sizeof(*rsp))) {
			eprintf("failed to read a response: %m\n");
			del_sheep_fd(pfds[i].fd);
			ret = SD_RES_NETWORK_ERROR;
			break;
		}

		if (rsp->result != SD_RES_SUCCESS) {
			eprintf("fail %"PRIu32"\n", rsp->result);
			ret = rsp->result;
		}

		break;
	}
	if (i < nr_fds) {
		nr_fds--;
		memmove(pfds + i, pfds + i + 1, sizeof(*pfds) * (nr_fds - i));
	}

	dprintf("%"PRIx64" %"PRIu32"\n", oid, nr_fds);

	if (nr_fds > 0) {
		goto again;
	}
out:
	return ret;
}

static int fix_object_consistency(struct request *req)
{
	int ret = SD_RES_NO_MEM;
	unsigned int data_length;
	struct sd_req *hdr = &req->rq;
	struct sd_req req_bak;
	struct sd_rsp rsp_bak;
	void *data = req->data, *buf;
	uint64_t oid = hdr->obj.oid;
	int old_opcode = hdr->opcode;

	memcpy(&req_bak, &req->rq, sizeof(req_bak));
	memcpy(&rsp_bak, &req->rp, sizeof(rsp_bak));

	if (is_vdi_obj(oid))
		data_length = SD_INODE_SIZE;
	else if (is_vdi_attr_obj(oid))
		data_length = SD_ATTR_OBJ_SIZE;
	else
		data_length = SD_DATA_OBJ_SIZE;

	buf = valloc(data_length);
	if (buf == NULL) {
		eprintf("failed to allocate memory\n");
		goto out;
	}
	memset(buf, 0, data_length);


	hdr->data_length = data_length;
	hdr->opcode = SD_OP_READ_OBJ;
	hdr->flags = 0;
	hdr->obj.offset = 0;

	req->data = buf;
	req->op = get_sd_op(SD_OP_READ_OBJ);

	ret = forward_read_obj_req(req);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to read object %x\n", ret);
		goto out;
	}

	hdr->opcode = SD_OP_CREATE_AND_WRITE_OBJ;
	hdr->flags = SD_FLAG_CMD_WRITE;
	hdr->obj.oid = oid;
	req->op = get_sd_op(hdr->opcode);
	ret = forward_write_obj_req(req);
	if (ret != SD_RES_SUCCESS) {
		eprintf("failed to write object %x\n", ret);
		goto out;
	}
out:
	free(buf);
	req->data = data;
	req->op = get_sd_op(old_opcode);

	memcpy(&req->rq, &req_bak, sizeof(req_bak));
	memcpy(&req->rp, &rsp_bak, sizeof(rsp_bak));

	return ret;
}

void do_gateway_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;

	dprintf("%x, %" PRIx64" , %u\n",
		req->rq.opcode, req->rq.obj.oid, req->rq.epoch);

	if (!sys->enable_write_cache || bypass_object_cache(req)) {
		/* fix object consistency when we read the object for the first time */
		if (req->check_consistency) {
			ret = fix_object_consistency(req);
			if (ret != SD_RES_SUCCESS)
				goto out;
		}
		if (req->rq.flags & SD_FLAG_CMD_WRITE)
			ret = forward_write_obj_req(req);
		else
			ret = forward_read_obj_req(req);
	} else {
		ret = object_cache_handle_request(req);
	}

out:
	if (ret != SD_RES_SUCCESS)
		dprintf("failed: %x, %" PRIx64" , %u, %"PRIx32"\n",
			req->rq.opcode, req->rq.obj.oid, req->rq.epoch, ret);
	req->rp.result = ret;
}
