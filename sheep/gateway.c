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


int forward_read_obj_req(struct request *req)
{
	int i, fd, ret = SD_RES_SUCCESS;
	unsigned wlen, rlen;
	struct sd_req fwd_hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&fwd_hdr;
	struct sd_vnode *v;
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	uint64_t oid = req->rq.obj.oid;
	int nr_copies, j;

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
	/* Read random copy from cluster for better load balance, useful for
	 * reading base VM's COW objects
	 */
	j = random();
	for (i = 0; i < nr_copies; i++) {
		int idx = (i + j) % nr_copies;
		v = obj_vnodes[idx];
		if (vnode_is_local(v))
			continue;

		fd = sheep_get_fd(v);
		if (fd < 0) {
			ret = SD_RES_NETWORK_ERROR;
			continue;
		}

		wlen = 0;
		rlen = fwd_hdr.data_length;

		ret = exec_req(fd, &fwd_hdr, req->data, &wlen, &rlen);

		if (ret) { /* network errors */
			sheep_del_fd(v, fd);
			ret = SD_RES_NETWORK_ERROR;
			continue;
		} else {
			sheep_put_fd(v, fd);
			memcpy(&req->rp, rsp, sizeof(*rsp));
			ret = rsp->result;
			break;
		}
	}
	return ret;
}

struct write_info {
	struct pollfd pfds[SD_MAX_REDUNDANCY];
	struct sd_vnode *vnodes[SD_MAX_REDUNDANCY];
};

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
	int nr_fds = 0, local = 0;
	struct write_info wi;

	dprintf("%"PRIx64"\n", oid);

	memset(&wi, 0, sizeof(wi));
	for (i = 0; i < SD_MAX_REDUNDANCY; i++)
		wi.pfds[i].fd = -1;

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

		fd = sheep_get_fd(v);
		if (fd < 0) {
			ret = SD_RES_NETWORK_ERROR;
			goto err;
		}

		ret = send_req(fd, &fwd_hdr, req->data, &wlen);
		if (ret) { /* network errors */
			sheep_del_fd(v, fd);
			ret = SD_RES_NETWORK_ERROR;
			dprintf("fail %"PRIu32"\n", ret);
			goto err;
		}

		wi.vnodes[nr_fds] = v;
		wi.pfds[nr_fds].fd = fd;
		wi.pfds[nr_fds].events = POLLIN;
		nr_fds++;
	}

	if (local) {
		ret = do_local_io(req, fwd_hdr.epoch);
		rsp->result = ret;

		if (rsp->result != SD_RES_SUCCESS) {
			eprintf("fail to write local %"PRIu32"\n", ret);
			ret = rsp->result;
			goto err;
		}

		if (nr_fds == 0)
			goto out;
	}

	ret = SD_RES_SUCCESS;
again:
	pollret = poll(wi.pfds, nr_fds, -1);
	if (pollret < 0) {
		if (errno == EINTR)
			goto again;

		ret = SD_RES_NETWORK_ERROR;
		goto err;
	}

	for (i = 0; i < nr_fds; i++) {
		if (wi.pfds[i].revents & POLLERR ||
		    wi.pfds[i].revents & POLLHUP ||
		    wi.pfds[i].revents & POLLNVAL) {
			sheep_del_fd(wi.vnodes[i], wi.pfds[i].fd);
			ret = SD_RES_NETWORK_ERROR;
			break;
		}

		if (!(wi.pfds[i].revents & POLLIN))
			continue;

		if (do_read(wi.pfds[i].fd, rsp, sizeof(*rsp))) {
			eprintf("failed to read a response: %m\n");
			sheep_del_fd(wi.vnodes[i], wi.pfds[i].fd);
			ret = SD_RES_NETWORK_ERROR;
			break;
		}

		if (rsp->result != SD_RES_SUCCESS) {
			eprintf("fail %"PRIu32"\n", rsp->result);
			ret = rsp->result;
		}

		sheep_put_fd(wi.vnodes[i], wi.pfds[i].fd);
		break;
	}
	if (i < nr_fds) {
		nr_fds--;
		memmove(wi.pfds + i, wi.pfds + i + 1,
			sizeof(struct pollfd) * (nr_fds - i));
		memmove(wi.vnodes + i, wi.vnodes + i + 1,
			sizeof(struct sd_vnode *) * (nr_fds - i));
	}

	dprintf("%"PRIx64" %"PRIu32"\n", oid, nr_fds);

	if (nr_fds > 0)
		goto again;
out:
	return ret;
err:
	for (i = 0; i < nr_fds; i++)
		sheep_del_fd(wi.vnodes[i], wi.pfds[i].fd);
	return ret;
}

void do_gateway_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;

	dprintf("%x, %" PRIx64" , %u\n",
		req->rq.opcode, req->rq.obj.oid, req->rq.epoch);

	if (!sys->enable_write_cache || req->local ||
	    bypass_object_cache(req)) {
		if (req->rq.flags & SD_FLAG_CMD_WRITE)
			ret = forward_write_obj_req(req);
		else
			ret = forward_read_obj_req(req);
	} else {
		ret = object_cache_handle_request(req);
	}

	if (ret != SD_RES_SUCCESS)
		dprintf("failed: %x, %" PRIx64" , %u, %"PRIx32"\n",
			req->rq.opcode, req->rq.obj.oid, req->rq.epoch, ret);
	req->rp.result = ret;
}
