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

/*
 * Try our best to read one copy and read local first.
 *
 * Return success if any read succeed.
 */
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

	oid_to_vnodes(req->vnodes, oid, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			ret = do_local_io(req, fwd_hdr.epoch);
			if (ret != SD_RES_SUCCESS) {
				goto read_remote;
				eprintf("local read fail %x\n", ret);
			}
			return ret;
		}
	}

read_remote:
	/*
	 * Read random copy from cluster for better load balance, useful for
	 * reading base VM's COW objects
	 */
	j = random();
	for (i = 0; i < nr_copies; i++) {
		int idx = (i + j) % nr_copies;
		int sock_idx;

		v = obj_vnodes[idx];
		if (vnode_is_local(v))
			continue;

		fd = sheep_get_fd(v, &sock_idx);
		if (fd < 0) {
			ret = SD_RES_NETWORK_ERROR;
			continue;
		}

		wlen = 0;
		rlen = fwd_hdr.data_length;

		ret = exec_req(fd, &fwd_hdr, req->data, &wlen, &rlen);

		if (!ret && rsp->result == SD_RES_SUCCESS) {
			memcpy(&req->rp, rsp, sizeof(*rsp));
			ret = rsp->result;
			sheep_put_fd(v, fd, sock_idx);
			break; /* Read success */
		}

		if (ret) {
			dprintf("remote node might have gone away");
			sheep_del_fd(v, fd, sock_idx);
			ret = SD_RES_NETWORK_ERROR;
		} else {
			ret = rsp->result;
			eprintf("remote read fail %x\n", ret);
			sheep_put_fd(v, fd, sock_idx);
		}
		/* Reset the hdr for next read */
		memcpy(&fwd_hdr, &req->rq, sizeof(fwd_hdr));
		fwd_hdr.flags |= SD_FLAG_CMD_IO_LOCAL;
	}
	return ret;
}

struct write_info {
	struct pollfd pfds[SD_MAX_REDUNDANCY];
	struct sd_vnode *vnodes[SD_MAX_REDUNDANCY];
	int sock_idx[SD_MAX_REDUNDANCY];
	int nr_sent;
};

static inline void update_write_info(struct write_info *wi, int pos)
{
	dprintf("%d, %d\n", wi->nr_sent, pos);
	wi->nr_sent--;
	memmove(wi->pfds + pos, wi->pfds + pos + 1,
		sizeof(struct pollfd) * (wi->nr_sent - pos));
	memmove(wi->vnodes + pos, wi->vnodes + pos + 1,
		sizeof(struct sd_vnode *) * (wi->nr_sent - pos));
	memmove(wi->sock_idx + pos, wi->sock_idx + pos + 1,
		sizeof(int) * (wi->nr_sent - pos));
}

static inline void finish_one_write(struct write_info *wi, int i)
{
	sheep_put_fd(wi->vnodes[i], wi->pfds[i].fd,
		     wi->sock_idx[i]);
	update_write_info(wi, i);
}

static inline void finish_one_write_err(struct write_info *wi, int i)
{
	sheep_del_fd(wi->vnodes[i], wi->pfds[i].fd,
		     wi->sock_idx[i]);
	update_write_info(wi, i);
}

/*
 * Wait for all forward writes completion.
 *
 * Even if something goes wrong, we have to wait forward write completion to
 * avoid interleaved requests.
 *
 * Return error code if any one request fails.
 */
static int wait_forward_write(struct write_info *wi, struct sd_rsp *rsp)
{
	int nr_sent, err_ret = SD_RES_SUCCESS, ret, pollret, i;
again:
	pollret = poll(wi->pfds, wi->nr_sent, -1);
	if (pollret < 0) {
		if (errno == EINTR)
			goto again;

		panic("%m\n");
	}

	nr_sent = wi->nr_sent;
	for (i = 0; i < nr_sent; i++)
		if (wi->pfds[i].revents & POLLIN)
			break;
	if (i < nr_sent) {
		int re = wi->pfds[i].revents;
		dprintf("%d, revents %x\n", i, re);
		if (re & (POLLERR | POLLHUP | POLLNVAL)) {
			err_ret = SD_RES_NETWORK_ERROR;
			finish_one_write_err(wi, i);
		} else if (re & POLLIN) {
			if (do_read(wi->pfds[i].fd, rsp, sizeof(*rsp))) {
				eprintf("remote node might have gone away\n");
				err_ret = SD_RES_NETWORK_ERROR;
				finish_one_write_err(wi, i);
				goto finish_write;
			}

			ret = rsp->result;
			if (ret != SD_RES_SUCCESS) {
				eprintf("fail %"PRIx32"\n", ret);
				err_ret = ret;
			}
			finish_one_write(wi, i);
		} else {
			eprintf("unhandled poll event\n");
		}
	}
finish_write:
	if (wi->nr_sent > 0)
		goto again;

	return err_ret;
}

static void init_write_info(struct write_info *wi)
{
	int i;
	for (i = 0; i < SD_MAX_REDUNDANCY; i++) {
		wi->pfds[i].fd = -1;
		wi->vnodes[i] = NULL;
	}
	wi->nr_sent = 0;
}

int forward_write_obj_req(struct request *req)
{
	int i, fd, err_ret = SD_RES_SUCCESS, ret, local = -1;
	unsigned wlen;
	struct sd_req fwd_hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&req->rp;
	struct sd_vnode *v;
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	uint64_t oid = req->rq.obj.oid;
	int nr_copies;
	struct write_info wi;

	dprintf("%"PRIx64"\n", oid);

	init_write_info(&wi);
	memcpy(&fwd_hdr, &req->rq, sizeof(fwd_hdr));
	fwd_hdr.flags |= SD_FLAG_CMD_IO_LOCAL;

	wlen = fwd_hdr.data_length;

	nr_copies = get_nr_copies(req->vnodes);
	oid_to_vnodes(req->vnodes, oid, nr_copies, obj_vnodes);

	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (vnode_is_local(v)) {
			local = i;
			continue;
		}

		fd = sheep_get_fd(v, &wi.sock_idx[wi.nr_sent]);
		if (fd < 0) {
			err_ret = SD_RES_NETWORK_ERROR;
			break;
		}

		ret = send_req(fd, &fwd_hdr, req->data, &wlen);
		if (ret) {
			sheep_del_fd(v, fd, wi.sock_idx[wi.nr_sent]);
			err_ret = SD_RES_NETWORK_ERROR;
			dprintf("fail %d\n", ret);
			break;
		}

		wi.vnodes[wi.nr_sent] = v;
		wi.pfds[wi.nr_sent].fd = fd;
		wi.pfds[wi.nr_sent].events = POLLIN;
		wi.nr_sent++;
	}

	if (local != -1 && err_ret == SD_RES_SUCCESS) {
		v = obj_vnodes[local];

		ret = do_local_io(req, fwd_hdr.epoch);

		if (ret != SD_RES_SUCCESS) {
			eprintf("fail to write local %"PRIx32"\n", ret);
			err_ret = ret;
		}
	}

	dprintf("nr_sent %d, err %x\n", wi.nr_sent, err_ret);
	if (wi.nr_sent > 0) {
		ret = wait_forward_write(&wi, rsp);
		if (ret != SD_RES_SUCCESS)
			err_ret = ret;
	}

	return err_ret;
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
