/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 * Copyright (C) 2012-2013 Taobao Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheep_priv.h"

static inline void gateway_init_fwd_hdr(struct sd_req *fwd, struct sd_req *hdr)
{
	memcpy(fwd, hdr, sizeof(*fwd));
	fwd->opcode = gateway_to_peer_opcode(hdr->opcode);
	fwd->proto_ver = SD_SHEEP_PROTO_VER;
}

/*
 * Try our best to read one copy and read local first.
 *
 * Return success if any read succeed. We don't call gateway_forward_request()
 * because we only read once.
 */
int gateway_read_obj(struct request *req)
{
	int i, ret = SD_RES_SUCCESS;
	struct sd_req fwd_hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&fwd_hdr;
	const struct sd_vnode *v;
	const struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	uint64_t oid = req->rq.obj.oid;
	int nr_copies, j;

	if (sys->enable_object_cache && !req->local &&
	    !bypass_object_cache(req)) {
		ret = object_cache_handle_request(req);
		goto out;
	}

	nr_copies = get_req_copy_number(req);

	if (nr_copies == 0) {
		sd_dprintf("there is no living nodes");
		return SD_RES_HALT;
	}

	oid_to_vnodes(req->vinfo->vnodes, req->vinfo->nr_vnodes, oid,
		      nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (!vnode_is_local(v))
			continue;
		ret = peer_read_obj(req);
		if (ret == SD_RES_SUCCESS)
			goto out;

		sd_eprintf("local read %"PRIx64" failed, %s", oid,
			   sd_strerror(ret));
		break;
	}

	/*
	 * Read random copy from cluster for better load balance, useful for
	 * reading base VM's COW objects
	 */
	j = random();
	for (i = 0; i < nr_copies; i++) {
		int idx = (i + j) % nr_copies;

		v = obj_vnodes[idx];
		if (vnode_is_local(v))
			continue;
		/*
		 * We need to re-init it because rsp and req share the same
		 * structure.
		 */
		gateway_init_fwd_hdr(&fwd_hdr, &req->rq);
		ret = sheep_exec_req(&v->nid, &fwd_hdr, req->data);
		if (ret != SD_RES_SUCCESS)
			continue;

		/* Read success */
		memcpy(&req->rp, rsp, sizeof(*rsp));
		break;
	}
out:
	if (ret == SD_RES_SUCCESS &&
	    req->rq.proto_ver < SD_PROTO_VER_TRIM_ZERO_SECTORS) {
		/* the client doesn't support trimming zero bytes */
		untrim_zero_blocks(req->data, req->rp.obj.offset,
				   req->rp.data_length, req->rq.data_length);
		req->rp.data_length = req->rq.data_length;
		req->rp.obj.offset = 0;
	}
	return ret;
}

struct write_info_entry {
	struct pollfd pfd;
	const struct node_id *nid;
	struct sockfd *sfd;
};

struct write_info {
	struct write_info_entry ent[SD_MAX_NODES];
	int nr_sent;
};

static inline void write_info_update(struct write_info *wi, int pos)
{
	sd_dprintf("%d, %d", wi->nr_sent, pos);
	wi->nr_sent--;
	memmove(wi->ent + pos, wi->ent + pos + 1,
		sizeof(struct write_info_entry) * (wi->nr_sent - pos));
}

static inline void finish_one_write(struct write_info *wi, int i)
{
	sockfd_cache_put(wi->ent[i].nid, wi->ent[i].sfd);
	write_info_update(wi, i);
}

static inline void finish_one_write_err(struct write_info *wi, int i)
{
	sockfd_cache_del(wi->ent[i].nid, wi->ent[i].sfd);
	write_info_update(wi, i);
}

struct pfd_info {
	struct pollfd pfds[SD_MAX_NODES];
	int nr;
};

static inline void pfd_info_init(struct write_info *wi, struct pfd_info *pi)
{
	int i;
	for (i = 0; i < wi->nr_sent; i++)
		pi->pfds[i] = wi->ent[i].pfd;
	pi->nr = wi->nr_sent;
}

/*
 * Wait for all forward requests completion.
 *
 * Even if something goes wrong, we have to wait forward requests completion to
 * avoid interleaved requests.
 *
 * Return error code if any one request fails.
 */
static int wait_forward_request(struct write_info *wi, struct request *req)
{
	int nr_sent, err_ret = SD_RES_SUCCESS, ret, pollret, i,
	    repeat = MAX_RETRY_COUNT;
	struct pfd_info pi;
	struct sd_rsp *rsp = &req->rp;
again:
	pfd_info_init(wi, &pi);
	pollret = poll(pi.pfds, pi.nr, 1000 * POLL_TIMEOUT);
	if (pollret < 0) {
		if (errno == EINTR)
			goto again;

		panic("%m");
	} else if (pollret == 0) {
		/*
		 * If IO NIC is down, epoch isn't incremented, so we can't retry
		 * for ever.
		 */
		if (sheep_need_retry(req->rq.epoch) && repeat) {
			repeat--;
			sd_printf(SDOG_WARNING,
				  "poll timeout %d, disks of some nodes or"
				   " network is busy. Going to poll-wait again",
				   wi->nr_sent);
			goto again;
		}

		nr_sent = wi->nr_sent;
		/* XXX Blinedly close all the connections */
		for (i = 0; i < nr_sent; i++)
			sockfd_cache_del(wi->ent[i].nid, wi->ent[i].sfd);

		return SD_RES_NETWORK_ERROR;
	}

	nr_sent = wi->nr_sent;
	for (i = 0; i < nr_sent; i++)
		if (pi.pfds[i].revents & POLLIN)
			break;
	if (i < nr_sent) {
		int re = pi.pfds[i].revents;
		sd_dprintf("%d, revents %x", i, re);
		if (re & (POLLERR | POLLHUP | POLLNVAL)) {
			err_ret = SD_RES_NETWORK_ERROR;
			finish_one_write_err(wi, i);
			goto finish_write;
		}
		if (do_read(pi.pfds[i].fd, rsp, sizeof(*rsp), sheep_need_retry,
			    req->rq.epoch, MAX_RETRY_COUNT)) {
			sd_eprintf("remote node might have gone away");
			err_ret = SD_RES_NETWORK_ERROR;
			finish_one_write_err(wi, i);
			goto finish_write;
		}

		ret = rsp->result;
		if (ret != SD_RES_SUCCESS) {
			sd_eprintf("fail %"PRIx64", %s", req->rq.obj.oid,
				   sd_strerror(ret));
			err_ret = ret;
		}
		finish_one_write(wi, i);
	}
finish_write:
	if (wi->nr_sent > 0)
		goto again;

	return err_ret;
}

static inline void write_info_init(struct write_info *wi, size_t nr_to_send)
{
	int i;
	for (i = 0; i < nr_to_send; i++)
		wi->ent[i].pfd.fd = -1;
	wi->nr_sent = 0;
}

static inline void
write_info_advance(struct write_info *wi, const struct node_id *nid,
		   struct sockfd *sfd)
{
	wi->ent[wi->nr_sent].nid = nid;
	wi->ent[wi->nr_sent].pfd.fd = sfd->fd;
	wi->ent[wi->nr_sent].pfd.events = POLLIN;
	wi->ent[wi->nr_sent].sfd = sfd;
	wi->nr_sent++;
}

static int init_target_nodes(struct request *req, uint64_t oid,
			     const struct sd_node **target_nodes)
{
	int nr_to_send;
	const struct vnode_info *vinfo = req->vinfo;

	nr_to_send = get_req_copy_number(req);
	oid_to_nodes(vinfo->vnodes, vinfo->nr_vnodes, oid, nr_to_send,
		     vinfo->nodes, target_nodes);

	return nr_to_send;
}

static int gateway_forward_request(struct request *req)
{
	int i, err_ret = SD_RES_SUCCESS, ret, local = -1;
	unsigned wlen;
	uint64_t oid = req->rq.obj.oid;
	int nr_to_send;
	struct write_info wi;
	const struct sd_op_template *op;
	struct sd_req hdr;
	const struct sd_node *target_nodes[SD_MAX_NODES];

	sd_dprintf("%"PRIx64, oid);

	gateway_init_fwd_hdr(&hdr, &req->rq);
	op = get_sd_op(hdr.opcode);

	wlen = hdr.data_length;
	nr_to_send = init_target_nodes(req, oid, target_nodes);
	write_info_init(&wi, nr_to_send);

	if (nr_to_send == 0) {
		sd_dprintf("there is no living nodes");
		return SD_RES_HALT;
	}

	for (i = 0; i < nr_to_send; i++) {
		struct sockfd *sfd;
		const struct node_id *nid;

		if (node_is_local(target_nodes[i])) {
			local = i;
			continue;
		}

		nid = &target_nodes[i]->nid;
		sfd = sockfd_cache_get(nid);
		if (!sfd) {
			err_ret = SD_RES_NETWORK_ERROR;
			break;
		}

		ret = send_req(sfd->fd, &hdr, req->data, wlen,
			       sheep_need_retry, req->rq.epoch,
			       MAX_RETRY_COUNT);
		if (ret) {
			sockfd_cache_del_node(nid);
			err_ret = SD_RES_NETWORK_ERROR;
			sd_dprintf("fail %d", ret);
			break;
		}
		write_info_advance(&wi, nid, sfd);
	}

	if (local != -1 && err_ret == SD_RES_SUCCESS) {
		assert(op);
		ret = sheep_do_op_work(op, req);

		if (ret != SD_RES_SUCCESS) {
			sd_eprintf("fail to write local %"PRIx64", %s", oid,
				   sd_strerror(ret));
			err_ret = ret;
		}
	}

	sd_dprintf("nr_sent %d, err %x", wi.nr_sent, err_ret);
	if (wi.nr_sent > 0) {
		ret = wait_forward_request(&wi, req);
		if (ret != SD_RES_SUCCESS)
			err_ret = ret;
	}

	return err_ret;
}

int gateway_write_obj(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;

	if (oid_is_readonly(oid))
		return SD_RES_READONLY;

	if (!bypass_object_cache(req))
		return object_cache_handle_request(req);

	return gateway_forward_request(req);
}

int gateway_create_and_write_obj(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;

	if (oid_is_readonly(oid))
		return SD_RES_READONLY;

	if (!bypass_object_cache(req))
		return object_cache_handle_request(req);

	return gateway_forward_request(req);
}

int gateway_remove_obj(struct request *req)
{
	return gateway_forward_request(req);
}
