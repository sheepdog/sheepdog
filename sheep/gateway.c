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

struct req_iter {
	uint8_t *buf;
	uint32_t wlen;
	uint32_t dlen;
	uint64_t off;
};

static struct req_iter *prepare_replication_requests(struct request *req,
						     int *nr)
{
	int nr_copies = get_req_copy_number(req);
	void *data = req->data;
	uint32_t len = req->rq.data_length;
	uint64_t off = req->rq.obj.offset;
	struct req_iter *reqs = xzalloc(sizeof(*reqs) * nr_copies);

	sd_debug("%"PRIx64, req->rq.obj.oid);

	*nr = nr_copies;
	for (int i = 0; i < nr_copies; i++) {
		reqs[i].buf = data;
		reqs[i].dlen = len;
		reqs[i].off = off;
		reqs[i].wlen = len;
	}
	return reqs;
}

static struct req_iter *prepare_requests(struct request *req, int *nr)
{
	return prepare_replication_requests(req, nr);
}

static void finish_requests(struct req_iter *reqs)
{
	free(reqs);
}

/*
 * Try our best to read one copy and read local first.
 *
 * Return success if any read succeed. We don't call gateway_forward_request()
 * because we only read once.
 */
static int gateway_replication_read(struct request *req)
{
	int i, ret = SD_RES_SUCCESS;
	struct sd_req fwd_hdr;
	struct sd_rsp *rsp = (struct sd_rsp *)&fwd_hdr;
	const struct sd_vnode *v;
	const struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	uint64_t oid = req->rq.obj.oid;
	int nr_copies, j;

	nr_copies = get_req_copy_number(req);

	oid_to_vnodes(oid, &req->vinfo->vroot, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		v = obj_vnodes[i];
		if (!vnode_is_local(v))
			continue;
		ret = peer_read_obj(req);
		if (ret == SD_RES_SUCCESS)
			goto out;

		sd_err("local read %"PRIx64" failed, %s", oid,
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
		ret = sheep_exec_req(&v->node->nid, &fwd_hdr, req->data);
		if (ret != SD_RES_SUCCESS)
			continue;

		/* Read success */
		memcpy(&req->rp, rsp, sizeof(*rsp));
		break;
	}
out:
	return ret;
}

struct forward_info_entry {
	struct pollfd pfd;
	const struct node_id *nid;
	struct sockfd *sfd;
	void *buf;
};

struct forward_info {
	struct forward_info_entry ent[SD_MAX_NODES];
	int nr_sent;
};

static inline void forward_info_update(struct forward_info *fi, int pos)
{
	sd_debug("%d, %d", fi->nr_sent, pos);
	fi->nr_sent--;
	memmove(fi->ent + pos, fi->ent + pos + 1,
		sizeof(struct forward_info_entry) * (fi->nr_sent - pos));
}

static inline void finish_one_entry(struct forward_info *fi, int i)
{
	sockfd_cache_put(fi->ent[i].nid, fi->ent[i].sfd);
	forward_info_update(fi, i);
}

static inline void finish_one_entry_err(struct forward_info *fi, int i)
{
	sockfd_cache_del(fi->ent[i].nid, fi->ent[i].sfd);
	forward_info_update(fi, i);
}

static inline struct forward_info_entry *
forward_info_find(struct forward_info *fi, int fd)
{
	for (int i = 0; i < fi->nr_sent; i++)
		if (fi->ent[i].pfd.fd == fd)
			return &fi->ent[i];

	panic("can't find entry for %d", fd);
	return NULL;
}

struct pfd_info {
	struct pollfd pfds[SD_MAX_NODES];
	int nr;
};

static inline void pfd_info_init(struct forward_info *fi, struct pfd_info *pi)
{
	int i;
	for (i = 0; i < fi->nr_sent; i++)
		pi->pfds[i] = fi->ent[i].pfd;
	pi->nr = fi->nr_sent;
}

/*
 * Wait for all forward requests completion.
 *
 * Even if something goes wrong, we have to wait forward requests completion to
 * avoid interleaved requests.
 *
 * Return error code if any one request fails.
 */
static int wait_forward_request(struct forward_info *fi, struct request *req)
{
	int nr_sent, err_ret = SD_RES_SUCCESS, ret, pollret, i,
	    repeat = MAX_RETRY_COUNT;
	struct pfd_info pi;
	struct sd_rsp *rsp = &req->rp;
again:
	pfd_info_init(fi, &pi);
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
			sd_warn("poll timeout %d, disks of some nodes or "
				"network is busy. Going to poll-wait again",
				fi->nr_sent);
			goto again;
		}

		nr_sent = fi->nr_sent;
		/* XXX Blinedly close all the connections */
		for (i = 0; i < nr_sent; i++)
			sockfd_cache_del(fi->ent[i].nid, fi->ent[i].sfd);

		return SD_RES_NETWORK_ERROR;
	}

	nr_sent = fi->nr_sent;
	for (i = 0; i < nr_sent; i++)
		if (pi.pfds[i].revents & POLLIN)
			break;
	if (i < nr_sent) {
		int re = pi.pfds[i].revents;
		sd_debug("%d, revents %x", i, re);
		if (re & (POLLERR | POLLHUP | POLLNVAL)) {
			err_ret = SD_RES_NETWORK_ERROR;
			finish_one_entry_err(fi, i);
			goto out;
		}
		if (do_read(pi.pfds[i].fd, rsp, sizeof(*rsp), sheep_need_retry,
			    req->rq.epoch, MAX_RETRY_COUNT)) {
			sd_err("remote node might have gone away");
			err_ret = SD_RES_NETWORK_ERROR;
			finish_one_entry_err(fi, i);
			goto out;
		}

		if (rsp->data_length) {
			struct forward_info_entry *ent;

			ent = forward_info_find(fi, pi.pfds[i].fd);
			if (do_read(pi.pfds[i].fd, ent->buf, rsp->data_length,
				    sheep_need_retry, req->rq.epoch,
				    MAX_RETRY_COUNT)) {
				sd_err("remote node might have gone away");
				err_ret = SD_RES_NETWORK_ERROR;
				finish_one_entry_err(fi, i);
				goto out;
			}
		}
		ret = rsp->result;
		if (ret != SD_RES_SUCCESS) {
			sd_err("fail %"PRIx64", %s", req->rq.obj.oid,
			       sd_strerror(ret));
			err_ret = ret;
		}
		finish_one_entry(fi, i);
	}
out:
	if (fi->nr_sent > 0)
		goto again;

	return err_ret;
}

static inline void forward_info_init(struct forward_info *fi, size_t nr_to_send)
{
	int i;
	for (i = 0; i < nr_to_send; i++)
		fi->ent[i].pfd.fd = -1;
	fi->nr_sent = 0;
}

static inline void
forward_info_advance(struct forward_info *fi, const struct node_id *nid,
		     struct sockfd *sfd, void *buf)
{
	fi->ent[fi->nr_sent].nid = nid;
	fi->ent[fi->nr_sent].pfd.fd = sfd->fd;
	fi->ent[fi->nr_sent].pfd.events = POLLIN;
	fi->ent[fi->nr_sent].sfd = sfd;
	fi->ent[fi->nr_sent].buf = buf;
	fi->nr_sent++;
}

static int gateway_forward_request(struct request *req)
{
	int i, err_ret = SD_RES_SUCCESS, ret;
	unsigned wlen;
	uint64_t oid = req->rq.obj.oid;
	struct forward_info fi;
	struct sd_req hdr;
	const struct sd_node *target_nodes[SD_MAX_NODES];
	int nr_copies = get_req_copy_number(req), nr_to_send = 0;
	struct req_iter *reqs = NULL;

	sd_debug("%"PRIx64, oid);

	gateway_init_fwd_hdr(&hdr, &req->rq);
	oid_to_nodes(oid, &req->vinfo->vroot, nr_copies, target_nodes);
	forward_info_init(&fi, nr_copies);
	reqs = prepare_requests(req, &nr_to_send);

	for (i = 0; i < nr_to_send; i++) {
		struct sockfd *sfd;
		const struct node_id *nid;

		nid = &target_nodes[i]->nid;
		sfd = sockfd_cache_get(nid);
		if (!sfd) {
			err_ret = SD_RES_NETWORK_ERROR;
			break;
		}

		hdr.data_length = reqs[i].dlen;
		wlen = reqs[i].wlen;
		hdr.obj.offset = reqs[i].off;
		ret = send_req(sfd->fd, &hdr, reqs[i].buf, wlen,
			       sheep_need_retry, req->rq.epoch,
			       MAX_RETRY_COUNT);
		if (ret) {
			sockfd_cache_del_node(nid);
			err_ret = SD_RES_NETWORK_ERROR;
			sd_debug("fail %d", ret);
			break;
		}
		forward_info_advance(&fi, nid, sfd, reqs[i].buf);
	}

	sd_debug("nr_sent %d, err %x", fi.nr_sent, err_ret);
	if (fi.nr_sent > 0) {
		ret = wait_forward_request(&fi, req);
		if (ret != SD_RES_SUCCESS)
			err_ret = ret;
	}

	finish_requests(reqs);
	return err_ret;
}

int gateway_read_obj(struct request *req)
{
	if (!bypass_object_cache(req))
		return object_cache_handle_request(req);

	return gateway_replication_read(req);
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
