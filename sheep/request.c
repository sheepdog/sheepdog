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

#include <netinet/tcp.h>

#include "sheep_priv.h"

#define TRACEPOINT_DEFINE
#include "request_tp.h"

static void del_requeue_request(struct request *req)
{
	list_del(&req->request_list);
	requeue_request(req);
}

static bool is_access_local(struct request *req, uint64_t oid)
{
	const struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	int nr_copies;
	int i;

	nr_copies = get_req_copy_number(req);
	oid_to_vnodes(oid, &req->vinfo->vroot, nr_copies, obj_vnodes);
	for (i = 0; i < nr_copies; i++) {
		if (vnode_is_local(obj_vnodes[i]))
			return true;
	}

	return false;
}

static void io_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);

	switch (req->rp.result) {
	case SD_RES_EIO:
		req->rp.result = SD_RES_NETWORK_ERROR;

		sd_err("leaving sheepdog cluster");
		leave_cluster();
		break;
	case SD_RES_SUCCESS:
	case SD_RES_NETWORK_ERROR:
		break;
	default:
		sd_debug("unhandled error %s", sd_strerror(req->rp.result));
		break;
	}

	put_request(req);
	return;
}

/*
 * There are 4 cases that a request needs to sleep on wait queues for requeue:
 *
 *	1. Epoch of request sender is older than system epoch of receiver
 *	   In this case, we response the sender with SD_RES_OLD_NODE_VER to
 *	   sender so sender would put the request into its own wait queue to
 *	   wait its system epoch get lifted and resend the request.
 *
 *      2. Epoch of request sender is newer than system epoch of receiver
 *         In this case, we put the request into wait queue of receiver, to wait
 *         system epoch of receiver to get lifted, then retry this request on
 *         its own.
 *
 *      3. Object requested doesn't exist and recovery work is at RW_INIT state
 *         In this case, we check whether the requested object exists, if so,
 *         go process the request directly, if not put the request into wait
 *         queue of the receiver to wait for the finish of this oid recovery.
 *
 *      4. Object requested doesn't exist and is being recovered
 *         In this case, we put the request into wait queue of receiver and when
 *         we recover an object we try to wake up the request on this oid.
 */
static inline void sleep_on_wait_queue(struct request *req)
{
	list_add_tail(&req->request_list, &sys->req_wait_queue);
}

static void gateway_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_req *hdr = &req->rq;

	if (hdr->opcode == SD_OP_WRITE_OBJ && is_data_vid_update(hdr)) {
		struct request *rq;

		sys->nr_ongoing_inode_update_request--;
		sd_assert(0 <= sys->nr_ongoing_inode_update_request);
		sd_debug("a number of ongoing inode update request: %d",
			 sys->nr_ongoing_inode_update_request);

		if (!sys->nr_ongoing_inode_update_request) {
			list_for_each_entry(rq,
			    &sys->pending_prevent_inode_update_request_queue,
			    pending_prevent_inode_update_reqs) {
				list_del(
					&rq->pending_prevent_inode_update_reqs);
				put_request(rq);
			}
		}
	}

	switch (req->rp.result) {
	case SD_RES_OLD_NODE_VER:
		if (req->rp.epoch > sys->cinfo.epoch) {
			/*
			 * Gateway of this node is expected to process this
			 * request later when epoch is lifted.
			 */
			sleep_on_wait_queue(req);
			return;
		}
		/* FALL THROUGH */
	case SD_RES_NEW_NODE_VER:
	case SD_RES_NETWORK_ERROR:
	case SD_RES_WAIT_FOR_JOIN:
	case SD_RES_WAIT_FOR_FORMAT:
	case SD_RES_KILLED:
		sd_debug("retrying failed I/O request op %s result %x epoch %"
			 PRIu32 ", sys epoch %" PRIu32, op_name(req->op),
			 req->rp.result, req->rq.epoch, sys->cinfo.epoch);
		goto retry;
	case SD_RES_EIO:
		if (is_access_local(req, hdr->obj.oid)) {
			sd_err("leaving sheepdog cluster");
			leave_cluster();
			goto retry;
		}
		break;
	case SD_RES_SUCCESS:
		break;
	default:
		sd_debug("unhandled error %s", sd_strerror(req->rp.result));
		break;
	}

	put_request(req);
	return;
retry:
	requeue_request(req);
}

static void local_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);

	if (has_process_main(req->op)) {
		req->rp.result = do_process_main(req->op, &req->rq,
						 &req->rp, req->data,
						 &sys->this_node);
	}

	put_request(req);
}

static int check_request_epoch(struct request *req)
{
	if (before(req->rq.epoch, sys->cinfo.epoch)) {
		sd_err("old node version %u, %u (%s)", sys->cinfo.epoch,
		       req->rq.epoch, op_name(req->op));
		/* Ask for sleeping req on requester's wait queue */
		req->rp.result = SD_RES_OLD_NODE_VER;
		req->rp.epoch = sys->cinfo.epoch;
		put_request(req);
		return -1;
	} else if (after(req->rq.epoch, sys->cinfo.epoch)) {
		sd_err("new node version %u, %u (%s)", sys->cinfo.epoch,
		       req->rq.epoch, op_name(req->op));
		/* Wait for local epoch to be lifted */
		req->rp.result = SD_RES_NEW_NODE_VER;
		sleep_on_wait_queue(req);
		return -1;
	}

	return 0;
}

static bool request_in_recovery(struct request *req)
{

	/*
	 * For CREATE request, we simply service it.  CREATE operations are
	 * atomic, so it cannot happen for recover process to overwrite the
	 * created objects with the older data.
	 */
	if (req->rq.opcode == SD_OP_CREATE_AND_WRITE_PEER ||
	    req->rq.opcode == SD_OP_CREATE_AND_WRITE_OBJ)
		return false;

	if (req->rq.flags & SD_FLAG_CMD_RECOVERY)
		/*
		 * Recovery requests must not be linked to wait queue to avoid a
		 * dead lock.  Here is an example scenario.
		 *  1. Node A sends a recovery request to node B.
		 *  2. Node B links the request to the wait queue.
		 *  3. Node B sends a recovery request to node A to recover the
		 *     object.
		 *  4. Node A links the request to the wait queue, and the
		 *     object cannot be recovered on either A or B (dead lock).
		 */
		return false;

	if (oid_in_recovery(req->local_oid)) {
		sd_debug("%"PRIx64" wait on oid", req->local_oid);
		sleep_on_wait_queue(req);
		return true;
	}
	return false;
}

/* Wakeup requests because of epoch mismatch */
void wakeup_requests_on_epoch(void)
{
	struct request *req;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->req_wait_queue, &pending_list);

	list_for_each_entry(req, &pending_list, request_list) {
		switch (req->rp.result) {
		case SD_RES_OLD_NODE_VER:
			/*
			 * Gateway retries to send the request when
			 * its epoch changes.
			 */
			sd_assert(is_gateway_op(req->op));
			sd_debug("gateway %"PRIx64, req->rq.obj.oid);
			req->rq.epoch = sys->cinfo.epoch;
			del_requeue_request(req);
			break;
		case SD_RES_NEW_NODE_VER:
			/*
			 * Peer retries the request locally when its epoch
			 * changes.
			 */
			sd_assert(!is_gateway_op(req->op));
			sd_debug("peer %"PRIx64, req->rq.obj.oid);
			del_requeue_request(req);
			break;
		default:
			break;
		}
	}

	list_splice_init(&pending_list, &sys->req_wait_queue);
}

/* Wakeup the requests on the oid that was previously being recovered */
void wakeup_requests_on_oid(uint64_t oid)
{
	struct request *req;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->req_wait_queue, &pending_list);

	list_for_each_entry(req, &pending_list, request_list) {
		if (req->local_oid != oid)
			continue;
		sd_debug("retry %" PRIx64, req->local_oid);
		del_requeue_request(req);
	}
	list_splice_init(&pending_list, &sys->req_wait_queue);
}

void wakeup_all_requests(void)
{
	struct request *req;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->req_wait_queue, &pending_list);

	list_for_each_entry(req, &pending_list, request_list) {
		sd_debug("%"PRIx64, req->rq.obj.oid);
		del_requeue_request(req);
	}
}

static void queue_peer_request(struct request *req)
{
	req->local_oid = req->rq.obj.oid;
	if (req->local_oid) {
		if (check_request_epoch(req) < 0)
			return;
		if (request_in_recovery(req))
			return;
	}

	if (req->rq.flags & SD_FLAG_CMD_RECOVERY)
		req->rq.epoch = req->rq.obj.tgt_epoch;

	req->work.fn = do_process_work;
	req->work.done = io_op_done;
	queue_work(sys->io_wqueue, &req->work);
}

/*
 * We make sure we write the exact number of copies to honor the promise of the
 * redundancy for strict mode. This means that after writing of targeted data,
 * they are redundant as promised and can withstand the random node failures.
 *
 * For example, with a 4:2 policy, we need at least write to 6 nodes with data
 * strip and parity strips. For non-strict mode, we allow to write successfully
 * only if the data are written fully with 4 nodes alive.
 */
static bool has_enough_zones(struct request *req)
{
	uint64_t oid = req->rq.obj.oid;

	return req->vinfo->nr_zones >= get_vdi_copy_number(oid_to_vid(oid));
}

static void queue_gateway_request(struct request *req)
{
	struct sd_req *hdr = &req->rq;

	if (is_access_local(req, hdr->obj.oid))
		req->local_oid = hdr->obj.oid;

	/*
	 * If we go for cache object, we don't care if it is being recovered
	 * Even if it doesn't exist in cache, we'll rely on cache layer to pull
	 * it.
	 *
	 * Not true for local request because it might go for backend store
	 * such as pushing cache object, in this case we should check if request
	 * is in recovery.
	 */
	if (sys->enable_object_cache && !req->local)
		goto queue_work;

	if (req->local_oid)
		if (request_in_recovery(req))
			return;

queue_work:
	if (RB_EMPTY_ROOT(&req->vinfo->vroot)) {
		sd_err("there is no living nodes");
		goto end_request;
	}
	if (sys->cinfo.flags & SD_CLUSTER_FLAG_STRICT &&
	    (hdr->opcode == SD_OP_CREATE_AND_WRITE_OBJ ||
	     hdr->opcode == SD_OP_WRITE_OBJ) &&
	    !has_enough_zones(req)) {
		sd_err("not enough zones available");
		goto end_request;
	}

	if (req->rq.opcode == SD_OP_WRITE_OBJ && is_data_vid_update(&req->rq)) {
		if (sys->nr_prevent_inode_update) {
			sd_debug("preventing inode update");
			list_add_tail(&req->prevented_inode_update_request_list,
			      &sys->prevented_inode_update_request_queue);
			return;
		} else {
			sd_assert(0 <= sys->nr_ongoing_inode_update_request);
			sys->nr_ongoing_inode_update_request++;
			sd_debug("a number of ongoing inode update request: %d",
				 sys->nr_ongoing_inode_update_request);
		}
	}

	req->work.fn = do_process_work;
	req->work.done = gateway_op_done;
	queue_work(sys->gateway_wqueue, &req->work);
	return;

end_request:
	req->rp.result = SD_RES_HALT;
	put_request(req);
	return;
}

static void queue_local_request(struct request *req)
{
	req->work.fn = do_process_work;
	req->work.done = local_op_done;
	queue_work(sys->io_wqueue, &req->work);
}

static main_fn inline void stat_request_begin(struct request *req)
{
	struct sd_req *hdr = &req->rq;

	req->stat = true;

	if (is_peer_op(req->op)) {
		sys->stat.r.peer_total_nr++;
		sys->stat.r.peer_active_nr++;
		if (hdr->flags & SD_FLAG_CMD_WRITE)
			sys->stat.r.peer_total_rx += hdr->data_length;
		else
			sys->stat.r.peer_total_tx += hdr->data_length;

		switch (hdr->opcode) {
		case SD_OP_READ_PEER:
			sys->stat.r.peer_total_read_nr++;
			break;
		case SD_OP_WRITE_PEER:
		case SD_OP_CREATE_AND_WRITE_PEER:
			sys->stat.r.peer_total_write_nr++;
			break;
		case SD_OP_REMOVE_PEER:
			sys->stat.r.peer_total_remove_nr++;
			break;
		}
	} else if (is_gateway_op(req->op)) {
		sys->stat.r.gway_total_nr++;
		sys->stat.r.gway_active_nr++;
		if (hdr->flags & SD_FLAG_CMD_WRITE)
			sys->stat.r.gway_total_rx += hdr->data_length;
		else
			sys->stat.r.gway_total_tx += hdr->data_length;

		switch (hdr->opcode) {
		case SD_OP_READ_OBJ:
			sys->stat.r.gway_total_read_nr++;
			break;
		case SD_OP_WRITE_OBJ:
		case SD_OP_CREATE_AND_WRITE_OBJ:
			sys->stat.r.gway_total_write_nr++;
			break;
		case SD_OP_DISCARD_OBJ:
			sys->stat.r.gway_total_remove_nr++;
			break;
		}
	} else if (hdr->opcode == SD_OP_FLUSH_VDI) {
		sys->stat.r.gway_total_nr++;
		sys->stat.r.gway_active_nr++;
		sys->stat.r.gway_total_flush_nr++;
	}
}

static main_fn inline void stat_request_end(struct request *req)
{
	struct sd_req *hdr = &req->rq;

	if (!req->stat)
		return;

	if (is_peer_op(req->op))
		sys->stat.r.peer_active_nr--;
	else if (is_gateway_op(req->op))
		sys->stat.r.gway_active_nr--;
	else if (hdr->opcode == SD_OP_FLUSH_VDI)
		sys->stat.r.gway_active_nr--;
}

static void queue_request(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;

	/*
	 * Check the protocol version for all internal commands, and public
	 * commands that have it set.  We can't enforce it on all public
	 * ones as it isn't a mandatory part of the public protocol.
	 */
	if (hdr->opcode >= 0x80) {
		if (hdr->proto_ver != SD_SHEEP_PROTO_VER) {
			rsp->result = SD_RES_VER_MISMATCH;
			goto done;
		}
	} else if (hdr->proto_ver) {
		if (hdr->proto_ver > SD_PROTO_VER) {
			rsp->result = SD_RES_VER_MISMATCH;
			goto done;
		}
	}

	req->op = get_sd_op(hdr->opcode);
	if (!req->op) {
		sd_err("invalid opcode %d", hdr->opcode);
		rsp->result = SD_RES_INVALID_PARMS;
		goto done;
	}

	sd_debug("%s, %d", op_name(req->op), sys->cinfo.status);

	switch (sys->cinfo.status) {
	case SD_STATUS_KILLED:
		rsp->result = SD_RES_KILLED;
		goto done;
	case SD_STATUS_SHUTDOWN:
		rsp->result = SD_RES_SHUTDOWN;
		goto done;
	case SD_STATUS_WAIT:
		if (!is_force_op(req->op)) {
			if (sys->cinfo.ctime == 0)
				rsp->result = SD_RES_WAIT_FOR_FORMAT;
			else
				rsp->result = SD_RES_WAIT_FOR_JOIN;
			goto done;
		}
		break;
	default:
		break;
	}

	req->vinfo = get_vnode_info();
	stat_request_begin(req);
	if (is_peer_op(req->op)) {
		queue_peer_request(req);
	} else if (is_gateway_op(req->op)) {
		hdr->epoch = sys->cinfo.epoch;
		queue_gateway_request(req);
	} else if (is_local_op(req->op)) {
		hdr->epoch = sys->cinfo.epoch;
		queue_local_request(req);
	} else if (is_cluster_op(req->op)) {
		hdr->epoch = sys->cinfo.epoch;
		queue_cluster_request(req);
	} else {
		sd_err("unknown operation %d", hdr->opcode);
		rsp->result = SD_RES_SYSTEM_ERROR;
		goto done;
	}

	return;
done:
	put_request(req);
}

void requeue_request(struct request *req)
{
	if (req->vinfo) {
		put_vnode_info(req->vinfo);
		req->vinfo = NULL;
	}
	stat_request_end(req);
	queue_request(req);
}

static void clear_client_info(struct client_info *ci);

static struct request *alloc_local_request(void *data, int data_length)
{
	struct request *req;

	req = xzalloc(sizeof(struct request));
	if (data_length) {
		req->data_length = data_length;
		req->data = data;
	}

	req->local = true;

	refcount_set(&req->refcnt, 1);

	return req;
}

static void free_local_request(struct request *req)
{
	put_vnode_info(req->vinfo);
	free(req);
}

static void submit_local_request(struct request *req)
{
	sd_mutex_lock(&sys->local_req_lock);
	list_add_tail(&req->request_list, &sys->local_req_queue);
	sd_mutex_unlock(&sys->local_req_lock);

	eventfd_xwrite(sys->local_req_efd, 1);
}

/*
 * Exec the request locally and synchronously.
 *
 * This function takes advantage of gateway's retry mechanism and can be only
 * called from worker thread.
 */
worker_fn int exec_local_req(struct sd_req *rq, void *data)
{
	struct request *req;
	int ret;

	req = alloc_local_request(data, rq->data_length);
	req->rq = *rq;
	req->local_req_efd = eventfd(0, 0);
	if (req->local_req_efd < 0) {
		sd_err("eventfd failed, %m");
		/* Fake the result to ask for retry */
		req->rp.result = SD_RES_NETWORK_ERROR;
		goto out;
	}

	submit_local_request(req);
	eventfd_xread(req->local_req_efd);
out:
	/* fill rq with response header as exec_req does */
	memcpy(rq, &req->rp, sizeof(req->rp));

	close(req->local_req_efd);
	ret = req->rp.result;
	free_local_request(req);

	return ret;
}

worker_fn struct request_iocb *local_req_init(void)
{
	struct request_iocb *iocb = xzalloc(sizeof(*iocb));

	iocb->efd = eventfd(0, EFD_SEMAPHORE);
	if (iocb->efd < 0) {
		sd_err("eventfd failed, %m");
		free(iocb);
		return NULL;
	}
	iocb->result = SD_RES_SUCCESS;
	return iocb;
}

worker_fn int local_req_wait(struct request_iocb *iocb)
{
	int ret;

	for (uint32_t i = 0; i < iocb->count; i++)
		eventfd_xread(iocb->efd);

	ret = iocb->result;
	close(iocb->efd);
	free(iocb);
	return ret;
}

struct areq_work {
	struct sd_req rq;
	void *data;
	struct request_iocb *iocb;
	int result;

	struct work work;
};

static void local_req_async_work(struct work *work)
{
	struct areq_work *areq = container_of(work, struct areq_work, work);

	areq->result = exec_local_req(&areq->rq, areq->data);
}

static void local_req_async_main(struct work *work)
{
	struct areq_work *areq = container_of(work, struct areq_work, work);

	if (unlikely(areq->result != SD_RES_SUCCESS))
		areq->iocb->result = areq->result;

	eventfd_xwrite(areq->iocb->efd, 1);
	free(areq);
}

worker_fn int exec_local_req_async(struct sd_req *rq, void *data,
				   struct request_iocb *iocb)
{
	struct areq_work *areq;

	areq = xzalloc(sizeof(*areq));
	areq->rq = *rq;
	areq->data = data;
	areq->iocb = iocb;
	areq->work.fn = local_req_async_work;
	areq->work.done = local_req_async_main;

	queue_work(sys->areq_wqueue, &areq->work);

	iocb->count++;

	return SD_RES_SUCCESS;
}

static struct request *alloc_request(struct client_info *ci,
				     uint32_t data_length)
{
	struct request *req;

	req = zalloc(sizeof(struct request));
	if (!req)
		return NULL;

	if (data_length) {
		req->data_length = data_length;
		req->data = valloc(data_length);
		if (!req->data) {
			free(req);
			return NULL;
		}
	}

	req->ci = ci;
	refcount_inc(&ci->refcnt);

	refcount_set(&req->refcnt, 1);

	uatomic_inc(&sys->nr_outstanding_reqs);

	return req;
}

static void free_request(struct request *req)
{
	uatomic_dec(&sys->nr_outstanding_reqs);

	refcount_dec(&req->ci->refcnt);
	put_vnode_info(req->vinfo);
	free(req->data);
	free(req);
}

main_fn void put_request(struct request *req)
{
	struct client_info *ci = req->ci;

	if (refcount_dec(&req->refcnt) > 0)
		return;

	stat_request_end(req);

	if (req->local)
		eventfd_xwrite(req->local_req_efd, 1);
	else {
		if (ci->conn.dead) {
			/*
			 * free_request should be called prior to
			 * clear_client_info because refcnt of ci will
			 * be decreased in free_request. Otherwise, ci
			 * cannot be freed in clear_client_info.
			 */
			free_request(req);
			clear_client_info(ci);
		} else {
			list_add_tail(&req->request_list, &ci->done_reqs);

			if (ci->tx_req == NULL)
				/* There is no request being sent. */
				if (conn_tx_on(&ci->conn)) {
					sd_err("switch on sending flag failure, "
						"connection maybe closed");
					/*
					 * should not free_request(req) here
					 * because it is already in done list
					 * clear_client_info will free it
					 */
					clear_client_info(ci);
				}
		}
	}
}

main_fn void get_request(struct request *req)
{
	refcount_inc(&req->refcnt);
}

static void rx_work(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      rx_work);
	int ret;
	struct connection *conn = &ci->conn;
	struct sd_req hdr;
	struct request *req;

	ret = do_read(conn->fd, &hdr, sizeof(hdr), NULL, 0, UINT32_MAX);
	if (ret) {
		sd_debug("failed to read a header");
		conn->dead = true;
		return;
	}

	req = alloc_request(ci, hdr.data_length);
	if (!req) {
		sd_err("failed to allocate request");
		conn->dead = true;
		return;
	}
	ci->rx_req = req;

	/* use le_to_cpu */
	memcpy(&req->rq, &hdr, sizeof(req->rq));

	if (hdr.data_length && hdr.flags & SD_FLAG_CMD_WRITE) {
		ret = do_read(conn->fd, req->data, hdr.data_length, NULL, 0,
			      UINT32_MAX);
		if (ret) {
			sd_err("failed to read data");
			conn->dead = true;
		}
	}

	tracepoint(request, rx_work, conn->fd, work, req, hdr.opcode);
}

static void rx_main(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      rx_work);
	struct request *req = ci->rx_req;

	ci->rx_req = NULL;

	refcount_dec(&ci->refcnt);

	if (ci->conn.dead) {
		if (req)
			free_request(req);

		clear_client_info(ci);
		return;
	}

	if (conn_rx_on(&ci->conn))
		sd_err("switch on receiving flag failure, "
				"connection maybe closed");

	if (is_logging_op(get_sd_op(req->rq.opcode))) {
		sd_info("req=%p, fd=%d, client=%s:%d, op=%s, data=%s",
			req,
			ci->conn.fd,
			ci->conn.ipstr, ci->conn.port,
			op_name(get_sd_op(req->rq.opcode)),
			data_to_str(req->data, req->rp.data_length));
	} else {
		sd_debug("%d, %s:%d",
			 ci->conn.fd,
			 ci->conn.ipstr,
			 ci->conn.port);
	}

	tracepoint(request, rx_main, ci->conn.fd, work, req);
	queue_request(req);
}

static void tx_work(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      tx_work);
	int ret;
	struct connection *conn = &ci->conn;
	struct sd_rsp rsp;
	struct request *req = ci->tx_req;
	void *data = NULL;

	/* use cpu_to_le */
	memcpy(&rsp, &req->rp, sizeof(rsp));

	rsp.epoch = sys->cinfo.epoch;
	rsp.opcode = req->rq.opcode;
	rsp.id = req->rq.id;

	if (rsp.data_length)
		data = req->data;

	ret = send_req(conn->fd, (struct sd_req *)&rsp, data, rsp.data_length,
		       NULL, 0, UINT32_MAX);
	if (ret != 0) {
		sd_err("failed to send a request");
		conn->dead = true;
	}

	tracepoint(request, tx_work, conn->fd, work, req);
}

static void tx_main(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      tx_work);

	tracepoint(request, tx_main, ci->conn.fd, work, ci->tx_req);

	refcount_dec(&ci->refcnt);

	if (is_logging_op(ci->tx_req->op)) {
		sd_info("req=%p, fd=%d, client=%s:%d, op=%s, result=%02X",
			ci->tx_req,
			ci->conn.fd,
			ci->conn.ipstr,
			ci->conn.port,
			op_name(ci->tx_req->op),
			ci->tx_req->rp.result);
	} else {
		sd_debug("%d, %s:%d",
			 ci->conn.fd,
			 ci->conn.ipstr,
			 ci->conn.port);
	}

	free_request(ci->tx_req);
	ci->tx_req = NULL;

	if (ci->conn.dead) {
		clear_client_info(ci);
		return;
	}

	if (!list_empty(&ci->done_reqs))
		if (conn_tx_on(&ci->conn))
			sd_err("switch on sending flag failure, "
					"connection maybe closed");
}

static void destroy_client(struct client_info *ci)
{
	sd_debug("connection from: %s:%d", ci->conn.ipstr, ci->conn.port);
	close(ci->conn.fd);
	free(ci);
}

static void clear_client_info(struct client_info *ci)
{
	struct request *req;

	tracepoint(request, clear_client, ci->conn.fd);

	sd_debug("connection seems to be dead");

	list_for_each_entry(req, &ci->done_reqs, request_list) {
		list_del(&req->request_list);
		free_request(req);
	}

	unregister_event(ci->conn.fd);

	sd_debug("refcnt:%d, fd:%d, %s:%d", refcount_read(&ci->refcnt),
		 ci->conn.fd, ci->conn.ipstr, ci->conn.port);

	if (refcount_read(&ci->refcnt))
		return;

	destroy_client(ci);
}

static struct client_info *create_client(int fd)
{
	struct client_info *ci;
	struct sockaddr_storage from;
	socklen_t namesize = sizeof(from);

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

	if (getpeername(fd, (struct sockaddr *)&from, &namesize)) {
		free(ci);
		return NULL;
	}

	switch (from.ss_family) {
	case AF_INET:
		ci->conn.port = ntohs(((struct sockaddr_in *)&from)->sin_port);
		inet_ntop(AF_INET, &((struct sockaddr_in *)&from)->sin_addr,
				ci->conn.ipstr, sizeof(ci->conn.ipstr));
		break;
	case AF_INET6:
		ci->conn.port = ntohs(((struct sockaddr_in6 *)&from)->sin6_port);
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&from)->sin6_addr,
				ci->conn.ipstr, sizeof(ci->conn.ipstr));
		break;
	}

	ci->conn.fd = fd;
	ci->conn.events = EPOLLIN;
	refcount_set(&ci->refcnt, 0);

	INIT_LIST_HEAD(&ci->done_reqs);

	tracepoint(request, create_client, fd);

	return ci;
}

static void client_handler(int fd, int events, void *data)
{
	struct client_info *ci = (struct client_info *)data;

	sd_debug("%x, %d", events, ci->conn.dead);

	if (events & (EPOLLERR | EPOLLHUP))
		ci->conn.dead = true;
	/*
	 * Although dead is true, ci might not be freed immediately
	 * because of refcnt. Never mind, we will complete it later
	 * as long as dead is true.
	 */
	if (ci->conn.dead)
		return clear_client_info(ci);

	if (events & EPOLLIN) {
		if (conn_rx_off(&ci->conn) != 0) {
			sd_err("switch off receiving flag failure, "
					"connection maybe closed");
			return;
		}

		/*
		 * Increment refcnt so that the client_info isn't freed while
		 * rx_work uses it.
		 */
		refcount_inc(&ci->refcnt);
		ci->rx_work.fn = rx_work;
		ci->rx_work.done = rx_main;
		tracepoint(request, queue_request, fd, &ci->rx_work, 1);
		queue_work(sys->net_wqueue, &ci->rx_work);
	}

	if (events & EPOLLOUT) {
		if (conn_tx_off(&ci->conn) != 0) {
			sd_err("switch off sending flag failure, "
					"connection maybe closed");
			return;
		}

		sd_assert(ci->tx_req == NULL);
		ci->tx_req = list_first_entry(&ci->done_reqs, struct request,
					      request_list);
		list_del(&ci->tx_req->request_list);

		/*
		 * Increment refcnt so that the client_info isn't freed while
		 * tx_work uses it.
		 */
		refcount_inc(&ci->refcnt);
		ci->tx_work.fn = tx_work;
		ci->tx_work.done = tx_main;
		tracepoint(request, queue_request, fd, &ci->tx_work, 0);
		queue_work(sys->net_wqueue, &ci->tx_work);
	}
}

static void listen_handler(int listen_fd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	int fd, ret;
	struct client_info *ci;
	bool is_inet_socket = *(bool *)data;

	if (sys->cinfo.status == SD_STATUS_SHUTDOWN) {
		sd_debug("unregistering connection %d", listen_fd);
		unregister_event(listen_fd);
		return;
	}

	namesize = sizeof(from);
	fd = accept(listen_fd, (struct sockaddr *)&from, &namesize);
	if (fd < 0) {
		sd_err("failed to accept a new connection: %m");
		return;
	}

	if (is_inet_socket) {
		ret = set_nodelay(fd);
		if (ret) {
			close(fd);
			return;
		}
	}

	ci = create_client(fd);
	if (!ci) {
		close(fd);
		return;
	}

	ret = register_event(fd, client_handler, ci);
	if (ret) {
		destroy_client(ci);
		return;
	}

	sd_debug("accepted a new connection: %d", fd);
}

static LIST_HEAD(listening_fd_list);

struct listening_fd {
	int fd;
	struct list_node list;
};

static int create_listen_port_fn(int fd, void *data)
{
	struct listening_fd *new_fd;

	new_fd = xzalloc(sizeof(*new_fd));
	new_fd->fd = fd;
	list_add_tail(&new_fd->list, &listening_fd_list);

	return register_event(fd, listen_handler, data);
}

void unregister_listening_fds(void)
{
	struct listening_fd *fd;

	list_for_each_entry(fd, &listening_fd_list, list) {
		sd_debug("unregistering fd: %d", fd->fd);
		unregister_event(fd->fd);
	}
}

int create_listen_port(const char *bindaddr, int port)
{
	static bool is_inet_socket = true;

	return create_listen_ports(bindaddr, port, create_listen_port_fn,
				   &is_inet_socket);
}

int init_unix_domain_socket(const char *dir)
{
	static bool is_inet_socket;
	char unix_path[PATH_MAX];

	snprintf(unix_path, sizeof(unix_path), "%s/sock", dir);
	unlink(unix_path);

	return create_unix_domain_socket(unix_path, create_listen_port_fn,
					 &is_inet_socket);
}

static void local_req_handler(int listen_fd, int events, void *data)
{
	struct request *req;
	LIST_HEAD(pending_list);

	if (events & EPOLLERR)
		sd_err("request handler error");

	eventfd_xread(listen_fd);

	sd_mutex_lock(&sys->local_req_lock);
	list_splice_init(&sys->local_req_queue, &pending_list);
	sd_mutex_unlock(&sys->local_req_lock);

	list_for_each_entry(req, &pending_list, request_list) {
		list_del(&req->request_list);
		queue_request(req);
	}
}

void local_request_init(void)
{
	sd_init_mutex(&sys->local_req_lock);
	sys->local_req_efd = eventfd(0, EFD_NONBLOCK);
	if (sys->local_req_efd < 0)
		panic("failed to init local req efd");
	register_event(sys->local_req_efd, local_req_handler, NULL);
}

worker_fn int sheep_exec_req(const struct node_id *nid, struct sd_req *hdr,
			     void *buf)
{
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;
	struct sockfd *sfd;
	int ret;

	sfd = sockfd_cache_get(nid);
	if (!sfd)
		return SD_RES_NETWORK_ERROR;

	ret = exec_req(sfd->fd, hdr, buf, sheep_need_retry, hdr->epoch,
		       MAX_RETRY_COUNT);
	if (ret) {
		sd_debug("remote node might have gone away");
		sockfd_cache_del(nid, sfd);
		return SD_RES_NETWORK_ERROR;
	}
	ret = rsp->result;
	if (ret != SD_RES_SUCCESS)
		sd_warn("failed %s, remote address: %s, op name: %s",
				sd_strerror(ret),
				addr_to_str(nid->addr, nid->port),
				op_name(get_sd_op(hdr->opcode)));

	sockfd_cache_put(nid, sfd);
	return ret;
}

bool sheep_need_retry(uint32_t epoch)
{
	return sys_epoch() == epoch;
}
