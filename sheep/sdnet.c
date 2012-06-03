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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "sheep_priv.h"

static void requeue_request(struct request *req);

static int is_access_local(struct request *req, uint64_t oid)
{
	struct sd_vnode *obj_vnodes[SD_MAX_COPIES];
	int nr_copies;
	int i;

	nr_copies = get_nr_copies(req->vnodes);
	oid_to_vnodes(req->vnodes, oid, nr_copies, obj_vnodes);

	for (i = 0; i < nr_copies; i++) {
		if (vnode_is_local(obj_vnodes[i]))
			return 1;
	}

	return 0;
}

static int need_consistency_check(struct request *req)
{
	struct sd_req *hdr = &req->rq;

	if (hdr->opcode != SD_OP_READ_OBJ)
		/* consistency is fixed when clients read data for the
		 * first time */
		return 0;

	if (hdr->flags & SD_FLAG_CMD_WEAK_CONSISTENCY)
		return 0;

	if (is_vdi_obj(hdr->obj.oid))
		/* only check consistency for data objects */
		return 0;

	return 1;
}

static inline void set_consistency_check(struct request *req)
{
	uint32_t vdi_id = oid_to_vid(req->rq.obj.oid);
	uint32_t idx = data_oid_to_idx(req->rq.obj.oid);
	struct data_object_bmap *bmap;

	req->check_consistency = 1;
	list_for_each_entry(bmap, &sys->consistent_obj_list, list) {
		if (bmap->vdi_id == vdi_id) {
			if (test_bit(idx, bmap->dobjs))
				req->check_consistency = 0;
			break;
		}
	}
}

static void check_object_consistency(struct sd_req *hdr)
{
	uint32_t vdi_id = oid_to_vid(hdr->obj.oid);
	struct data_object_bmap *bmap, *n;
	int nr_bmaps = 0;

	list_for_each_entry_safe(bmap, n, &sys->consistent_obj_list, list) {
		nr_bmaps++;
		if (bmap->vdi_id == vdi_id) {
			set_bit(data_oid_to_idx(hdr->obj.oid), bmap->dobjs);
			list_move_tail(&bmap->list, &sys->consistent_obj_list);
			return;
		}
	}

	bmap = zalloc(sizeof(*bmap));
	if (bmap == NULL) {
		eprintf("failed to allocate memory\n");
		return;
	}

	dprintf("allocating a new object map\n");

	bmap->vdi_id = vdi_id;
	list_add_tail(&bmap->list, &sys->consistent_obj_list);
	set_bit(data_oid_to_idx(hdr->obj.oid), bmap->dobjs);
	if (nr_bmaps >= MAX_DATA_OBJECT_BMAPS) {
		/* the first entry is the least recently used one */
		bmap = list_first_entry(&sys->consistent_obj_list,
					struct data_object_bmap, list);
		list_del(&bmap->list);
		free(bmap);
	}
}

static void io_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);

	if (req->rp.result == SD_RES_EIO) {
		req->rp.result = SD_RES_NETWORK_ERROR;

		eprintf("leaving sheepdog cluster\n");
		leave_cluster();
	}

	req_done(req);
	return;
}

static void gateway_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_req *hdr = &req->rq;

	switch (req->rp.result) {
	case SD_RES_OLD_NODE_VER:
		if (req->rp.epoch > sys->epoch) {
			list_add_tail(&req->request_list,
				      &sys->wait_rw_queue);
			/*
			 * Gateway of this node is expected to process this
			 * request later when epoch is lifted.
			 */
			return;
		}
		/*FALLTHRU*/
	case SD_RES_NEW_NODE_VER:
	case SD_RES_NETWORK_ERROR:
	case SD_RES_WAIT_FOR_JOIN:
	case SD_RES_WAIT_FOR_FORMAT:
		goto retry;
	case SD_RES_EIO:
		if (is_access_local(req, hdr->obj.oid)) {
			eprintf("leaving sheepdog cluster\n");
			leave_cluster();
			goto retry;
		}
		break;
	case SD_RES_SUCCESS:
		if (req->check_consistency && is_data_obj(hdr->obj.oid))
			check_object_consistency(hdr);
		break;
	}

	req_done(req);
	return;
retry:
	requeue_request(req);
}

static void local_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);

	if (has_process_main(req->op)) {
		req->rp.result = do_process_main(req->op, &req->rq,
						 &req->rp, req->data);
	}

	req_done(req);
}

static void do_local_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;

	if (has_process_work(req->op))
		ret = do_process_work(req);

	req->rp.result = ret;
}

static int check_request_epoch(struct request *req)
{
	if (before(req->rq.epoch, sys->epoch)) {
		eprintf("old node version %u, %u, %x\n",
			sys->epoch, req->rq.epoch, req->rq.opcode);
		/* ask gateway to retry. */
		req->rp.result = SD_RES_OLD_NODE_VER;
		req->rp.epoch = sys->epoch;
		req_done(req);
		return -1;
	} else if (after(req->rq.epoch, sys->epoch)) {
		eprintf("new node version %u, %u, %x\n",
			sys->epoch, req->rq.epoch, req->rq.opcode);

		/* put on local wait queue, waiting for local epoch
		   to be lifted */
		req->rp.result = SD_RES_NEW_NODE_VER;
		list_add_tail(&req->request_list, &sys->wait_rw_queue);
		return -1;
	}

	return 0;
}

static bool request_in_recovery(struct request *req)
{
	/*
	 * Request from recovery should go down the Farm even if
	 * oid_in_recovery() returns true because we should also try snap
	 * cache of the Farm and return the error code back if not found.
	 */
	if (oid_in_recovery(req->local_oid) &&
	    !(req->rq.flags & SD_FLAG_CMD_RECOVERY)) {
		/*
		 * Put request on wait queues of local node
		 */
		if (is_recovery_init()) {
			req->rp.result = SD_RES_OBJ_RECOVERING;
			list_add_tail(&req->request_list,
				      &sys->wait_rw_queue);
		} else {
			list_add_tail(&req->request_list,
				      &sys->wait_obj_queue);
		}
		return true;
	}
	return false;
}

void resume_wait_epoch_requests(void)
{
	struct request *req, *t;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->wait_rw_queue, &pending_list);

	list_for_each_entry_safe(req, t, &pending_list, request_list) {
		switch (req->rp.result) {
		case SD_RES_OLD_NODE_VER:
			/*
			 * Gateway retries to send the request when
			 * its epoch changes.
			 */
			assert(!(req->rq.flags & SD_FLAG_CMD_IO_LOCAL));
			req->rq.epoch = sys->epoch;
			list_del(&req->request_list);
			requeue_request(req);
			break;
		case SD_RES_NEW_NODE_VER:
			/* Peer retries the request locally when its epoch changes. */
			assert(req->rq.flags & SD_FLAG_CMD_IO_LOCAL);
			list_del(&req->request_list);
			requeue_request(req);
			break;
		default:
			break;
		}
	}

	list_splice_init(&pending_list, &sys->wait_rw_queue);
}

void resume_wait_recovery_requests(void)
{
	struct request *req, *t;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->wait_rw_queue, &pending_list);

	list_for_each_entry_safe(req, t, &pending_list, request_list) {
		if (req->rp.result != SD_RES_OBJ_RECOVERING)
			continue;

		dprintf("resume wait oid %" PRIx64 "\n", req->local_oid);
		list_del(&req->request_list);
		requeue_request(req);
	}

	list_splice_init(&pending_list, &sys->wait_rw_queue);
}

void resume_wait_obj_requests(uint64_t oid)
{
	struct request *req, *t;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->wait_obj_queue, &pending_list);

	list_for_each_entry_safe(req, t, &pending_list, request_list) {
		if (req->local_oid != oid)
			continue;

		/* the object requested by a pending request has been
		 * recovered, notify the pending request. */
		dprintf("retry %" PRIx64 "\n", req->local_oid);
		list_del(&req->request_list);
		requeue_request(req);
	}
	list_splice_init(&pending_list, &sys->wait_obj_queue);
}

void flush_wait_obj_requests(void)
{
	struct request *req, *n;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->wait_obj_queue, &pending_list);

	list_for_each_entry_safe(req, n, &pending_list, request_list) {
		list_del(&req->request_list);
		requeue_request(req);
	}
}

static void queue_io_request(struct request *req)
{
	req->local_oid = req->rq.obj.oid;
	if (req->local_oid) {
		if (check_request_epoch(req) < 0)
			return;
		if (request_in_recovery(req))
			return;
	}

	req->work.fn = do_io_request;
	req->work.done = io_op_done;
	queue_work(sys->io_wqueue, &req->work);
}

static void queue_gateway_request(struct request *req)
{
	struct sd_req *hdr = &req->rq;

	if (is_access_local(req, hdr->obj.oid))
		req->local_oid = hdr->obj.oid;

	/*
	 * If we go for a cached object, we don't care if it is being recovered
	 */
	if (sys->enable_write_cache &&
	    req->rq.flags & SD_FLAG_CMD_CACHE &&
	    object_is_cached(req->rq.obj.oid))
		goto queue_work;

	if (req->local_oid)
		if (request_in_recovery(req))
			return;

	if (need_consistency_check(req))
		set_consistency_check(req);

queue_work:
	req->work.fn = do_gateway_request;
	req->work.done = gateway_op_done;
	queue_work(sys->gateway_wqueue, &req->work);
}

static void queue_local_request(struct request *req)
{
	req->work.fn = do_local_request;
	req->work.done = local_op_done;
	queue_work(sys->io_wqueue, &req->work);
}

static void queue_request(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;

	req->op = get_sd_op(hdr->opcode);
	if (!req->op) {
		eprintf("invalid opcode %d\n", hdr->opcode);
		rsp->result = SD_RES_INVALID_PARMS;
		goto done;
	}

	dprintf("%x\n", hdr->opcode);

	switch (sys->status) {
	case SD_STATUS_SHUTDOWN:
		rsp->result = SD_RES_SHUTDOWN;
		goto done;
	case SD_STATUS_WAIT_FOR_FORMAT:
		if (!is_force_op(req->op)) {
			rsp->result = SD_RES_WAIT_FOR_FORMAT;
			goto done;
		}
		break;
	case SD_STATUS_WAIT_FOR_JOIN:
		if (!is_force_op(req->op)) {
			rsp->result = SD_RES_WAIT_FOR_JOIN;
			goto done;
		}
		break;
	case SD_STATUS_HALT:
		if (!is_force_op(req->op)) {
			rsp->result = SD_RES_HALT;
			goto done;
		}
		break;
	default:
		break;
	}

	/*
	 * we set epoch for non direct requests here.  Note that we need to
	 * sample sys->epoch before passing requests to worker threads as
	 * it can change anytime we return to processing membership change
	 * events.
	 */
	if (!(hdr->flags & SD_FLAG_CMD_IO_LOCAL))
		hdr->epoch = sys->epoch;

	/*
	 * force operations shouldn't access req->vnodes in their
	 * process_work() and process_main() because they can be
	 * called before we set up current_vnode_info
	 */
	if (!is_force_op(req->op))
		req->vnodes = get_vnode_info();

	if (is_io_op(req->op)) {
		if (req->rq.flags & SD_FLAG_CMD_IO_LOCAL)
			queue_io_request(req);
		else
			queue_gateway_request(req);
	} else if (is_local_op(req->op)) {
		queue_local_request(req);
	} else if (is_cluster_op(req->op)) {
		queue_cluster_request(req);
	} else {
		eprintf("unknown operation %d\n", hdr->opcode);
		rsp->result = SD_RES_SYSTEM_ERROR;
		goto done;
	}

	return;
done:
	req_done(req);
}

static void requeue_request(struct request *req)
{
	if (req->vnodes)
		put_vnode_info(req->vnodes);
	queue_request(req);
}

static void client_incref(struct client_info *ci);
static void client_decref(struct client_info *ci);

static struct request *alloc_request(struct client_info *ci, int data_length)
{
	struct request *req;

	req = zalloc(sizeof(struct request));
	if (!req)
		return NULL;

	req->ci = ci;
	client_incref(ci);
	if (data_length) {
		req->data_length = data_length;
		req->data = valloc(data_length);
		if (!req->data) {
			free(req);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&req->request_list);

	sys->nr_outstanding_reqs++;
	sys->outstanding_data_size += data_length;

	return req;
}

static void free_request(struct request *req)
{
	sys->nr_outstanding_reqs--;
	sys->outstanding_data_size -= req->data_length;

	put_vnode_info(req->vnodes);
	free(req->data);
	free(req);
}

void req_done(struct request *req)
{
	struct client_info *ci = req->ci;

	if (conn_tx_on(&ci->conn)) {
		dprintf("connection seems to be dead\n");
		free_request(req);
	} else {
		list_add(&req->request_list, &ci->done_reqs);
	}

	client_decref(ci);
}

static void init_rx_hdr(struct client_info *ci)
{
	ci->conn.c_rx_state = C_IO_HEADER;
	ci->rx_req = NULL;
	ci->conn.rx_length = sizeof(struct sd_req);
	ci->conn.rx_buf = &ci->conn.rx_hdr;
}

static void client_rx_handler(struct client_info *ci)
{
	int ret;
	uint64_t data_len;
	struct connection *conn = &ci->conn;
	struct sd_req *hdr = &conn->rx_hdr;
	struct request *req;

	if (!ci->rx_req && sys->outstanding_data_size > MAX_OUTSTANDING_DATA_SIZE) {
		dprintf("too many requests (%p)\n", &ci->conn);
		conn_rx_off(&ci->conn);
		list_add(&ci->conn.blocking_siblings, &sys->blocking_conn_list);
		return;
	}

	switch (conn->c_rx_state) {
	case C_IO_HEADER:
		ret = rx(conn, C_IO_DATA_INIT);
		if (!ret || conn->c_rx_state != C_IO_DATA_INIT)
			break;
	case C_IO_DATA_INIT:
		data_len = hdr->data_length;

		req = alloc_request(ci, data_len);
		if (!req) {
			conn->c_rx_state = C_IO_CLOSED;
			break;
		}
		ci->rx_req = req;

		/* use le_to_cpu */
		memcpy(&req->rq, hdr, sizeof(req->rq));

		if (data_len && hdr->flags & SD_FLAG_CMD_WRITE) {
			conn->c_rx_state = C_IO_DATA;
			conn->rx_length = data_len;
			conn->rx_buf = req->data;
		} else {
			conn->c_rx_state = C_IO_END;
			break;
		}
	case C_IO_DATA:
		ret = rx(conn, C_IO_END);
		break;
	default:
		eprintf("bug: unknown state %d\n", conn->c_rx_state);
	}

	if (is_conn_dead(conn) && ci->rx_req) {
		free_request(ci->rx_req);
		return;
	}

	if (conn->c_rx_state != C_IO_END)
		return;

	/* now we have a complete command */

	req = ci->rx_req;

	init_rx_hdr(ci);

	if (hdr->flags & SD_FLAG_CMD_WRITE)
		req->rp.data_length = 0;
	else
		req->rp.data_length = hdr->data_length;

	dprintf("connection from: %s:%d\n", ci->conn.ipstr, ci->conn.port);
	queue_request(req);
}

static void init_tx_hdr(struct client_info *ci)
{
	struct sd_rsp *rsp = (struct sd_rsp *)&ci->conn.tx_hdr;
	struct request *req;

	if (ci->tx_req || list_empty(&ci->done_reqs))
		return;

	memset(rsp, 0, sizeof(*rsp));

	req = list_first_entry(&ci->done_reqs, struct request, request_list);
	list_del(&req->request_list);

	ci->tx_req = req;
	ci->conn.tx_length = sizeof(*rsp);
	ci->conn.c_tx_state = C_IO_HEADER;
	ci->conn.tx_buf = rsp;

	/* use cpu_to_le */
	memcpy(rsp, &req->rp, sizeof(*rsp));

	rsp->epoch = sys->epoch;
	rsp->opcode = req->rq.opcode;
	rsp->id = req->rq.id;
}

static void client_tx_handler(struct client_info *ci)
{
	int ret, opt;
	struct sd_rsp *rsp = (struct sd_rsp *)&ci->conn.tx_hdr;
	struct connection *conn, *n;
again:
	init_tx_hdr(ci);
	if (!ci->tx_req) {
		conn_tx_off(&ci->conn);
		if (sys->outstanding_data_size < MAX_OUTSTANDING_DATA_SIZE) {
			list_for_each_entry_safe(conn, n, &sys->blocking_conn_list,
						 blocking_siblings) {
				dprintf("rx on %p\n", conn);
				list_del(&conn->blocking_siblings);
				conn_rx_on(conn);
			}
		}
		return;
	}

	opt = 1;
	setsockopt(ci->conn.fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));

	switch (ci->conn.c_tx_state) {
	case C_IO_HEADER:
		ret = tx(&ci->conn, C_IO_DATA_INIT, 0);
		if (!ret)
			break;

		if (rsp->data_length) {
			ci->conn.tx_length = rsp->data_length;
			ci->conn.tx_buf = ci->tx_req->data;
			ci->conn.c_tx_state = C_IO_DATA;
		} else {
			ci->conn.c_tx_state = C_IO_END;
			break;
		}
	case C_IO_DATA:
		ret = tx(&ci->conn, C_IO_END, 0);
		if (!ret)
			break;
	default:
		break;
	}

	opt = 0;
	setsockopt(ci->conn.fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));

	if (is_conn_dead(&ci->conn)) {
		free_request(ci->tx_req);
		return;
	}

	if (ci->conn.c_tx_state == C_IO_END) {
		free_request(ci->tx_req);
		ci->tx_req = NULL;
		goto again;
	}
}

static void destroy_client(struct client_info *ci)
{
	dprintf("connection from: %s:%d\n", ci->conn.ipstr, ci->conn.port);
	close(ci->conn.fd);
	free(ci);
}

static void client_incref(struct client_info *ci)
{
	if (ci)
		ci->refcnt++;
}

static void client_decref(struct client_info *ci)
{
	if (ci && --ci->refcnt == 0)
		destroy_client(ci);
}

static struct client_info *create_client(int fd, struct cluster_info *cluster)
{
	struct client_info *ci;
	struct sockaddr_storage from;
	socklen_t namesize = sizeof(from);

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

	if (getpeername(fd, (struct sockaddr *)&from, &namesize))
		return NULL;

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
	ci->refcnt = 1;

	INIT_LIST_HEAD(&ci->done_reqs);

	init_rx_hdr(ci);

	return ci;
}

static void client_handler(int fd, int events, void *data)
{
	struct client_info *ci = (struct client_info *)data;

	if (events & EPOLLIN)
		client_rx_handler(ci);

	if (events & EPOLLOUT)
		client_tx_handler(ci);

	if ((events & (EPOLLERR | EPOLLHUP))
		|| is_conn_dead(&ci->conn)) {
		if (!(ci->conn.events & EPOLLIN))
			list_del(&ci->conn.blocking_siblings);

		dprintf("closed connection %d\n", fd);
		unregister_event(fd);
		client_decref(ci);
	}
}

static void listen_handler(int listen_fd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	int fd, ret;
	struct client_info *ci;

	if (sys_stat_shutdown()) {
		dprintf("unregistering connection %d\n", listen_fd);
		unregister_event(listen_fd);
		return;
	}

	namesize = sizeof(from);
	fd = accept(listen_fd, (struct sockaddr *)&from, &namesize);
	if (fd < 0) {
		eprintf("failed to accept a new connection: %m\n");
		return;
	}

	ret = set_nodelay(fd);
	if (ret) {
		close(fd);
		return;
	}

	ret = set_nonblocking(fd);
	if (ret) {
		close(fd);
		return;
	}

	ci = create_client(fd, data);
	if (!ci) {
		close(fd);
		return;
	}

	ret = register_event(fd, client_handler, ci);
	if (ret) {
		destroy_client(ci);
		return;
	}

	dprintf("accepted a new connection: %d\n", fd);
}

static int create_listen_port_fn(int fd, void *data)
{
	return register_event(fd, listen_handler, data);
}

int create_listen_port(int port, void *data)
{
	return create_listen_ports(port, create_listen_port_fn, data);
}

static __thread int cached_fds[SD_MAX_NODES];
static __thread uint32_t cached_epoch = 0;

void del_sheep_fd(int fd)
{
	int i;

	for (i = 0; i < SD_MAX_NODES; i++) {
		if (cached_fds[i] == fd) {
			if (fd >= 0)
				close(fd);

			cached_fds[i] = -1;

			return;
		}
	}
}

int get_sheep_fd(uint8_t *addr, uint16_t port, int node_idx, uint32_t epoch)
{
	int i, fd, ret;
	char name[INET6_ADDRSTRLEN];

	if (cached_epoch == 0) {
		/* initialize */
		for (i = 0; i < SD_MAX_NODES; i++)
			cached_fds[i] = -1;

		cached_epoch = epoch;
	}

	if (before(epoch, cached_epoch)) {
		eprintf("requested epoch is smaller than the previous one: %d < %d\n",
			epoch, cached_epoch);
		return -1;
	}
	if (after(epoch, cached_epoch)) {
		for (i = 0; i < SD_MAX_NODES; i++) {
			if (cached_fds[i] >= 0)
				close(cached_fds[i]);

			cached_fds[i] = -1;
		}
		cached_epoch = epoch;
	}

	fd = cached_fds[node_idx];
	dprintf("%d, %d\n", epoch, fd);

	if (cached_epoch == epoch && fd >= 0) {
		dprintf("using the cached fd %d\n", fd);
		return fd;
	}

	addr_to_str(name, sizeof(name), addr, 0);

	fd = connect_to(name, port);
	if (fd < 0)
		return -1;

	ret = set_timeout(fd);
	if (ret) {
		eprintf("%m\n");
		close(fd);
		return -1;
	}

	ret = set_nodelay(fd);
	if (ret) {
		eprintf("%m\n");
		close(fd);
		return -1;
	}

	cached_fds[node_idx] = fd;

	return fd;
}
