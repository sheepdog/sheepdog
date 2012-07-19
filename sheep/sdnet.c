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
#include <pthread.h>
#include <sys/eventfd.h>
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

static void io_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);

	if (req->rp.result == SD_RES_EIO) {
		req->rp.result = SD_RES_NETWORK_ERROR;

		eprintf("leaving sheepdog cluster\n");
		leave_cluster();
	}

	put_request(req);
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
		dprintf("retrying failed I/O request "
			"op %s result %d epoch %d, sys epoch %d\n",
			op_name(req->op),
			req->rp.result,
			req->rq.epoch,
			sys->epoch);
		goto retry;
	case SD_RES_EIO:
		if (is_access_local(req, hdr->obj.oid)) {
			eprintf("leaving sheepdog cluster\n");
			leave_cluster();
			goto retry;
		}
		break;
	case SD_RES_SUCCESS:
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
						 &req->rp, req->data);
	}

	put_request(req);
}

static int check_request_epoch(struct request *req)
{
	if (before(req->rq.epoch, sys->epoch)) {
		eprintf("old node version %u, %u (%s)\n",
			sys->epoch, req->rq.epoch, op_name(req->op));
		/* ask gateway to retry. */
		req->rp.result = SD_RES_OLD_NODE_VER;
		req->rp.epoch = sys->epoch;
		put_request(req);
		return -1;
	} else if (after(req->rq.epoch, sys->epoch)) {
		eprintf("new node version %u, %u (%s)\n",
			sys->epoch, req->rq.epoch, op_name(req->op));

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
			assert(is_gateway_op(req->op));
			req->rq.epoch = sys->epoch;
			list_del(&req->request_list);
			requeue_request(req);
			break;
		case SD_RES_NEW_NODE_VER:
			/* Peer retries the request locally when its epoch changes. */
			assert(!is_gateway_op(req->op));
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

queue_work:
	req->work.fn = do_process_work;
	req->work.done = gateway_op_done;
	queue_work(sys->gateway_wqueue, &req->work);
}

static void queue_local_request(struct request *req)
{
	req->work.fn = do_process_work;
	req->work.done = local_op_done;
	queue_work(sys->io_wqueue, &req->work);
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
		if (hdr->proto_ver != SD_PROTO_VER) {
			rsp->result = SD_RES_VER_MISMATCH;
			goto done;
		}
	}

	req->op = get_sd_op(hdr->opcode);
	if (!req->op) {
		eprintf("invalid opcode %d\n", hdr->opcode);
		rsp->result = SD_RES_INVALID_PARMS;
		goto done;
	}

	dprintf("%s\n", op_name(req->op));

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
	 * force operations shouldn't access req->vnodes in their
	 * process_work() and process_main() because they can be
	 * called before we set up current_vnode_info
	 */
	if (!is_force_op(req->op))
		req->vnodes = get_vnode_info();

	if (is_peer_op(req->op)) {
		queue_peer_request(req);
	} else if (is_gateway_op(req->op)) {
		hdr->epoch = sys->epoch;
		queue_gateway_request(req);
	} else if (is_local_op(req->op)) {
		hdr->epoch = sys->epoch;
		queue_local_request(req);
	} else if (is_cluster_op(req->op)) {
		hdr->epoch = sys->epoch;
		queue_cluster_request(req);
	} else {
		eprintf("unknown operation %d\n", hdr->opcode);
		rsp->result = SD_RES_SYSTEM_ERROR;
		goto done;
	}

	return;
done:
	put_request(req);
}

static void requeue_request(struct request *req)
{
	if (req->vnodes)
		put_vnode_info(req->vnodes);
	queue_request(req);
}

static void clear_client(struct client_info *ci);

static struct request *alloc_local_request(void *data, int data_length)
{
	struct request *req;

	req = xzalloc(sizeof(struct request));
	if (data_length) {
		req->data_length = data_length;
		req->data = data;
	}

	req->local = 1;

	INIT_LIST_HEAD(&req->request_list);

	return req;
}

/*
 * Exec the request locally and synchronously.
 *
 * This function takes advantage of gateway's retry mechanism.
 */
int exec_local_req(struct sd_req *rq, void *data)
{
	struct request *req;
	eventfd_t value = 1;
	int ret;

	req = alloc_local_request(data, rq->data_length);
	req->rq = *rq;
	req->wait_efd = eventfd(0, 0);

	pthread_mutex_lock(&sys->wait_req_lock);
	list_add_tail(&req->request_list, &sys->wait_req_queue);
	pthread_mutex_unlock(&sys->wait_req_lock);

	eventfd_write(sys->req_efd, value);

	ret = eventfd_read(req->wait_efd, &value);
	if (ret < 0)
		eprintf("event fd read error %m");

	close(req->wait_efd);
	ret = req->rp.result;
	free(req);

	return ret;
}

static struct request *alloc_request(struct client_info *ci, int data_length)
{
	struct request *req;

	req = zalloc(sizeof(struct request));
	if (!req)
		return NULL;

	req->ci = ci;
	ci->refcnt++;
	if (data_length) {
		req->data_length = data_length;
		req->data = valloc(data_length);
		if (!req->data) {
			free(req);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&req->request_list);
	uatomic_set(&req->refcnt, 1);

	uatomic_inc(&sys->nr_outstanding_reqs);

	return req;
}

static void free_request(struct request *req)
{
	uatomic_dec(&sys->nr_outstanding_reqs);

	req->ci->refcnt--;
	put_vnode_info(req->vnodes);
	free(req->data);
	free(req);
}

void put_request(struct request *req)
{
	struct client_info *ci = req->ci;
	eventfd_t value = 1;

	if (uatomic_sub_return(&req->refcnt, 1) > 0)
		return;

	if (req->local) {
		req->done = 1;
		eventfd_write(req->wait_efd, value);
	} else {
		if (conn_tx_on(&ci->conn)) {
			dprintf("connection seems to be dead\n");
			free_request(req);
			clear_client(ci);
		} else {
			list_add(&req->request_list, &ci->done_reqs);
		}
	}
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
		ci->rx_req = NULL;
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

	dprintf("connection from: %d, %s:%d\n", ci->conn.fd,
		ci->conn.ipstr, ci->conn.port);
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
again:
	init_tx_hdr(ci);
	if (!ci->tx_req) {
		conn_tx_off(&ci->conn);
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
		ci->tx_req = NULL;
		return;
	}

	if (ci->conn.c_tx_state == C_IO_END) {
		dprintf("connection from: %d, %s:%d\n", ci->conn.fd,
			ci->conn.ipstr, ci->conn.port);
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

static void clear_client(struct client_info *ci)
{
	struct request *req, *t;

	if (ci->rx_req) {
		free_request(ci->rx_req);
		ci->rx_req = NULL;
	}

	if (ci->tx_req) {
		free_request(ci->tx_req);
		ci->tx_req = NULL;
	}

	list_for_each_entry_safe(req, t, &ci->done_reqs, request_list) {
		list_del(&req->request_list);
		free_request(req);
	}

	unregister_event(ci->conn.fd);

	dprintf("refcnt:%d, fd:%d, %s:%d\n",
		ci->refcnt, ci->conn.fd,
		ci->conn.ipstr, ci->conn.port);

	if (ci->refcnt)
		return;

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
	ci->refcnt = 0;

	INIT_LIST_HEAD(&ci->done_reqs);

	init_rx_hdr(ci);

	return ci;
}

static void client_handler(int fd, int events, void *data)
{
	struct client_info *ci = (struct client_info *)data;

	if (events & (EPOLLERR | EPOLLHUP))
		goto err;

	if (events & EPOLLIN)
		client_rx_handler(ci);

	if (events & EPOLLOUT)
		client_tx_handler(ci);

	if (is_conn_dead(&ci->conn)) {
err:
		dprintf("connection seems to be dead\n");
		clear_client(ci);
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

	ret = set_keepalive(fd);
	if (ret) {
		close(fd);
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


static void req_handler(int listen_fd, int events, void *data)
{
	eventfd_t value;
	struct request *req, *t;
	LIST_HEAD(pending_list);
	int ret;

	if (events & EPOLLERR)
		eprintf("request handler error\n");

	ret = eventfd_read(listen_fd, &value);
	if (ret < 0)
		return;

	pthread_mutex_lock(&sys->wait_req_lock);
	list_splice_init(&sys->wait_req_queue, &pending_list);
	pthread_mutex_unlock(&sys->wait_req_lock);

	list_for_each_entry_safe(req, t, &pending_list, request_list) {
		list_del(&req->request_list);
		queue_request(req);
	}
}

void local_req_init(void)
{
	pthread_mutex_init(&sys->wait_req_lock, NULL);
	sys->req_efd = eventfd(0, EFD_NONBLOCK);
	register_event(sys->req_efd, req_handler, NULL);
}
