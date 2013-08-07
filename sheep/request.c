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

static void requeue_request(struct request *req);

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
	oid_to_vnodes(req->vinfo->vnodes, req->vinfo->nr_vnodes, oid,
		      nr_copies, obj_vnodes);

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

		sd_eprintf("leaving sheepdog cluster");
		leave_cluster();
		break;
	case SD_RES_SUCCESS:
	case SD_RES_NETWORK_ERROR:
		break;
	default:
		sd_dprintf("unhandled error %s", sd_strerror(req->rp.result));
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
 *      4. Object requested doesn't exist and is being recoverred
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
		/*FALLTHRU*/
	case SD_RES_NEW_NODE_VER:
	case SD_RES_NETWORK_ERROR:
	case SD_RES_WAIT_FOR_JOIN:
	case SD_RES_WAIT_FOR_FORMAT:
	case SD_RES_KILLED:
		sd_dprintf("retrying failed I/O request op %s result %x epoch %"
			   PRIu32", sys epoch %"PRIu32, op_name(req->op),
			   req->rp.result, req->rq.epoch, sys->cinfo.epoch);
		goto retry;
	case SD_RES_EIO:
		if (is_access_local(req, hdr->obj.oid)) {
			sd_eprintf("leaving sheepdog cluster");
			leave_cluster();
			goto retry;
		}
		break;
	case SD_RES_SUCCESS:
		break;
	default:
		sd_dprintf("unhandled error %s", sd_strerror(req->rp.result));
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
	if (before(req->rq.epoch, sys->cinfo.epoch)) {
		sd_eprintf("old node version %u, %u (%s)",
			   sys->cinfo.epoch, req->rq.epoch, op_name(req->op));
		/* Ask for sleeping req on requester's wait queue */
		req->rp.result = SD_RES_OLD_NODE_VER;
		req->rp.epoch = sys->cinfo.epoch;
		put_request(req);
		return -1;
	} else if (after(req->rq.epoch, sys->cinfo.epoch)) {
		sd_eprintf("new node version %u, %u (%s)",
			   sys->cinfo.epoch, req->rq.epoch, op_name(req->op));
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

	/*
	 * Request from recovery should go down the Farm even if
	 * oid_in_recovery() returns true because we should also try snap
	 * cache of the Farm and return the error code back if not found.
	 */
	if (oid_in_recovery(req->local_oid) &&
	    !(req->rq.flags & SD_FLAG_CMD_RECOVERY)) {
		sd_dprintf("%"PRIx64" wait on oid", req->local_oid);
		sleep_on_wait_queue(req);
		return true;
	}
	return false;
}

/* Wakeup requests because of epoch mismatch */
void wakeup_requests_on_epoch(void)
{
	struct request *req, *t;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->req_wait_queue, &pending_list);

	list_for_each_entry_safe(req, t, &pending_list, request_list) {
		switch (req->rp.result) {
		case SD_RES_OLD_NODE_VER:
			/*
			 * Gateway retries to send the request when
			 * its epoch changes.
			 */
			assert(is_gateway_op(req->op));
			sd_dprintf("gateway %"PRIx64, req->rq.obj.oid);
			req->rq.epoch = sys->cinfo.epoch;
			del_requeue_request(req);
			break;
		case SD_RES_NEW_NODE_VER:
			/*
			 * Peer retries the request locally when its epoch
			 * changes.
			 */
			assert(!is_gateway_op(req->op));
			sd_dprintf("peer %"PRIx64, req->rq.obj.oid);
			del_requeue_request(req);
			break;
		default:
			break;
		}
	}

	list_splice_init(&pending_list, &sys->req_wait_queue);
}

/* Wakeup the requests on the oid that was previously being recoverred */
void wakeup_requests_on_oid(uint64_t oid)
{
	struct request *req, *t;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->req_wait_queue, &pending_list);

	list_for_each_entry_safe(req, t, &pending_list, request_list) {
		if (req->local_oid != oid)
			continue;
		sd_dprintf("retry %" PRIx64, req->local_oid);
		del_requeue_request(req);
	}
	list_splice_init(&pending_list, &sys->req_wait_queue);
}

void wakeup_all_requests(void)
{
	struct request *req, *n;
	LIST_HEAD(pending_list);

	list_splice_init(&sys->req_wait_queue, &pending_list);

	list_for_each_entry_safe(req, n, &pending_list, request_list) {
		sd_dprintf("%"PRIx64, req->rq.obj.oid);
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
	 * Not ture for local request because it might go for backend store
	 * such as pushing cache object, in this case we should check if request
	 * is in recovery.
	 */
	if (sys->enable_object_cache && !req->local)
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
		if (hdr->proto_ver > SD_PROTO_VER) {
			rsp->result = SD_RES_VER_MISMATCH;
			goto done;
		}
	}

	req->op = get_sd_op(hdr->opcode);
	if (!req->op) {
		sd_eprintf("invalid opcode %d", hdr->opcode);
		rsp->result = SD_RES_INVALID_PARMS;
		goto done;
	}

	sd_dprintf("%s, %d", op_name(req->op), sys->cinfo.status);

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
		sd_eprintf("unknown operation %d", hdr->opcode);
		rsp->result = SD_RES_SYSTEM_ERROR;
		goto done;
	}

	return;
done:
	put_request(req);
}

static void requeue_request(struct request *req)
{
	if (req->vinfo) {
		put_vnode_info(req->vinfo);
		req->vinfo = NULL;
	}
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

	INIT_LIST_HEAD(&req->request_list);

	refcount_set(&req->refcnt, 1);

	return req;
}

static void free_local_request(struct request *req)
{
	put_vnode_info(req->vinfo);
	free(req);
}

/*
 * Exec the request locally and synchronously.
 *
 * This function takes advantage of gateway's retry mechanism and can be only
 * called from worker thread.
 */
int exec_local_req(struct sd_req *rq, void *data)
{
	struct request *req;
	int ret;

	assert(is_worker_thread());

	req = alloc_local_request(data, rq->data_length);
	req->rq = *rq;
	req->local_req_efd = eventfd(0, 0);
	if (req->local_req_efd < 0) {
		/* Fake the result to ask for retry */
		req->rp.result = SD_RES_NETWORK_ERROR;
		goto out;
	}

	pthread_mutex_lock(&sys->local_req_lock);
	list_add_tail(&req->request_list, &sys->local_req_queue);
	pthread_mutex_unlock(&sys->local_req_lock);

	eventfd_xwrite(sys->local_req_efd, 1);
	eventfd_xread(req->local_req_efd);
out:
	/* fill rq with response header as exec_req does */
	memcpy(rq, &req->rp, sizeof(req->rp));

	close(req->local_req_efd);
	ret = req->rp.result;
	free_local_request(req);

	return ret;
}

static struct request *alloc_request(struct client_info *ci, int data_length)
{
	struct request *req;

	req = zalloc(sizeof(struct request));
	if (!req)
		return NULL;

	req->ci = ci;
	refcount_inc(&ci->refcnt);
	if (data_length) {
		req->data_length = data_length;
		req->data = valloc(data_length);
		if (!req->data) {
			free(req);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&req->request_list);
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

void put_request(struct request *req)
{
	struct client_info *ci = req->ci;

	if (refcount_dec(&req->refcnt) > 0)
		return;

	if (req->local)
		eventfd_xwrite(req->local_req_efd, 1);
	else {
		if (conn_tx_on(&ci->conn)) {
			clear_client_info(ci);
			free_request(req);
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

static inline int begin_rx(struct client_info *ci)
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
		sd_eprintf("bug: unknown state %d", conn->c_rx_state);
	}

	if (is_conn_dead(conn)) {
		clear_client_info(ci);
		return -1;
	}

	/* Short read happens */
	if (conn->c_rx_state != C_IO_END)
		return -1;

	return 0;
}

static inline void finish_rx(struct client_info *ci)
{
	struct request *req;

	req = ci->rx_req;
	init_rx_hdr(ci);

	sd_dprintf("%d, %s:%d", ci->conn.fd, ci->conn.ipstr, ci->conn.port);
	queue_request(req);
}

static void do_client_rx(struct client_info *ci)
{
	if (begin_rx(ci) < 0)
		return;

	finish_rx(ci);
}

static void init_tx_hdr(struct client_info *ci)
{
	struct sd_rsp *rsp = (struct sd_rsp *)&ci->conn.tx_hdr;
	struct request *req;

	assert(!list_empty(&ci->done_reqs));

	memset(rsp, 0, sizeof(*rsp));

	req = list_first_entry(&ci->done_reqs, struct request, request_list);
	list_del(&req->request_list);

	ci->tx_req = req;
	ci->conn.tx_length = sizeof(*rsp);
	ci->conn.c_tx_state = C_IO_HEADER;
	ci->conn.tx_buf = rsp;

	/* use cpu_to_le */
	memcpy(rsp, &req->rp, sizeof(*rsp));

	rsp->epoch = sys->cinfo.epoch;
	rsp->opcode = req->rq.opcode;
	rsp->id = req->rq.id;
}

static inline int begin_tx(struct client_info *ci)
{
	int ret, opt;
	struct sd_rsp *rsp = (struct sd_rsp *)&ci->conn.tx_hdr;

	/* If short send happens, we don't need init hdr */
	if (!ci->tx_req)
		init_tx_hdr(ci);

	opt = 1;
	setsockopt(ci->conn.fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));

	switch (ci->conn.c_tx_state) {
	case C_IO_HEADER:
		ret = tx(&ci->conn, C_IO_DATA_INIT);
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
		ret = tx(&ci->conn, C_IO_END);
		if (!ret)
			break;
	default:
		break;
	}

	opt = 0;
	setsockopt(ci->conn.fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));

	if (is_conn_dead(&ci->conn)) {
		clear_client_info(ci);
		return -1;
	}
	return 0;
}

/* Return 1 if short send happens or we have more data to send */
static inline int finish_tx(struct client_info *ci)
{
	/* Finish sending one response */
	if (ci->conn.c_tx_state == C_IO_END) {
		sd_dprintf("connection from: %d, %s:%d", ci->conn.fd,
			   ci->conn.ipstr, ci->conn.port);
		free_request(ci->tx_req);
		ci->tx_req = NULL;
	}
	if (ci->tx_req || !list_empty(&ci->done_reqs))
		return 1;
	return 0;
}

static void do_client_tx(struct client_info *ci)
{
	if (!ci->tx_req && list_empty(&ci->done_reqs)) {
		if (conn_tx_off(&ci->conn))
			clear_client_info(ci);
		return;
	}

	if (begin_tx(ci) < 0)
		return;

	if (finish_tx(ci))
		return;

	/* Let's go sleep, and put_request() will wake me up */
	if (conn_tx_off(&ci->conn))
		clear_client_info(ci);
}

static void destroy_client(struct client_info *ci)
{
	sd_dprintf("connection from: %s:%d", ci->conn.ipstr, ci->conn.port);
	close(ci->conn.fd);
	free(ci);
}

static void clear_client_info(struct client_info *ci)
{
	struct request *req, *t;

	sd_dprintf("connection seems to be dead");

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

	sd_dprintf("refcnt:%d, fd:%d, %s:%d", refcount_read(&ci->refcnt),
		ci->conn.fd, ci->conn.ipstr, ci->conn.port);

	if (refcount_read(&ci->refcnt))
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
	refcount_set(&ci->refcnt, 0);

	INIT_LIST_HEAD(&ci->done_reqs);

	init_rx_hdr(ci);

	return ci;
}

static void client_handler(int fd, int events, void *data)
{
	struct client_info *ci = (struct client_info *)data;

	sd_dprintf("%x, rx %d, tx %d", events, ci->conn.c_rx_state,
		   ci->conn.c_tx_state);

	if (events & (EPOLLERR | EPOLLHUP) || is_conn_dead(&ci->conn))
		return clear_client_info(ci);

	if (events & EPOLLIN)
		do_client_rx(ci);

	if (events & EPOLLOUT)
		do_client_tx(ci);
}

static void listen_handler(int listen_fd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	int fd, ret;
	struct client_info *ci;
	bool is_inet_socket = *(bool *)data;

	if (sys->cinfo.status == SD_STATUS_SHUTDOWN) {
		sd_dprintf("unregistering connection %d", listen_fd);
		unregister_event(listen_fd);
		return;
	}

	namesize = sizeof(from);
	fd = accept(listen_fd, (struct sockaddr *)&from, &namesize);
	if (fd < 0) {
		sd_eprintf("failed to accept a new connection: %m");
		return;
	}

	if (is_inet_socket) {
		ret = set_nodelay(fd);
		if (ret) {
			close(fd);
			return;
		}
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

	sd_dprintf("accepted a new connection: %d", fd);
}

static int create_listen_port_fn(int fd, void *data)
{
	return register_event(fd, listen_handler, data);
}

int create_listen_port(char *bindaddr, int port)
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
	struct request *req, *t;
	LIST_HEAD(pending_list);

	if (events & EPOLLERR)
		sd_eprintf("request handler error");

	eventfd_xread(listen_fd);

	pthread_mutex_lock(&sys->local_req_lock);
	list_splice_init(&sys->local_req_queue, &pending_list);
	pthread_mutex_unlock(&sys->local_req_lock);

	list_for_each_entry_safe(req, t, &pending_list, request_list) {
		list_del(&req->request_list);
		queue_request(req);
	}
}

void local_req_init(void)
{
	pthread_mutex_init(&sys->local_req_lock, NULL);
	sys->local_req_efd = eventfd(0, EFD_NONBLOCK);
	if (sys->local_req_efd < 0)
		panic("failed to init local req efd");
	register_event(sys->local_req_efd, local_req_handler, NULL);
}

int sheep_exec_req(const struct node_id *nid, struct sd_req *hdr, void *buf)
{
	struct sd_rsp *rsp = (struct sd_rsp *)hdr;
	struct sockfd *sfd;
	int ret;

	assert(is_worker_thread());

	sfd = sockfd_cache_get(nid);
	if (!sfd)
		return SD_RES_NETWORK_ERROR;

	ret = exec_req(sfd->fd, hdr, buf, sheep_need_retry, hdr->epoch,
		       MAX_RETRY_COUNT);
	if (ret) {
		sd_dprintf("remote node might have gone away");
		sockfd_cache_del(nid, sfd);
		return SD_RES_NETWORK_ERROR;
	}
	ret = rsp->result;
	if (ret != SD_RES_SUCCESS)
		sd_eprintf("failed %s", sd_strerror(ret));

	sockfd_cache_put(nid, sfd);
	return ret;
}

bool sheep_need_retry(uint32_t epoch)
{
	return sys_epoch() == epoch;
}
