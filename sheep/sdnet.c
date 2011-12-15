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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "sheep_priv.h"

void resume_pending_requests(void)
{
	struct request *next, *tmp;

	list_for_each_entry_safe(next, tmp, &sys->req_wait_for_obj_list,
				 r_wlist) {
		struct cpg_event *cevent = &next->cev;

		list_del(&next->r_wlist);
		list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);
	}

	if (!list_empty(&sys->cpg_event_siblings))
		start_cpg_event_work();
}

int is_access_local(struct sheepdog_vnode_list_entry *e, int nr_nodes,
		    uint64_t oid, int copies)
{
	int i, n;

	if (oid == 0)
		return 0;

	if (copies > nr_nodes)
		copies = nr_nodes;

	for (i = 0; i < copies; i++) {
		n = obj_to_sheep(e, nr_nodes, oid, i);

		if (is_myself(e[n].addr, e[n].port))
			return 1;
	}

	return 0;
}

static void setup_access_to_local_objects(struct request *req)
{
	struct sd_obj_req *hdr = (struct sd_obj_req *)&req->rq;
	int copies;

	if (hdr->flags & SD_FLAG_CMD_IO_LOCAL) {
		req->local_oid = hdr->oid;
		return;
	}

	copies = hdr->copies;
	if (!copies)
		copies = sys->nr_sobjs;
	if (copies > req->nr_zones)
		copies = req->nr_zones;

	if (is_access_local(req->entry, req->nr_vnodes, hdr->oid, copies))
		req->local_oid = hdr->oid;
}

static void io_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct cpg_event *cevent = &req->cev;
	int again = 0;
	int copies = sys->nr_sobjs;

	if (copies > req->nr_zones)
		copies = req->nr_zones;

	list_del(&req->r_wlist);

	sys->nr_outstanding_io--;
	/*
	 * TODO: if the request failed due to epoch unmatch,
	 * we should retry here (adds this request to the tail
	 * of sys->cpg_event_siblings.
	 */
	if (!(req->rq.flags & SD_FLAG_CMD_IO_LOCAL) &&
	    (req->rp.result == SD_RES_OLD_NODE_VER ||
	     req->rp.result == SD_RES_NEW_NODE_VER ||
	     req->rp.result == SD_RES_NETWORK_ERROR ||
	     req->rp.result == SD_RES_WAIT_FOR_JOIN ||
	     req->rp.result == SD_RES_WAIT_FOR_FORMAT)) {

		req->rq.epoch = sys->epoch;
		setup_ordered_sd_vnode_list(req);
		setup_access_to_local_objects(req);

		list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);
		again = 1;
	} else if (req->rp.result == SD_RES_SUCCESS && req->check_consistency) {
		struct sd_obj_req *obj_hdr = (struct sd_obj_req *)&req->rq;
		uint32_t vdi_id = oid_to_vid(obj_hdr->oid);
		struct data_object_bmap *bmap, *n;
		int nr_bmaps = 0;

		if (!is_data_obj(obj_hdr->oid))
			goto done;

		list_for_each_entry_safe(bmap, n, &sys->consistent_obj_list, list) {
			nr_bmaps++;
			if (bmap->vdi_id == vdi_id) {
				set_bit(data_oid_to_idx(obj_hdr->oid), bmap->dobjs);
				list_del(&bmap->list);
				list_add_tail(&bmap->list, &sys->consistent_obj_list);
				goto done;
			}
		}
		bmap = zalloc(sizeof(*bmap));
		if (bmap == NULL) {
			eprintf("failed to allocate memory\n");
			goto done;
		}
		dprintf("allocating a new object map\n");
		bmap->vdi_id = vdi_id;
		list_add_tail(&bmap->list, &sys->consistent_obj_list);
		set_bit(data_oid_to_idx(obj_hdr->oid), bmap->dobjs);
		if (nr_bmaps >= MAX_DATA_OBJECT_BMAPS) {
			/* the first entry is the least recently used one */
			bmap = list_first_entry(&sys->consistent_obj_list,
						struct data_object_bmap, list);
			list_del(&bmap->list);
			free(bmap);
		}
	} else if (is_access_local(req->entry, req->nr_vnodes,
				   ((struct sd_obj_req *)&req->rq)->oid, copies) &&
		   req->rp.result == SD_RES_EIO) {
		eprintf("leaving sheepdog cluster\n");
		leave_cluster();

		if (req->rq.flags & SD_FLAG_CMD_IO_LOCAL)
			/* hack to retry */
			req->rp.result = SD_RES_NETWORK_ERROR;
		else {
			req->rq.epoch = sys->epoch;
			setup_ordered_sd_vnode_list(req);
			setup_access_to_local_objects(req);

			list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);
			again = 1;
		}
	}
done:
	resume_pending_requests();
	resume_recovery_work();

	if (!again)
		req->done(req);
}

static void local_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);

	if (has_process_main(req->op)) {
		req->rp.result = do_process_main(req->op, &req->rq,
						 &req->rp, req->data);
	}

	req->done(req);
}

static void cluster_op_done(struct work *work)
{
	/* request is forwarded to cpg group */
}

static void do_local_request(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&req->rp;
	int ret = SD_RES_SUCCESS;

	if (has_process_work(req->op))
		ret = do_process_work(req->op, &req->rq, &req->rp, req->data);

	rsp->result = ret;
}

static void queue_request(struct request *req)
{
	struct cpg_event *cevent = &req->cev;
	struct sd_req *hdr = (struct sd_req *)&req->rq;
	struct sd_rsp *rsp = (struct sd_rsp *)&req->rp;

	req->op = get_sd_op(hdr->opcode);
	if (!req->op) {
		eprintf("invalid opcode %d\n", hdr->opcode);
		rsp->result = SD_RES_INVALID_PARMS;
		req->done(req);
		return;
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
	default:
		break;
	}

	if (is_io_op(req->op)) {
		req->work.fn = do_io_request;
		req->work.done = io_op_done;
	} else if (is_local_op(req->op)) {
		req->work.fn = do_local_request;
		req->work.done = local_op_done;
	} else if (is_cluster_op(req->op)) {
		req->work.fn = do_cluster_request;
		req->work.done = cluster_op_done;
	} else {
		eprintf("unknown operation %d\n", hdr->opcode);
		rsp->result = SD_RES_SYSTEM_ERROR;
		req->done(req);
		return;
	}

	list_del(&req->r_wlist);

	/*
	 * we set epoch for non direct requests here. Note that we
	 * can't access to sys->epoch after calling
	 * start_cpg_event_work(that is, passing requests to work
	 * threads).
	 */
	if (!(hdr->flags & SD_FLAG_CMD_IO_LOCAL))
		hdr->epoch = sys->epoch;

	setup_ordered_sd_vnode_list(req);
	if (is_io_op(req->op))
		setup_access_to_local_objects(req);

	cevent->ctype = CPG_EVENT_REQUEST;
	list_add_tail(&cevent->cpg_event_list, &sys->cpg_event_siblings);
	start_cpg_event_work();
	return;
done:
	req->done(req);
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

	list_add(&req->r_siblings, &ci->reqs);
	INIT_LIST_HEAD(&req->r_wlist);

	sys->nr_outstanding_reqs++;
	sys->outstanding_data_size += data_length;

	return req;
}

static void free_request(struct request *req)
{
	sys->nr_outstanding_reqs--;
	sys->outstanding_data_size -= req->data_length;

	list_del(&req->r_siblings);
	free_ordered_sd_vnode_list(req->entry);
	free(req->data);
	free(req);
}

static void req_done(struct request *req)
{
	int dead = 0;
	struct client_info *ci = req->ci;

	if (conn_tx_on(&ci->conn)) {
		dprintf("connection seems to be dead\n");
		dead = 1;
	} else
		list_add(&req->r_wlist, &ci->done_reqs);

	if (dead)
		free_request(req);

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

	req->done = req_done;

	queue_request(req);
}

static void init_tx_hdr(struct client_info *ci)
{
	struct sd_rsp *rsp = (struct sd_rsp *)&ci->conn.tx_hdr;
	struct request *req;

	if (ci->tx_req || list_empty(&ci->done_reqs))
		return;

	memset(rsp, 0, sizeof(*rsp));

	req = list_first_entry(&ci->done_reqs, struct request, r_wlist);
	list_del(&req->r_wlist);

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

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

	ci->conn.fd = fd;
	ci->conn.events = EPOLLIN;
	ci->refcnt = 1;

	INIT_LIST_HEAD(&ci->reqs);
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

	if (is_conn_dead(&ci->conn)) {
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

int write_object(struct sheepdog_vnode_list_entry *e,
		 int vnodes, int zones, uint32_t node_version,
		 uint64_t oid, char *data, unsigned int datalen,
		 uint64_t offset, uint16_t flags, int nr, int create)
{
	struct sd_obj_req hdr;
	int i, n, fd, ret;
	char name[128];

	if (nr > zones)
		nr = zones;

	for (i = 0; i < nr; i++) {
		unsigned rlen = 0, wlen = datalen;

		n = obj_to_sheep(e, vnodes, oid, i);

		if (is_myself(e[n].addr, e[n].port)) {
			ret = write_object_local(oid, data, datalen, offset,
						 flags, nr, node_version, create);

			if (ret != 0) {
				eprintf("fail %"PRIx64" %"PRIx32"\n", oid, ret);
				return -1;
			}

			continue;
		}

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		fd = connect_to(name, e[n].port);
		if (fd < 0) {
			eprintf("failed to connect to host %s\n", name);
			return -1;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_version;
		if (create)
			hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		else
			hdr.opcode = SD_OP_WRITE_OBJ;

		hdr.oid = oid;
		hdr.copies = nr;

		hdr.flags = flags;
		hdr.flags |= SD_FLAG_CMD_WRITE | SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = wlen;
		hdr.offset = offset;

		ret = exec_req(fd, (struct sd_req *)&hdr, data, &wlen, &rlen);
		close(fd);
		if (ret) {
			eprintf("failed to update host %s\n", name);
			return -1;
		}
	}

	return 0;
}

int read_object(struct sheepdog_vnode_list_entry *e,
		int vnodes, int zones, uint32_t node_version,
		uint64_t oid, char *data, unsigned int datalen,
		uint64_t offset, int nr)
{
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	char name[128];
	int i = 0, n, fd, ret, last_error = SD_RES_SUCCESS;

	if (nr > zones)
		nr = zones;

	/* search a local object first */
	for (i = 0; i < nr; i++) {
		n = obj_to_sheep(e, vnodes, oid, i);

		if (is_myself(e[n].addr, e[n].port)) {
			ret = read_object_local(oid, data, datalen, offset, nr,
						node_version);

			if (ret != SD_RES_SUCCESS) {
				eprintf("fail %"PRIx64" %"PRId32"\n", oid, ret);
				return ret;
			}

			return SD_RES_SUCCESS;
		}

	}

	for (i = 0; i < nr; i++) {
		unsigned wlen = 0, rlen = datalen;

		n = obj_to_sheep(e, vnodes, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		fd = connect_to(name, e[n].port);
		if (fd < 0) {
			printf("%s(%d): %s, %m\n", __func__, __LINE__,
			       name);
			return SD_RES_EIO;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_version;
		hdr.opcode = SD_OP_READ_OBJ;
		hdr.oid = oid;

		hdr.flags =  SD_FLAG_CMD_IO_LOCAL;
		hdr.data_length = rlen;
		hdr.offset = offset;

		ret = exec_req(fd, (struct sd_req *)&hdr, data, &wlen, &rlen);
		close(fd);

		if (ret) {
			last_error = SD_RES_EIO;
			continue;
		}

		if (rsp->result == SD_RES_SUCCESS)
			return SD_RES_SUCCESS;

		last_error = rsp->result;
	}

	return last_error;
}

int remove_object(struct sheepdog_vnode_list_entry *e,
		  int vnodes, int zones, uint32_t node_version,
		  uint64_t oid, int nr)
{
	char name[128];
	struct sd_obj_req hdr;
	struct sd_obj_rsp *rsp = (struct sd_obj_rsp *)&hdr;
	int i = 0, n, fd, ret;

	if (nr > zones)
		nr = zones;

	for (i = 0; i < nr; i++) {
		unsigned wlen = 0, rlen = 0;

		n = obj_to_sheep(e, vnodes, oid, i);

		addr_to_str(name, sizeof(name), e[n].addr, 0);

		fd = connect_to(name, e[n].port);
		if (fd < 0) {
			rsp->result = SD_RES_EIO;
			return -1;
		}

		memset(&hdr, 0, sizeof(hdr));
		hdr.epoch = node_version;
		hdr.opcode = SD_OP_REMOVE_OBJ;
		hdr.oid = oid;

		hdr.flags = 0;
		hdr.data_length = rlen;

		ret = exec_req(fd, (struct sd_req *)&hdr, NULL, &wlen, &rlen);
		close(fd);

		if (ret)
			return -1;
	}

	if (rsp->result != SD_RES_SUCCESS)
		return -1;

	return 0;
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
