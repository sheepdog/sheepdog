/*
 * Copyright (C) 2015 China Mobile Inc.
 *
 * Liu Yuan <liuyuan@cmss.chinamobile.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "sheepdog.h"
#include "internal.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <pthread.h>

int sheep_submit_sdreq(struct sd_cluster *c, struct sd_req *hdr,
			      void *data, uint32_t wlen)
{
	int ret;

	sd_mutex_lock(&c->submit_mutex);
	ret = xwrite(c->sockfd, hdr, sizeof(*hdr));
	if (ret < 0)
		goto out;

	if (wlen)
		ret = xwrite(c->sockfd, data, wlen);
out:
	sd_mutex_unlock(&c->submit_mutex);
	if (unlikely(ret < 0))
		return -SD_RES_EIO;

	return ret;
}

/* Run the request synchronously */
int sd_run_sdreq(struct sd_cluster *c, struct sd_req *hdr, void *data)
{
	struct sd_request *req = alloc_request(c, data,
		hdr->data_length, SHEEP_CTL);
	int ret;

	if (!req)
		return SD_RES_SYSTEM_ERROR;

	req->hdr = hdr;
	queue_request(req);

	eventfd_xread(req->efd);
	ret = req->ret;
	free_request(req);

	return ret;
}

static void aio_end_request(struct sd_request *req, int ret)
{
	req->ret = ret;
	eventfd_xwrite(req->efd, 1);
}

static void aio_rw_done(struct sheep_aiocb *aiocb)
{
	aio_end_request(aiocb->request, aiocb->ret);
	free(aiocb);
}

static struct sheep_aiocb *sheep_aiocb_setup(struct sd_request *req)
{
	struct sheep_aiocb *aiocb = xmalloc(sizeof(*aiocb));

	aiocb->offset = req->offset;
	aiocb->length = req->length;
	aiocb->ret = 0;
	aiocb->buf_iter = 0;
	aiocb->request = req;
	aiocb->buf = req->data;
	aiocb->aio_done_func = aio_rw_done;
	uatomic_set(&aiocb->nr_requests, 0);

	return aiocb;
}

struct sheep_request *alloc_sheep_request(struct sheep_aiocb *aiocb,
						 uint64_t oid, uint64_t cow_oid,
						 int len, int offset)
{
	struct sheep_request *req = xzalloc(sizeof(*req));
	struct sd_cluster *c = aiocb->request->cluster;

	req->offset = offset;
	req->length = len;
	req->oid = oid;
	req->cow_oid = cow_oid;
	req->aiocb = aiocb;
	req->buf = aiocb->buf + aiocb->buf_iter;
	req->seq_num = uatomic_add_return(&c->seq_num, 1);
	req->opcode = aiocb->request->opcode;
	aiocb->buf_iter += len;

	INIT_LIST_NODE(&req->list);
	uatomic_inc(&aiocb->nr_requests);

	return req;
}

uint32_t sheep_inode_get_vid(struct sd_request *req, uint32_t idx)
{
	uint32_t vid;

	sd_read_lock(&req->vdi->lock);
	vid = req->vdi->inode->data_vdi_id[idx];
	sd_rw_unlock(&req->vdi->lock);

	return vid;
}

int submit_sheep_request(struct sheep_request *req)
{
	struct sd_req hdr = {};
	struct sd_cluster *c = req->aiocb->request->cluster;
	int ret = 0;

	hdr.id = req->seq_num;
	hdr.data_length = req->length;
	hdr.obj.oid = req->oid;
	hdr.obj.cow_oid = req->cow_oid;
	hdr.obj.offset = req->offset;

	sd_write_lock(&c->inflight_lock);
	list_add_tail(&req->list, &c->inflight_list);
	sd_rw_unlock(&c->inflight_lock);

	switch (req->opcode) {
	case VDI_CREATE:
	case VDI_WRITE:
		if (req->opcode == VDI_CREATE)
			hdr.opcode = SD_OP_CREATE_AND_WRITE_OBJ;
		else
			hdr.opcode = SD_OP_WRITE_OBJ;
		hdr.flags = SD_FLAG_CMD_WRITE | SD_FLAG_CMD_DIRECT;
		if (req->cow_oid)
			hdr.flags |= SD_FLAG_CMD_COW;
		ret = sheep_submit_sdreq(c, &hdr, req->buf, req->length);
		if (ret < 0)
			goto err;
		break;
	case VDI_READ:
		hdr.opcode = SD_OP_READ_OBJ;
		ret = sheep_submit_sdreq(c, &hdr, NULL, 0);
		if (ret < 0)
			goto err;
		break;
	}
err:
	eventfd_xwrite(c->reply_fd, 1);
	return ret;
}

void submit_blocking_sheep_request(struct sd_cluster *c, uint64_t oid)
{
	struct sheep_request *req;

	sd_write_lock(&c->blocking_lock);
	list_for_each_entry(req, &c->blocking_list, list) {
		if (req->oid != oid)
			continue;
		list_del(&req->list);
		submit_sheep_request(req);
	}
	sd_rw_unlock(&c->blocking_lock);
}

struct sheep_request *find_inflight_request_oid(struct sd_cluster *c,
						       uint64_t oid)
{
	struct sheep_request *req;

	sd_read_lock(&c->inflight_lock);
	list_for_each_entry(req, &c->inflight_list, list) {
		if (req->oid == oid) {
			sd_rw_unlock(&c->inflight_lock);
			return req;
		}
	}
	sd_rw_unlock(&c->inflight_lock);
	return NULL;
}

static int sheep_aiocb_submit(struct sheep_aiocb *aiocb)
{
	struct sd_request *request = aiocb->request;
	uint8_t opcode = request->opcode;
	int ret = -1;

	aiocb->op = get_sd_op(opcode);

	if (aiocb->op != NULL && aiocb->op->request_process)
		ret = aiocb->op->request_process(aiocb);

	return ret;
}

static int submit_request(struct sd_request *req)
{
	struct sheep_aiocb *aiocb = sheep_aiocb_setup(req);

	return sheep_aiocb_submit(aiocb);
}

static void *request_handler(void *data)
{
	struct sd_request *req;
	struct sd_cluster *c = data;

	while (!uatomic_is_true(&c->stop_request_handler) ||
	       !list_empty(&c->request_list)) {
		bool empty;
		uint64_t events;

		events = eventfd_xread(c->request_fd);
		sd_read_lock(&c->request_lock);
		empty = list_empty(&c->request_list);
		sd_rw_unlock(&c->request_lock);

		if (empty)
			continue;

		for (uint64_t i = 0; i < events; i++) {
			sd_write_lock(&c->request_lock);
			req = list_first_entry(&c->request_list,
				struct sd_request, list);
			list_del(&req->list);
			sd_rw_unlock(&c->request_lock);

			submit_request(req);
		}
	}
	pthread_exit(NULL);
}

static struct sheep_request *fetch_first_inflight_request(struct sd_cluster *c)
{
	struct sheep_request *req;

	sd_write_lock(&c->inflight_lock);
	if (!list_empty(&c->inflight_list)) {
		req = list_first_entry(&c->inflight_list, struct sheep_request,
				       list);
		list_del(&req->list);
	} else {
		req = NULL;
	}
	sd_rw_unlock(&c->inflight_lock);
	return req;
}

static struct sheep_request *fetch_inflight_request(struct sd_cluster *c,
						    uint32_t seq_num)
{
	struct sheep_request *req;

	sd_write_lock(&c->inflight_lock);
	list_for_each_entry(req, &c->inflight_list, list) {
		if (req->seq_num == seq_num) {
			list_del(&req->list);
			goto out;
		}
	}
	req = NULL;
out:
	sd_rw_unlock(&c->inflight_lock);
	return req;
}

int end_sheep_request(struct sheep_request *req)
{
	struct sheep_aiocb *aiocb = req->aiocb;

	if (uatomic_sub_return(&aiocb->nr_requests, 1) <= 0)
		aiocb->aio_done_func(aiocb);

	free(req);

	return 0;
}


/* FIXME: add auto-reconnect support */
static int sheep_handle_reply(struct sd_cluster *c)
{
	struct sd_rsp rsp = {};
	struct sheep_request *req;
	struct sheep_aiocb *aiocb;
	int ret;

	ret = xread(c->sockfd, (char *)&rsp, sizeof(rsp));
	if (ret < 0) {
		req = fetch_first_inflight_request(c);
		if (req != NULL) {
			req->aiocb->ret = SD_RES_EIO;
			goto end_request;
		}
		goto err;
	}

	req = fetch_inflight_request(c, rsp.id);
	if (!req)
		return 0;

	if (rsp.data_length > 0) {
		ret = xread(c->sockfd, req->buf, req->length);
		if (ret < 0) {
			req->aiocb->ret = SD_RES_EIO;
			goto end_request;
		}
	}

	aiocb = req->aiocb;
	aiocb->op = get_sd_op(req->opcode);
	if (aiocb->op != NULL && !!aiocb->op->response_process)
		ret = aiocb->op->response_process(req, &rsp);

end_request:
	end_sheep_request(req);
err:
	return ret;
}

static void *reply_handler(void *data)
{
	struct sd_cluster *c = data;

	while (!uatomic_is_true(&c->stop_request_handler) ||
	       !list_empty(&c->inflight_list)) {
		bool empty;

		uint64_t events;
		events = eventfd_xread(c->reply_fd);

		sd_read_lock(&c->inflight_lock);
		empty = list_empty(&c->inflight_list);
		sd_rw_unlock(&c->inflight_lock);

		if (empty)
			continue;

		for (uint64_t i = 0; i < events; i++)
			sheep_handle_reply(c);

	}
	pthread_exit(NULL);
}

static int init_cluster_handlers(struct sd_cluster *c)
{
	pthread_t thread;
	int ret;

	c->request_fd = eventfd(0, 0);
	if (c->request_fd < 0)
		return -SD_RES_SYSTEM_ERROR;

	c->reply_fd = eventfd(0, 0);
	if (c->reply_fd < 0) {
		close(c->request_fd);
		return -SD_RES_SYSTEM_ERROR;
	}

	ret = pthread_create(&thread, NULL, request_handler, c);
	if (ret < 0) {
		close(c->request_fd);
		close(c->reply_fd);
		return ret;
	}
	c->request_thread = thread;
	ret = pthread_create(&thread, NULL, reply_handler, c);
	if (ret < 0) {
		close(c->reply_fd);
		uatomic_set_true(&c->stop_request_handler);
		eventfd_xwrite(c->request_fd, 1);
		pthread_join(c->request_thread, NULL);
		return ret;
	}
	c->reply_thread = thread;

	return SD_RES_SUCCESS;
}

struct sd_cluster *sd_connect(char *host)
{
	char *ip, *pt, *h = xstrdup(host);
	unsigned port;
	struct sockaddr_in addr;
	struct linger linger_opt = {1, 0};
	int fd, ret, value = 1;
	struct sd_cluster *c;

	ip = strtok(h, ":");
	if (!ip) {
		errno = SD_RES_INVALID_PARMS;
		goto err;
	}

	pt = strtok(NULL, ":");
	if (!pt) {
		errno = SD_RES_INVALID_PARMS;
		goto err;
	}

	if (sscanf(pt, "%u", &port) != 1) {
		errno = SD_RES_INVALID_PARMS;
		goto err;
	}

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		errno = SD_RES_SYSTEM_ERROR;
		goto err;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger_opt,
			 sizeof(linger_opt));
	if (ret < 0) {
		errno = SD_RES_SYSTEM_ERROR;
		goto err_close;
	}

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
	if (ret < 0) {
		errno = SD_RES_SYSTEM_ERROR;
		goto err_close;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	ret = inet_pton(AF_INET, ip, &addr.sin_addr);
	switch (ret) {
	case 1:
		break;
	default:
		errno = SD_RES_INVALID_PARMS;
		goto err_close;
	}

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		errno = SD_RES_SYSTEM_ERROR;
		goto err_close;
	}

	c = xzalloc(sizeof(*c));
	c->sockfd = fd;
	c->port = port;
	memcpy(c->addr, &addr.sin_addr, INET_ADDRSTRLEN);
	ret = init_cluster_handlers(c);
	if (ret < 0) {
		free(c);
		errno = -ret;
		goto err_close;
	};
	INIT_LIST_HEAD(&c->request_list);
	INIT_LIST_HEAD(&c->inflight_list);
	INIT_LIST_HEAD(&c->blocking_list);
	sd_init_rw_lock(&c->request_lock);
	sd_init_rw_lock(&c->inflight_lock);
	sd_init_rw_lock(&c->blocking_lock);
	sd_init_mutex(&c->submit_mutex);

	free(h);
	return c;
err_close:
	close(fd);
err:
	free(h);
	return NULL;
}

int sd_disconnect(struct sd_cluster *c)
{
	uatomic_set_true(&c->stop_request_handler);
	uatomic_set_true(&c->stop_reply_handler);
	eventfd_xwrite(c->request_fd, 1);
	eventfd_xwrite(c->reply_fd, 1);
	pthread_join(c->request_thread, NULL);
	pthread_join(c->reply_thread, NULL);
	sd_destroy_rw_lock(&c->request_lock);
	sd_destroy_rw_lock(&c->inflight_lock);
	sd_destroy_rw_lock(&c->blocking_lock);
	sd_destroy_mutex(&c->submit_mutex);
	close(c->request_fd);
	close(c->reply_fd);
	close(c->sockfd);
	free(c);

	return SD_RES_SUCCESS;
}
